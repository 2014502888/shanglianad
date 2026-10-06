#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>

// ===== ShanLianAD v3.3: 真实 API 域名（抓包确认 api.aslafvbn.shop） =====
// v3.3 变更：用户 ProxyPin 抓到 App 真实请求域名 = api.aslafvbn.shop
// （之前 6 个域名全错/失效）。替换为主域名 + 保留旧 slapower 备选。

static NSArray *slHosts(void) {
    return @[@"https://api.aslafvbn.shop",
             @"https://api.slapower.com"];
}

static void slLog(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/sl_debug.txt"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [line writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } else {
        [fh seekToEndOfFile];
        [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    }
}

static void slShowAlert(NSString *title, NSString *msg) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIApplication *app = [UIApplication sharedApplication];
        UIWindow *win = nil;
        for (UIWindow *w in app.windows) {
            if (w.isKeyWindow) { win = w; break; }
        }
        if (!win) win = app.windows.firstObject;
        UIViewController *root = win.rootViewController;
        if (!root) return;
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
        [root presentViewController:ac animated:YES completion:nil];
    });
}

#pragma mark - 从 App 存储读取现有 token

static NSDictionary *slScanUserDefaults(void) {
    // 枚举 NSUserDefaults 全部 key，找含 token/auth 的
    NSMutableDictionary *found = [NSMutableDictionary dictionary];
    NSDictionary *rep = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
    for (NSString *k in rep) {
        NSString *low = [k lowercaseString];
        if ([low containsString:@"token"] || [low containsString:@"auth"] ||
            [low containsString:@"session"] || [low containsString:@"login"] ||
            [low containsString:@"user"]) {
            id v = rep[k];
            if ([v isKindOfClass:[NSString class]] && [(NSString *)v length] > 8) {
                found[k] = v;
            } else if ([v isKindOfClass:[NSData class]] && [(NSData *)v length] > 8) {
                found[k] = [[NSString alloc] initWithData:(NSData *)v encoding:NSUTF8StringEncoding] ?: @"";
            }
        }
    }
    return found;
}

static NSString *slScanKeychain(void) {
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    query[(__bridge id)kSecReturnAttributes] = @YES;
    query[(__bridge id)kSecReturnData] = @YES;
    CFArrayRef results = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&results);
    if (st != errSecSuccess || !results) return nil;
    NSArray *items = (__bridge_transfer NSArray *)results;
    NSString *best = nil;
    for (NSDictionary *item in items) {
        NSData *data = item[(__bridge id)kSecValueData];
        NSString *str = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
        NSDictionary *attrs = item[(__bridge id)kSecAttrGeneric] ? @{} : item;
        NSString *svc = attrs[(__bridge id)kSecAttrService] ?: @"";
        NSString *acct = attrs[(__bridge id)kSecAttrAccount] ?: @"";
        slLog(@"keychain item: svc=%@ acct=%@ len=%lu", svc, acct, (unsigned long)str.length);
        if (str.length > 20 && ([str rangeOfString:@"Bearer"].location != NSNotFound ||
                                [str rangeOfString:@"token"].location != NSNotFound ||
                                [str rangeOfString:@"access"].location != NSNotFound)) {
            if (!best || str.length > best.length) best = str;
        }
    }
    return best;
}

// 从所有候选中挑最像 token 的：优先解析 JSON 里的 token 字段
static NSString *slPickToken(NSDictionary *found, NSString *keychainStr) {
    if (keychainStr.length > 20) return keychainStr;
    NSString *best = nil;
    for (NSString *k in found) {
        NSString *v = found[k];
        NSString *low = [k lowercaseString];
        // 若值是 JSON，尝试取 token / accessToken / userToken 字段
        if ([v hasPrefix:@"{"]) {
            NSData *d = [v dataUsingEncoding:NSUTF8StringEncoding];
            NSError *err = nil;
            id obj = [NSJSONSerialization JSONObjectWithData:d options:0 error:&err];
            if (!err && [obj isKindOfClass:[NSDictionary class]]) {
                NSDictionary *dict = (NSDictionary *)obj;
                for (NSString *tk in @[@"token", @"accessToken", @"access_token", @"userToken", @"authToken", @"sessionToken", @"tokenValue"]) {
                    id tv = dict[tk];
                    if ([tv isKindOfClass:[NSString class]] && [(NSString *)tv length] > 10) {
                        if (!best || [(NSString *)tv length] > best.length) best = tv;
                    }
                }
            }
        }
        if ([low containsString:@"token"] || [low containsString:@"auth"] || [low containsString:@"session"]) {
            if (!best || v.length > best.length) {
                // 仅当该值本身像 token（无大段 JSON 外壳）时兜底
                if (![v hasPrefix:@"{"]) best = v;
            }
        }
    }
    return best;
}

#pragma mark - 请求（禁用 SSL 证书校验，与 App 的 Flutter 一致）

@interface SLURLSessionDelegate : NSObject <NSURLSessionDelegate>
@end

@implementation SLURLSessionDelegate
- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler {
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        // 直接信任任意服务器证书（App 的 Flutter 同样不校验）
        NSURLCredential *cred = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        if (cred) {
            completionHandler(NSURLSessionAuthChallengeUseCredential, cred);
            return;
        }
    }
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}
@end

static SLURLSessionDelegate *slSessionDelegateInstance(void) {
    static SLURLSessionDelegate *d = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ d = [[SLURLSessionDelegate alloc] init]; });
    return d;
}

static void slRequestInternal(NSString *method, NSString *path, NSDictionary *body, NSString *token, int hostIndex, void (^done)(NSDictionary *json, NSString *raw, NSError *err, BOOL lastTry)) {
    NSArray *hosts = slHosts();
    if (hostIndex >= (int)hosts.count) {
        if (done) done(nil, @"", nil, YES);
        return;
    }
    NSURL *url = [NSURL URLWithString:[hosts[hostIndex] stringByAppendingString:path]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.timeoutInterval = 8;
    if ([method isEqualToString:@"POST"]) {
        req.HTTPMethod = @"POST";
        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        req.HTTPBody = [NSJSONSerialization dataWithJSONObject:body ?: @{} options:0 error:nil];
    }
    if (token) {
        [req setValue:[@"Bearer " stringByAppendingString:token] forHTTPHeaderField:@"Authorization"];
    }
    [req setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    [req setValue:@"ShanLianVPN/4.5.4 (iPhone; iOS 17.0)" forHTTPHeaderField:@"User-Agent"];

    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    cfg.connectionProxyDictionary = @{};   // 直连
    cfg.timeoutIntervalForRequest = 8;
    cfg.timeoutIntervalForResource = 8;
    NSURLSession *sess = [NSURLSession sessionWithConfiguration:cfg delegate:slSessionDelegateInstance() delegateQueue:nil];
    [[sess dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        BOOL isLast = (hostIndex >= (int)hosts.count - 1);
        if (err) {
            slLog(@"%@ %@ 域名%@失败 err=%@", method, path, hosts[hostIndex], err);
            [sess invalidateAndCancel];
            slRequestInternal(method, path, body, token, hostIndex + 1, done);
            return;
        }
        [sess invalidateAndCancel];
        NSString *raw = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"";
        NSDictionary *json = nil;
        if (data.length) {
            json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        }
        if (done) done(json, raw, nil, isLast);
    }] resume];
}

static void slRequest(NSString *method, NSString *path, NSDictionary *body, NSString *token, void (^done)(NSDictionary *json, NSString *raw, NSError *err)) {
    slRequestInternal(method, path, body, token, 0, ^(NSDictionary *json, NSString *raw, NSError *err, BOOL last) {
        if (done) done(json, raw, err);
    });
}

#pragma mark - 节点转 Shadowrocket

static NSString *slURIFromDict(NSDictionary *d) {
    NSString *name = d[@"name"] ?: d[@"remark"] ?: d[@"title"] ?: d[@"ps"] ?: d[@"tag"] ?: @"sl";
    NSString *host = d[@"server"] ?: d[@"host"] ?: d[@"address"] ?: d[@"addr"] ?: d[@"ip"];
    NSNumber *portN = d[@"port"] ?: d[@"server_port"];
    if (!host || !portN) return nil;
    NSString *port = [portN stringValue];
    NSString *uuid = d[@"uuid"] ?: d[@"id"];
    NSString *method = d[@"method"] ?: d[@"cipher"] ?: @"aes-128-gcm";
    NSString *passwd = d[@"password"] ?: d[@"key"];
    NSString *sni = d[@"sni"] ?: d[@"servername"] ?: d[@"serverName"];
    NSDictionary *tls = d[@"tls"];
    if ([tls isKindOfClass:[NSDictionary class]] && !sni) sni = tls[@"server_name"] ?: tls[@"serverName"];
    NSString *type = d[@"type"] ?: d[@"protocol"];
    if ([type isKindOfClass:[NSString class]]) {
        if ([type isEqualToString:@"selector"] || [type isEqualToString:@"urltest"] ||
            [type isEqualToString:@"direct"] || [type isEqualToString:@"block"] ||
            [type isEqualToString:@"dns"] || [type isEqualToString:@"reject"] ||
            [type isEqualToString:@"loopback"] || [type isEqualToString:@"wireguard"]) {
            return nil;
        }
    }

    NSData *nameData = [name dataUsingEncoding:NSUTF8StringEncoding];
    NSString *nameB64 = [nameData base64EncodedStringWithOptions:0];

    if (uuid && passwd && [passwd length] > 0) {
        return [@"trojan://" stringByAppendingString:[NSString stringWithFormat:@"%@:%@@%@:%@?peer=%@#%@",
                                                      uuid, passwd, host, port, sni ?: @"", nameB64]];
    }
    if (uuid) {
        return [@"vless://" stringByAppendingString:[NSString stringWithFormat:@"%@:%@@%@:%@?encryption=none&security=tls&sni=%@#%@",
                                                     uuid, @"", host, port, sni ?: @"", nameB64]];
    }
    if (passwd && method) {
        NSData *userinfo = [[NSString stringWithFormat:@"%@:%@", method, passwd] dataUsingEncoding:NSUTF8StringEncoding];
        NSString *uiB64 = [[userinfo base64EncodedStringWithOptions:0] stringByReplacingOccurrencesOfString:@"=" withString:@""];
        return [NSString stringWithFormat:@"ss://%@@%@:%@#%@", uiB64, host, port, nameB64];
    }
    return nil;
}

static void slCollectNodes(id obj, NSMutableArray *uris, int depth) {
    if (!obj || depth > 6) return;
    if ([obj isKindOfClass:[NSArray class]]) {
        for (id item in (NSArray *)obj) {
            slCollectNodes(item, uris, depth + 1);
        }
    } else if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary *d = (NSDictionary *)obj;
        for (NSString *key in @[@"outbounds", @"nodes", @"servers", @"serverList", @"list", @"proxies", @"configs", @"data", @"subs", @"groups", @"items", @"list2", @"urls", @"links", @"v2ray", @"nodesList", @"nodeList"]) {
            id val = d[key];
            if ([val isKindOfClass:[NSArray class]]) {
                for (id item in (NSArray *)val) {
                    if ([item isKindOfClass:[NSDictionary class]]) {
                        NSString *uri = slURIFromDict((NSDictionary *)item);
                        if (uri) [uris addObject:uri];
                    } else if ([item isKindOfClass:[NSString class]]) {
                        NSString *str = (NSString *)item;
                        if ([str hasPrefix:@"vless://"] || [str hasPrefix:@"vmess://"] ||
                            [str hasPrefix:@"trojan://"] || [str hasPrefix:@"ss://"] ||
                            [str hasPrefix:@"hysteria"]) {
                            [uris addObject:str];
                        } else {
                            slCollectNodes(item, uris, depth + 1);
                        }
                    } else {
                        slCollectNodes(item, uris, depth + 1);
                    }
                }
            } else if ([val isKindOfClass:[NSString class]]) {
                NSString *str = (NSString *)val;
                if ([str hasPrefix:@"vless://"] || [str hasPrefix:@"vmess://"] ||
                    [str hasPrefix:@"trojan://"] || [str hasPrefix:@"ss://"]) {
                    [uris addObject:str];
                }
            }
        }
        NSString *uri = slURIFromDict(d);
        if (uri && ![uris containsObject:uri]) [uris addObject:uri];
    }
}

#pragma mark - 主流程：读 token → 抓节点

static void slRunFlow(void) {
    slLog(@"===== 闪连抓节点开始(读现有登录态) %@ =====", [NSDate date]);

    NSDictionary *found = slScanUserDefaults();
    slLog(@"UserDefaults 候选 key 数: %lu", (unsigned long)found.count);
    for (NSString *k in found) {
        NSString *v = found[k];
        slLog(@"  key=%@ len=%lu prefix=%@", k, (unsigned long)v.length,
              v.length > 30 ? [v substringToIndex:30] : v);
    }
    NSString *keychain = slScanKeychain();
    if (keychain.length) slLog(@"Keychain 命中 token len=%lu", (unsigned long)keychain.length);

    NSString *token = slPickToken(found, keychain);
    if (!token.length) {
        slLog(@"未找到任何 token，请确认 App 已登录");
        slShowAlert(@"闪连助手", @"未找到登录 token\n请先在闪连VPN里登录一次再试");
        return;
    }
    slLog(@"使用 token len=%lu", (unsigned long)token.length);

    slRequest(@"GET", @"/app/customer/slgetNodes", nil, token, ^(NSDictionary *json, NSString *raw, NSError *err) {
        if (err) {
            slLog(@"节点请求失败 err=%@", err);
            slShowAlert(@"闪连助手", [NSString stringWithFormat:@"节点请求失败\n%@", err.localizedDescription]);
            return;
        }
        slLog(@"节点响应长度: %lu", (unsigned long)raw.length);
        NSString *docDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
        [raw writeToFile:[docDir stringByAppendingPathComponent:@"sl_nodes_raw.json"] atomically:YES encoding:NSUTF8StringEncoding error:nil];

        // 若响应含 base64 密文特征（如 rivoLinks 式），提示用户把原始 JSON 发回，再适配解密
        if ([raw containsString:@"rivoLinks"] || [raw containsString:@"links"] ||
            [raw containsString:@"dataList"] || [raw containsString:@"encrypt"] ||
            [raw containsString:@"cipher"]) {
            slLog(@"响应可能含密文字段，先保存原始数据");
        }

        NSMutableArray *uris = [NSMutableArray array];
        if ([json isKindOfClass:[NSDictionary class]] || [json isKindOfClass:[NSArray class]]) {
            slCollectNodes(json, uris, 0);
        }

        if (uris.count == 0) {
            slLog(@"未解析出节点，完整响应前500: %@", raw.length > 500 ? [raw substringToIndex:500] : raw);
            slShowAlert(@"闪连助手", [NSString stringWithFormat:@"拿到响应但未解析出节点\n原始JSON已存 Documents/sl_nodes_raw.json\n前500字符:\n%@",
                                      raw.length > 500 ? [raw substringToIndex:500] : raw]);
            return;
        }

        NSString *subText = [uris componentsJoinedByString:@"\n"];
        NSData *subData = [subText dataUsingEncoding:NSUTF8StringEncoding];
        NSString *subB64 = [[subData base64EncodedStringWithOptions:0] stringByReplacingOccurrencesOfString:@"=" withString:@""];
        NSString *subLink = [@"sub://" stringByAppendingString:subB64];

        UIPasteboard *pb = [UIPasteboard generalPasteboard];
        pb.string = subLink;
        [subText writeToFile:[docDir stringByAppendingPathComponent:@"sl_sub.txt"] atomically:YES encoding:NSUTF8StringEncoding error:nil];

        slLog(@"成功: %lu 节点, 订阅已复制", (unsigned long)uris.count);
        slShowAlert(@"闪连助手", [NSString stringWithFormat:@"抓取 %lu 个节点\n订阅已复制到剪贴板\nShadowrocket 粘贴导入即可", (unsigned long)uris.count]);
    });
}

#pragma mark - 出站请求记录（看 App 真实怎么带鉴权）

@interface SLReqProtocol : NSURLProtocol
@end

static void slLogRequest(NSURLRequest *req, NSData *bodyData) {
    if (!req.URL) return;
    NSString *u = req.URL.absoluteString;
    // 只记 API 类请求，过滤图片/统计
    if ([u containsString:@"aslafvbn"] || [u containsString:@"slaclouds"] ||
        [u containsString:@"slacover"] || [u containsString:@"slapower"] ||
        [u containsString:@"slcloudstore"] || [u containsString:@"sladoc"] ||
        [u containsString:@"surfonline"] || [u containsString:@"shanlian"] ||
        [u containsString:@"nodes"] || [u containsString:@"register"] ||
        [u containsString:@"login"] || [u containsString:@"invite"] ||
        [u containsString:@"user"] || [u containsString:@"token"]) {
        NSMutableString *ms = [NSMutableString string];
        [ms appendFormat:@"\n>>> OUT %@ %@", req.HTTPMethod ?: @"GET", u];
        for (NSString *k in req.allHTTPHeaderFields) {
            [ms appendFormat:@"\n    H %@: %@", k, req.allHTTPHeaderFields[k]];
        }
        if (bodyData.length) {
            NSString *bs = [[NSString alloc] initWithData:bodyData encoding:NSUTF8StringEncoding];
            if (bs.length > 800) bs = [bs substringToIndex:800];
            [ms appendFormat:@"\n    BODY %@", bs ?: @""];
        }
        slLog(@"%@", ms);
    }
}

@implementation SLReqProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    slLogRequest(request, request.HTTPBody);
    return NO;  // 只观察，不拦截
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)startLoading {}
- (void)stopLoading {}
@end

static id (*orig_slDataTask)(id, SEL, NSURLRequest *, id);

static id slDataTaskHook(id self, SEL _cmd, NSURLRequest *req, id completion) {
    @try {
        slLogRequest(req, req.HTTPBody);
    } @catch (NSException *e) {}
    return ((id (*)(id, SEL, id, id))orig_slDataTask)(self, _cmd, req, completion);
}

static void slHookOutbound(void) {
    [NSURLProtocol registerClass:[SLReqProtocol class]];
    Method md = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:completionHandler:));
    if (md) {
        orig_slDataTask = (void *)method_getImplementation(md);
        method_setImplementation(md, (IMP)slDataTaskHook);
        slLog(@"outbound recorder installed (NSURLProtocol + dataTask)");
    }
}

__attribute__((constructor)) static void slInit(void) {
    slHookOutbound();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
                       slRunFlow();
                   });
}
