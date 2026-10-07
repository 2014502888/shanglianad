#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonDigest.h>

// 前置声明（v3.6.1 修复）：slHandleNodesResponse 在 slURIFromDict/slCollectNodes 定义前调用，
// C99 后隐式函数声明是编译错误，需 forward declaration
static NSString *slURIFromDict(NSDictionary *d);
static void slCollectNodes(id obj, NSMutableArray *uris, int depth);

// ===== ShanLianAD v3.6: 真实接口(带后缀) + 设备签名鉴权组合 + 自动游客注册/邀请码 =====
// v3.6 变更（依据 App AOT 逆向）：
//   - 真实接口名带混淆后缀（服务器剥后缀路由）：节点 = /app/customer/slgetNodesgs，
//     游客注册 = /app/tourist/slgenRandomUsergr，注册 = /app/tourist/slregisterrr，
//     填邀请码 = /app/customer/slfillInviteCodefe，设备登录 = /app/tourist/sldeviceLogindn。
//   - 鉴权疑似 token + deviceSig(设备签名) + encryptUid，v3.5 只试 6 种裸 token 头故全 401。
//   - 新增自动流程：无 token → 游客注册拿 token → 填邀请码 88888888 → 再抓节点。
//   - 路径带后缀 + 组合头逐个实测，全程写 sl_debug.txt。

static NSArray *slHosts(void) {
    return @[@"https://api.aslafvbn.shop",
             @"https://api.qinghuapf.cn",
             @"https://api.sladoc.com"];
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

static NSString *slMD5(NSString *s) {
    if (!s.length) return @"";
    const char *cstr = [s UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cstr, (CC_LONG)strlen(cstr), digest);
    NSMutableString *out = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) [out appendFormat:@"%02x", digest[i]];
    return out;
}

// 固定设备 ID（首次运行生成并持久化，保证签名/注册一致性）
static NSString *slDeviceId(void) {
    NSString *k = @"sl_dylib_device_id";
    NSString *v = [[NSUserDefaults standardUserDefaults] stringForKey:k];
    if (!v.length) {
        v = [[[NSUUID UUID] UUIDString] lowercaseString];
        [[NSUserDefaults standardUserDefaults] setObject:v forKey:k];
    }
    return v;
}

static NSString *slTimestamp(void) {
    return [NSString stringWithFormat:@"%lld", (long long)[[NSDate date] timeIntervalSince1970]];
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

// 处理节点响应（成功路径）
static void slHandleNodesResponse(NSDictionary *json, NSString *raw, NSString *from) {
    slLog(@"节点响应长度: %lu (来自 %@)", (unsigned long)raw.length, from);
    NSString *docDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    [raw writeToFile:[docDir stringByAppendingPathComponent:@"sl_nodes_raw.json"] atomically:YES encoding:NSUTF8StringEncoding error:nil];

    NSMutableArray *uris = [NSMutableArray array];
    if ([json isKindOfClass:[NSDictionary class]] || [json isKindOfClass:[NSArray class]]) {
        slCollectNodes(json, uris, 0);
    }
    // 响应可能是纯文本订阅（每行一个节点）
    if (uris.count == 0 && raw.length > 20) {
        for (NSString *line in [raw componentsSeparatedByString:@"\n"]) {
            if ([line hasPrefix:@"vless://"] || [line hasPrefix:@"vmess://"] ||
                [line hasPrefix:@"trojan://"] || [line hasPrefix:@"ss://"] ||
                [line hasPrefix:@"hysteria"]) {
                [uris addObject:line];
            }
        }
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

#pragma mark - 主流程：读 token → 抓节点（v3.6 多组合 + 自动注册）

// 带组合头的请求：headers 为字典数组 [{name,value},...]；多域名自动切换
static void slRWHeadersAt(NSString *method, NSString *path, NSDictionary *body, NSArray *headers, int host, void (^done)(NSDictionary *json, NSString *raw, NSError *err)) {
    NSArray *hosts = slHosts();
    if (host >= (int)hosts.count) {
        if (done) done(nil, @"", nil);
        return;
    }
    NSURL *url = [NSURL URLWithString:[hosts[host] stringByAppendingString:path]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.timeoutInterval = 10;
    if ([method isEqualToString:@"POST"]) {
        req.HTTPMethod = @"POST";
        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        req.HTTPBody = [NSJSONSerialization dataWithJSONObject:body ?: @{} options:0 error:nil];
    }
    for (NSDictionary *h in headers) {
        if (h[@"name"] && h[@"value"]) {
            [req setValue:h[@"value"] forHTTPHeaderField:h[@"name"]];
        }
    }
    [req setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    [req setValue:@"Dart/3.3 (dart:io)" forHTTPHeaderField:@"User-Agent"];

    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    cfg.connectionProxyDictionary = @{};
    cfg.timeoutIntervalForRequest = 10;
    cfg.timeoutIntervalForResource = 10;
    NSURLSession *sess = [NSURLSession sessionWithConfiguration:cfg delegate:slSessionDelegateInstance() delegateQueue:nil];
    [[sess dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        [sess invalidateAndCancel];
        if (err) {
            slLog(@"  域名%@失败 err=%@，切备用", hosts[host], err.localizedDescription);
            slRWHeadersAt(method, path, body, headers, host + 1, done);
            return;
        }
        NSString *raw = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"";
        NSDictionary *json = nil;
        if (data.length) json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if (done) done(json, raw, nil);
    }] resume];
}

static void slRequestWithHeaders(NSString *method, NSString *path, NSDictionary *body, NSArray *headers, void (^done)(NSDictionary *json, NSString *raw, NSError *err)) {
    slRWHeadersAt(method, path, body, headers, 0, done);
}

// 构造鉴权变体列表（v3.6：10 组，含设备签名/时间戳/deviceId 组合）
static NSArray *slBuildAuthVariants(NSString *token) {
    NSString *ts = slTimestamp();
    NSString *dev = slDeviceId();
    NSString *sign1 = slMD5([NSString stringWithFormat:@"%@%@", token, ts]);
    NSString *sign2 = slMD5([NSString stringWithFormat:@"%@%@%@", token, dev, ts]);
    return @[
        @{@"name": @"Bearer",      @"headers": @[@{@"name": @"Authorization", @"value": [@"Bearer " stringByAppendingString:token]}]},
        @{@"name": @"rawAuth",     @"headers": @[@{@"name": @"Authorization", @"value": token}]},
        @{@"name": @"tokenH",      @"headers": @[@{@"name": @"token",         @"value": token}]},
        @{@"name": @"xToken",      @"headers": @[@{@"name": @"x-token",       @"value": token}]},
        @{@"name": @"accTok",      @"headers": @[@{@"name": @"accessToken",   @"value": token}]},
        @{@"name": @"Bearer+aux",  @"headers": @[@{@"name": @"Authorization", @"value": [@"Bearer " stringByAppendingString:token]},
                                                   @{@"name": @"X-Device-Id", @"value": dev},
                                                   @{@"name": @"X-Timestamp", @"value": ts},
                                                   @{@"name": @"X-Platform",   @"value": @"ios"},
                                                   @{@"name": @"X-Version",    @"value": @"4.5.4"}]},
        @{@"name": @"raw+ts+sign", @"headers": @[@{@"name": @"Authorization", @"value": token},
                                                   @{@"name": @"X-Timestamp",  @"value": ts},
                                                   @{@"name": @"X-Sign",       @"value": sign1}]},
        @{@"name": @"token+dev+sign", @"headers": @[@{@"name": @"token",      @"value": token},
                                                   @{@"name": @"deviceId",     @"value": dev},
                                                   @{@"name": @"timestamp",    @"value": ts},
                                                   @{@"name": @"sign",         @"value": sign2}]},
        @{@"name": @"Bearer+dev+sign", @"headers": @[@{@"name": @"Authorization", @"value": [@"Bearer " stringByAppendingString:token]},
                                                   @{@"name": @"deviceId",     @"value": dev},
                                                   @{@"name": @"timestamp",    @"value": ts},
                                                   @{@"name": @"sign",         @"value": sign2}]},
        @{@"name": @"xToken+aux",  @"headers": @[@{@"name": @"x-token",       @"value": token},
                                                   @{@"name": @"X-Device-Id",  @"value": dev},
                                                   @{@"name": @"X-Timestamp",  @"value": ts}]},
    ];
}

static void slTryAuthVariants(NSString *token, NSString *path) {
    NSArray *variants = slBuildAuthVariants(token);
    __block BOOL done = NO;
    for (NSDictionary *v in variants) {
        if (done) break;
        NSString *name = v[@"name"];
        NSArray *headers = v[@"headers"];
        NSMutableString *hd = [NSMutableString string];
        for (NSDictionary *h in headers) {
            NSString *val = h[@"value"];
            [hd appendFormat:@"%@=%@... ", h[@"name"], val.length > 20 ? [val substringToIndex:20] : val];
        }
        slLog(@"尝试鉴权[%@]: %@", name, hd);
        slRequestWithHeaders(@"GET", path, nil, headers, ^(NSDictionary *json, NSString *raw, NSError *err) {
            if (err) {
                slLog(@"  [%@] 失败 err=%@", name, err.localizedDescription);
                return;
            }
            BOOL ok = !([raw containsString:@"401"] || [raw containsString:@"无权限"] || [raw containsString:@"\"code\":401"] || [raw containsString:@"\"code\":500"]);
            slLog(@"  [%@] 响应: %@ -> %@", name, raw.length > 140 ? [raw substringToIndex:140] : raw,
                  ok ? @"可能成功" : @"仍失败");
            if (ok && raw.length > 30) {
                done = YES;
                slHandleNodesResponse(json, raw, [NSString stringWithFormat:@"鉴权[%@]", name]);
            }
        });
        [NSThread sleepForTimeInterval:1.2];
    }
    if (!done) {
        slLog(@"鉴权组合全部失败，进入自动注册流程");
    }
}

// 游客注册：POST /app/tourist/slgenRandomUsergr，尝试取 token
static void slTryTouristRegister(void (^done)(NSString *tokenOrNil)) {
    NSString *dev = slDeviceId();
    NSDictionary *body = @{@"deviceId": dev, @"platform": @"ios", @"version": @"4.5.4", @"versionCode": @"1"};
    slLog(@"游客注册 slgenRandomUsergr...");
    slRequestWithHeaders(@"POST", @"/app/tourist/slgenRandomUsergr", body, @[], ^(NSDictionary *json, NSString *raw, NSError *err) {
        if (err) {
            slLog(@"  注册失败 err=%@", err.localizedDescription);
            if (done) done(nil);
            return;
        }
        slLog(@"  注册响应: %@", raw.length > 300 ? [raw substringToIndex:300] : raw);
        NSString *tok = nil;
        if ([json isKindOfClass:[NSDictionary class]]) {
            for (NSString *k in @[@"token", @"accessToken", @"access_token", @"userToken", @"data"]) {
                id v = json[k];
                if ([v isKindOfClass:[NSString class]] && [(NSString *)v length] > 10) { tok = v; break; }
                if ([v isKindOfClass:[NSDictionary class]]) {
                    id t2 = ((NSDictionary *)v)[@"token"] ?: ((NSDictionary *)v)[@"accessToken"];
                    if ([t2 isKindOfClass:[NSString class]] && [(NSString *)t2 length] > 10) { tok = t2; break; }
                }
            }
        }
        if (done) done(tok);
    });
}

// 填邀请码：POST /app/customer/slfillInviteCodefe
static void slTryFillInvite(NSString *token, void (^done)(BOOL ok)) {
    NSString *dev = slDeviceId();
    NSDictionary *body = @{@"inviteCode": @"88888888", @"deviceId": dev};
    NSArray *headers = @[@{@"name": @"Authorization", @"value": [@"Bearer " stringByAppendingString:token]}];
    slLog(@"填邀请码 88888888...");
    slRequestWithHeaders(@"POST", @"/app/customer/slfillInviteCodefe", body, headers, ^(NSDictionary *json, NSString *raw, NSError *err) {
        if (err) { slLog(@"  填码失败 err=%@", err.localizedDescription); if (done) done(NO); return; }
        slLog(@"  填码响应: %@", raw.length > 300 ? [raw substringToIndex:300] : raw);
        BOOL ok = !([raw containsString:@"401"] || [raw containsString:@"无权限"]);
        if (done) done(ok);
    });
}

static void slRunFlow(void) {
    slLog(@"===== 闪连抓节点 v3.6 开始 %@ =====", [NSDate date]);
    slLog(@"deviceId=%@", slDeviceId());

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
        slLog(@"未找到 token，走游客注册");
        slTryTouristRegister(^(NSString *newToken) {
            if (!newToken.length) {
                slLog(@"游客注册未拿到 token");
                slShowAlert(@"闪连助手", @"游客注册未返回 token\n请先手动登录一次，或把 sl_debug.txt 发我");
                return;
            }
            slLog(@"游客注册拿到新 token len=%lu，尝试填邀请码+抓节点", (unsigned long)newToken.length);
            slTryFillInvite(newToken, ^(BOOL ok) {
                if (ok) slLog(@"邀请码填写成功");
                else slLog(@"邀请码填写未确认（继续试节点）");
                slTryAuthVariants(newToken, @"/app/customer/slgetNodesgs");
                slShowAlert(@"闪连助手", @"自动流程已完成\n看 Documents/sl_debug.txt 结果");
            });
        });
        return;
    }
    slLog(@"使用已有 token len=%lu", (unsigned long)token.length);

    slTryAuthVariants(token, @"/app/customer/slgetNodesgs");
    // 全失败后：试填邀请码再抓一次（可能 token 需要绑定邀请码才有权限）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(20.0 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        slTryFillInvite(token, ^(BOOL ok) {
            if (ok) slLog(@"邀请码填写成功，再抓一次节点");
            slTryAuthVariants(token, @"/app/customer/slgetNodesgs");
            slShowAlert(@"闪连助手", @"自动流程已完成\n看 Documents/sl_debug.txt 结果");
        });
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
