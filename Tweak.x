#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import "fishhook.h"

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
// v3.7 变更（依据用户装测 sl_debug.txt 出站记录）：
//   - App 真实 UA = "Shan Lian" + 自定义头 shanlian:1（之前自造 UA 触发 SSL 失败/风控）。
//   - 真实域名 10 个（日志抓到的 getIw 轮询域名），补全 slHosts。
//   - App 真实 deviceId 存钥匙串 kShanLianDeviceIdKey（36位），优先读取替代自造 UUID。
//   - 出站记录器 URL 过滤改大小写不敏感 + 补 slgetNodes/getNodes 关键词
//     （之前漏掉节点请求，导致"点连接"的真实鉴权头没被记录）。

static NSArray *slHosts(void) {
    return @[@"https://api.aslafvbn.shop",
             @"https://api.qinghuapf.cn",
             @"https://api.slacover.com",
             @"https://api.intlcg.com",
             @"https://api.slcloudstore.com",
             @"https://api.slapower.com",
             @"https://api.intljp.com",
             @"https://api.sladoc.com",
             @"https://api.intldllc.com",
             @"https://api.slaclouds.com"];
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

// 固定设备 ID：优先读 App 钥匙串 kShanLianDeviceIdKey（真实 deviceId），
// 读不到才自造并持久化（保证签名/注册与 App 一致）
static NSString *slDeviceId(void) {
    NSString *k = @"sl_dylib_device_id";
    NSString *v = [[NSUserDefaults standardUserDefaults] stringForKey:k];
    // 尝试从钥匙串读 App 真实 deviceId
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    query[(__bridge id)kSecAttrService] = @"flutter_secure_storage_service";
    query[(__bridge id)kSecAttrAccount] = @"kShanLianDeviceIdKey";
    query[(__bridge id)kSecReturnData] = @YES;
    CFDataRef outData = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&outData);
    if (st == errSecSuccess && outData) {
        NSString *kv = [[NSString alloc] initWithData:(__bridge_transfer NSData *)outData encoding:NSUTF8StringEncoding];
        if (kv.length == 36) {
            return kv;
        }
    }
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
    // v3.7: 与 App 真实请求一致（日志实测 UA=Shan Lian + shanlian:1），避免风控/SSL 拒绝
    [req setValue:@"Shan Lian" forHTTPHeaderField:@"User-Agent"];
    [req setValue:@"1" forHTTPHeaderField:@"shanlian"];

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
        [NSThread sleepForTimeInterval:1.5];
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

// v3.8.1: 停用后函数未使用触发 -Werror，加 unused 属性保留（恢复自动抓取时取消 slInit 调度即可）
static void slRunFlow(void) __attribute__((unused));
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
    NSString *low = [u lowercaseString];
    // v3.7: 大小写不敏感匹配 + 补 slgetNodes/getNodes 关键词（之前漏记节点请求）
    if ([low containsString:@"aslafvbn"] || [low containsString:@"slaclouds"] ||
        [low containsString:@"slacover"] || [low containsString:@"slapower"] ||
        [low containsString:@"slcloudstore"] || [low containsString:@"sladoc"] ||
        [low containsString:@"surfonline"] || [low containsString:@"shanlian"] ||
        [low containsString:@"slgetnodes"] || [low containsString:@"getnodes"] ||
        [low containsString:@"nodes"] || [low containsString:@"register"] ||
        [low containsString:@"login"] || [low containsString:@"invite"] ||
        [low containsString:@"user"] || [low containsString:@"token"] ||
        [low containsString:@"intlcg"] || [low containsString:@"intljp"] ||
        [low containsString:@"intldllc"] || [low containsString:@"qinghuapf"]) {
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

// v3.8: 响应拦截转发——App 自己请求 slgetNodesgs 时（已带合法 JWT），
// 我们截住转发并保存响应（节点 JSON），100% 拿到真实节点数据。
@interface SLRespProtocol : NSURLProtocol
@end

@implementation SLRespProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"SLRESP_SKIP" inRequest:request]) return NO; // 防循环
    NSString *u = [request.URL.absoluteString lowercaseString];
    if ([u containsString:@"slgetnodes"] || [u containsString:@"getnodes"]) {
        return YES;
    }
    return NO;
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
- (void)startLoading {
    NSMutableURLRequest *r = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"SLRESP_SKIP" inRequest:r];
    NSURLSession *s = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]];
    [[s dataTaskWithRequest:r completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        [s invalidateAndCancel];
        if (!err && data.length) {
            // 保存节点响应（原始 JSON）
            NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/sl_nodes_raw.json"];
            [data writeToFile:path atomically:YES];
            NSString *head = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (head.length > 600) head = [head substringToIndex:600];
            slLog(@"[SLRESP] 节点响应已保存 %lu 字节 -> sl_nodes_raw.json\n%@", (unsigned long)data.length, head);
            dispatch_async(dispatch_get_main_queue(), ^{
                slShowAlert(@"节点响应已抓取", [NSString stringWithFormat:@"已保存 %lu 字节到 sl_nodes_raw.json", (unsigned long)data.length]);
            });
        } else if (err) {
            slLog(@"[SLRESP] 节点响应失败 err=%@", err.localizedDescription);
        }
        // 转发给原始请求方（不能影响 App 自身功能）
        if (!err) {
            NSHTTPURLResponse *hr = (NSHTTPURLResponse *)resp;
            [self.client URLProtocol:self didReceiveResponse:hr cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:data];
            [self.client URLProtocolDidFinishLoading:self];
        } else {
            [self.client URLProtocol:self didFailWithError:err];
        }
    }] resume];
}
- (void)stopLoading {}
@end

// v3.9: hook CCCrypt（CommonCrypto AES）——App 在原生层解密节点时 dump key/iv/明文。
// 背景：sl_nodes_raw.json 的 data 是 AES 密文（16 对齐、随机字节），盲试密钥无意义；
// 若 App 用 CommonCrypto 解密，CCCrypt 的 outData 就是节点明文 JSON，直接截获。
static CCCryptorStatus (*orig_CCCrypt)(CCOperation op, CCAlgorithm alg, CCOptions options,
    const void *key, size_t keyLength, const void *iv,
    const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable,
    size_t *dataOutMoved);

static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options,
    const void *key, size_t keyLength, const void *iv,
    const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable,
    size_t *dataOutMoved) {
    CCCryptorStatus st = orig_CCCrypt(op, alg, options, key, keyLength, iv, dataIn, dataInLength, dataOut, dataOutAvailable, dataOutMoved);
    @try {
        if (alg != kCCAlgorithmAES) return st;
        size_t outLen = (dataOutMoved && st == kCCSuccess) ? *dataOutMoved : 0;
        NSMutableString *kh = [NSMutableString string];
        for (size_t i = 0; i < keyLength; i++) [kh appendFormat:@"%02x", ((const unsigned char*)key)[i]];
        NSString *ivh = @"-";
        if (iv) {
            NSMutableString *t = [NSMutableString string];
            for (int i = 0; i < 16; i++) [t appendFormat:@"%02x", ((const unsigned char*)iv)[i]];
            ivh = t;
        }
        if (op == kCCEncrypt) {
            if (dataInLength > 100) slLog(@"[CCCrypt] ENC alg=%d keyLen=%zu in=%zu key=%@ iv=%@", (int)alg, keyLength, dataInLength, kh, ivh);
            return st;
        }
        // DEC
        slLog(@"[CCCrypt] DEC alg=%d keyLen=%zu in=%zu out=%zu key=%@ iv=%@", (int)alg, keyLength, dataInLength, outLen, kh, ivh);
        if (outLen > 0) {
            NSString *s = [[NSString alloc] initWithBytes:dataOut length:outLen encoding:NSUTF8StringEncoding];
            if (s) {
                if (outLen > 50) slLog(@"[CCCrypt] DEC text(%.200s)", s.UTF8String);
                if ([s containsString:@"vmess"] || [s containsString:@"\"host\""] || [s containsString:@"\"port\""] ||
                    [s containsString:@"ss://"] || [s containsString:@"trojan"] || [s containsString:@"ws://"]) {
                    NSString *pp = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/sl_nodes_plain.json"];
                    [s writeToFile:pp atomically:YES encoding:NSUTF8StringEncoding error:nil];
                    slLog(@"[CCCrypt] ★节点明文已保存 -> sl_nodes_plain.json");
                    dispatch_async(dispatch_get_main_queue(), ^{
                        slShowAlert(@"节点明文已解密", @"已保存到 sl_nodes_plain.json，可直接转订阅");
                    });
                }
            } else {
                slLog(@"[CCCrypt] DEC binary out=%zu first=%@", outLen,
                      [[NSData dataWithBytes:dataOut length:MIN(outLen,16)] base64EncodedStringWithOptions:0]);
            }
        }
    } @catch (NSException *e) {
        slLog(@"[CCCrypt] hook 异常 %@", e);
    }
    return st;
}

static void slHookCCCrypt(void) {
    rebind_symbols((struct rebinding[]){
        {"CCCrypt", (void*)my_CCCrypt, (void**)&orig_CCCrypt}
    }, 1);
    slLog(@"CCCrypt hooked");
}

// ============ v4.0: hook CCCryptorCreateWithMode / CCCryptorUpdate / CCCryptorGCM ============
// 背景：v3.9 的 CCCrypt hook 零命中 → App 解密不走 CCCrypt。
// CryptoKit(Swift) 底层走 CCCryptorCreateWithMode(kCCModeGCM=11) + CCCryptorUpdate，
// 或一键 CCCryptorGCM——这些才是 GCM 解密的真正入口。
// 目标：dump 出 key/iv（自动写 Documents/sl_crypt_keys.txt）+ 截获节点明文。
#define SL_MAX_REFS 64
typedef struct {
    CCCryptorRef ref;
    int op;
    int mode;
    int alg;
    int padding;
    char keyHex[160];
    char ivHex[160];
} SLRefRec;

static SLRefRec slRefs[SL_MAX_REFS];
static int slRefCnt = 0;

static CCCryptorStatus (*orig_CCCreateMode)(CCOperation op, CCMode mode, CCAlgorithm alg, CCPadding padding,
    const void *iv, const void *key, size_t keyLength,
    const void *tweak, size_t tweakLength, int numRounds, CCModeOptions options, CCCryptorRef *cryptorRef);
static CCCryptorStatus (*orig_CCUpdate)(CCCryptorRef cryptorRef, const void *dataIn, size_t dataInLength,
    void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved);
static CCCryptorStatus (*orig_CCFinal)(CCCryptorRef cryptorRef, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved);
static CCCryptorStatus (*orig_CCGCM)(CCOperation op, CCAlgorithm alg, const void *key, size_t keyLength,
    const void *iv, size_t ivLength, const void *aData, size_t aDataLength,
    const void *dataIn, size_t dataInLength, void *dataOut, const void *tag, size_t *tagLength);

static void slDumpHex(char *out, size_t outCap, const void *p, size_t n) {
    size_t m = MIN(n, (outCap - 1) / 2);
    for (size_t i = 0; i < m; i++) sprintf(out + i * 2, "%02x", ((const unsigned char *)p)[i]);
    out[m * 2] = 0;
}

static void slCheckPlainAndSave(const void *dataOut, size_t outLen) {
    if (!dataOut || outLen < 50) return;
    NSString *s = [[NSString alloc] initWithBytes:dataOut length:outLen encoding:NSUTF8StringEncoding];
    if (!s) return;
    if ([s containsString:@"vmess"] || [s containsString:@"\"host\""] || [s containsString:@"\"port\""] ||
        [s containsString:@"ss://"] || [s containsString:@"trojan"] || [s containsString:@"ws://"]) {
        NSString *pp = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/sl_nodes_plain.json"];
        [s writeToFile:pp atomically:YES encoding:NSUTF8StringEncoding error:nil];
        slLog(@"[CCMODE] ★节点明文已保存 -> sl_nodes_plain.json (len=%zu)", outLen);
        dispatch_async(dispatch_get_main_queue(), ^{
            slShowAlert(@"节点明文已解密", @"已保存到 sl_nodes_plain.json，可直接转订阅");
        });
    }
}

static SLRefRec *slFindRef(CCCryptorRef ref) {
    for (int i = 0; i < slRefCnt; i++) {
        if (slRefs[i].ref == ref) return &slRefs[i];
    }
    return NULL;
}

static CCCryptorStatus my_CCCreateMode(CCOperation op, CCMode mode, CCAlgorithm alg, CCPadding padding,
    const void *iv, const void *key, size_t keyLength,
    const void *tweak, size_t tweakLength, int numRounds, CCModeOptions options, CCCryptorRef *cryptorRef) {
    CCCryptorStatus st = orig_CCCreateMode(op, mode, alg, padding, iv, key, keyLength, tweak, tweakLength, numRounds, options, cryptorRef);
    @try {
        if (st != kCCSuccess || !cryptorRef || !*cryptorRef) return st;
        char kh[160] = "-", ih[160] = "-";
        if (key && keyLength > 0) slDumpHex(kh, sizeof(kh), key, keyLength);
        if (iv) slDumpHex(ih, sizeof(ih), iv, 16);
        slLog(@"[CCMODE] op=%d mode=%d alg=%d pad=%d keyLen=%zu key=%@ iv=%@", op, mode, alg, padding, keyLength,
            [NSString stringWithUTF8String:kh], [NSString stringWithUTF8String:ih]);
        // 自动落盘密钥（追加），便于回传分析
        if (keyLength == 16 || keyLength == 32 || keyLength == 24) {
            NSString *kp = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/sl_crypt_keys.txt"];
            NSString *line = [NSString stringWithFormat:@"op=%d mode=%d alg=%d keyLen=%zu key=%s iv=%s\n", op, mode, alg, keyLength, kh, ih];
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:kp];
            if (!fh) {
                [line writeToFile:kp atomically:YES encoding:NSUTF8StringEncoding error:nil];
            } else {
                @try { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
                @catch (NSException *e) {}
            }
        }
        if (slRefCnt < SL_MAX_REFS) {
            SLRefRec *r = &slRefs[slRefCnt++];
            memset(r, 0, sizeof(SLRefRec));
            r->ref = *cryptorRef; r->op = op; r->mode = mode; r->alg = alg; r->padding = padding;
            strncpy(r->keyHex, kh, sizeof(r->keyHex) - 1);
            strncpy(r->ivHex, ih, sizeof(r->ivHex) - 1);
        }
    } @catch (NSException *e) {
        slLog(@"[CCMODE] create hook 异常 %@", e);
    }
    return st;
}

static CCCryptorStatus my_CCUpdate(CCCryptorRef cryptorRef, const void *dataIn, size_t dataInLength,
    void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    CCCryptorStatus st = orig_CCUpdate(cryptorRef, dataIn, dataInLength, dataOut, dataOutAvailable, dataOutMoved);
    @try {
        SLRefRec *r = slFindRef(cryptorRef);
        // 只记录大块数据（节点密文 32KB 级别；小包跳过防刷屏）
        if (dataInLength >= 2000) {
            char h[200] = "-";
            slDumpHex(h, sizeof(h), dataIn, 96);
            slLog(@"[CCMODE-upd] ref=%p op=%d mode=%d alg=%d in=%zu key=%s iv=%s first=%@",
                cryptorRef, r ? r->op : -1, r ? r->mode : -1, r ? r->alg : -1, dataInLength,
                r ? r->keyHex : "-", r ? r->ivHex : "-", [NSString stringWithUTF8String:h]);
        }
        // DEC 且出数据 → 检查节点明文
        if (st == kCCSuccess && dataOutMoved && *dataOutMoved > 0 && r && r->op == kCCDecrypt) {
            slCheckPlainAndSave(dataOut, *dataOutMoved);
        }
    } @catch (NSException *e) {
        slLog(@"[CCMODE] update hook 异常 %@", e);
    }
    return st;
}

static CCCryptorStatus my_CCFinal(CCCryptorRef cryptorRef, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    CCCryptorStatus st = orig_CCFinal(cryptorRef, dataOut, dataOutAvailable, dataOutMoved);
    @try {
        if (st == kCCSuccess && dataOutMoved && *dataOutMoved > 0) {
            SLRefRec *r = slFindRef(cryptorRef);
            if (r && r->op == kCCDecrypt) slCheckPlainAndSave(dataOut, *dataOutMoved);
        }
    } @catch (NSException *e) {}
    return st;
}

static CCCryptorStatus my_CCGCM(CCOperation op, CCAlgorithm alg, const void *key, size_t keyLength,
    const void *iv, size_t ivLength, const void *aData, size_t aDataLength,
    const void *dataIn, size_t dataInLength, void *dataOut, const void *tag, size_t *tagLength) {
    CCCryptorStatus st = orig_CCGCM(op, alg, key, keyLength, iv, ivLength, aData, aDataLength,
        dataIn, dataInLength, dataOut, tag, tagLength);
    @try {
        char kh[160] = "-", ih[160] = "-";
        if (key && keyLength > 0) slDumpHex(kh, sizeof(kh), key, keyLength);
        if (iv && ivLength > 0) slDumpHex(ih, sizeof(ih), iv, ivLength);
        slLog(@"[CCGCM] op=%d alg=%d keyLen=%zu ivLen=%zu aData=%zu in=%zu tagLen=%zu key=%s iv=%s",
            op, alg, keyLength, ivLength, aDataLength, dataInLength, tagLength ? *tagLength : 0, kh, ih);
        if (op == kCCDecrypt && st == kCCSuccess && dataOut) {
            slCheckPlainAndSave(dataOut, dataInLength);
        }
    } @catch (NSException *e) {
        slLog(@"[CCGCM] hook 异常 %@", e);
    }
    return st;
}

static void slHookCCCryptors(void) {
    rebind_symbols((struct rebinding[]){
        {"CCCryptorCreateWithMode", (void*)my_CCCreateMode, (void**)&orig_CCCreateMode},
        {"CCCryptorUpdate", (void*)my_CCUpdate, (void**)&orig_CCUpdate},
        {"CCCryptorFinal", (void*)my_CCFinal, (void**)&orig_CCFinal},
        {"CCCryptorGCM", (void*)my_CCGCM, (void**)&orig_CCGCM}
    }, 4);
    slLog(@"CCCryptor hooks installed (CreateWithMode/Update/Final/GCM)");
}

static id (*orig_slDataTask)(id, SEL, NSURLRequest *, id);

static id slDataTaskHook(id self, SEL _cmd, NSURLRequest *req, id completion) {
    @try {
        slLogRequest(req, req.HTTPBody);
    } @catch (NSException *e) {}
    return ((id (*)(id, SEL, id, id))orig_slDataTask)(self, _cmd, req, completion);
}

static void slHookOutbound(void) {
    [NSURLProtocol registerClass:[SLReqProtocol class]];
    [NSURLProtocol registerClass:[SLRespProtocol class]]; // v3.8: 拦截节点响应
    Method md = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:completionHandler:));
    if (md) {
        orig_slDataTask = (void *)method_getImplementation(md);
        method_setImplementation(md, (IMP)slDataTaskHook);
        slLog(@"outbound recorder installed (NSURLProtocol + dataTask)");
    }
}

__attribute__((constructor)) static void slInit(void) {
    slHookCCCrypt(); // v3.9: hook CCCrypt
    slHookCCCryptors(); // v4.0: hook CCCryptorCreateWithMode/Update/Final/GCM（GCM 真正入口）
    slHookOutbound();
    // v3.8: 停用自动伪造鉴权流程（旧 token 已失效 + 加密 data 无法伪造，徒增干扰），
    // 改为纯被动：App 自己点连接时拦截响应拿节点 JSON。
    // 需要恢复主动抓取时再启用 slRunFlow。
    // dispatch_after(..., slRunFlow);
}
