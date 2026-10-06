#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

// ===== ShanLianAD v1: 闪连VPN 自动注册+邀请88888888+抓节点→Shadowrocket订阅 =====

static NSString *slBaseURL(void) {
    // App 主后端；多线路可切换
    return @"https://api.slaclouds.com";
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

// 通用请求：POST/GET JSON
static void slRequest(NSString *method, NSString *path, NSDictionary *body, NSString *token, void (^done)(NSDictionary *json, NSString *raw, NSError *err)) {
    NSURL *url = [NSURL URLWithString:[slBaseURL() stringByAppendingString:path]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.timeoutInterval = 20;
    if ([method isEqualToString:@"POST"]) {
        req.HTTPMethod = @"POST";
        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        if (body) {
            req.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
        } else {
            req.HTTPBody = [@"{}" dataUsingEncoding:NSUTF8StringEncoding];
        }
    }
    if (token) {
        [req setValue:[@"Bearer " stringByAppendingString:token] forHTTPHeaderField:@"Authorization"];
    }
    [req setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    [req setValue:@"ShanLianVPN/4.5.4 (iPhone; iOS 17.0)" forHTTPHeaderField:@"User-Agent"];

    NSURLSession *sess = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]];
    [[sess dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        NSString *raw = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"";
        NSDictionary *json = nil;
        if (data.length) {
            json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        }
        done(json, raw, err);
    }] resume];
}

#pragma mark - 节点转 Shadowrocket

static NSString *slURIFromDict(NSDictionary *d) {
    NSString *name = d[@"name"] ?: d[@"remark"] ?: d[@"title"] ?: d[@"ps"] ?: @"sl";
    NSString *host = d[@"server"] ?: d[@"host"] ?: d[@"address"] ?: d[@"addr"] ?: d[@"ip"];
    NSNumber *portN = d[@"port"];
    if (!host || !portN) return nil;
    NSString *port = [portN stringValue];
    NSString *uuid = d[@"uuid"] ?: d[@"id"] ?: d[@"password"];
    NSString *method = d[@"method"] ?: d[@"cipher"] ?: @"aes-128-gcm";
    NSString *passwd = d[@"password"] ?: d[@"key"];
    NSString *sni = d[@"sni"] ?: d[@"servername"] ?: d[@"serverName"] ?: d[@"host"];

    NSData *nameData = [name dataUsingEncoding:NSUTF8StringEncoding];
    NSString *nameB64 = [nameData base64EncodedStringWithOptions:0];

    if (uuid && passwd && [passwd length] > 0) {
        NSString *tp = [NSString stringWithFormat:@"%@:%@@%@:%@?peer=%@#%@",
                        uuid, passwd, host, port, sni ?: @"", nameB64];
        return [@"trojan://" stringByAppendingString:tp];
    }
    if (uuid) {
        NSString *vp = [NSString stringWithFormat:@"%@:%@@%@:%@?encryption=none&security=tls&sni=%@#%@",
                        uuid, @"", host, port, sni ?: @"", nameB64];
        return [@"vless://" stringByAppendingString:vp];
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
        for (NSString *key in @[@"outbounds", @"nodes", @"servers", @"serverList", @"list", @"proxies", @"configs", @"data", @"subs", @"groups", @"items"]) {
            id val = d[key];
            if ([val isKindOfClass:[NSArray class]]) {
                for (id item in (NSArray *)val) {
                    if ([item isKindOfClass:[NSDictionary class]]) {
                        NSString *uri = slURIFromDict((NSDictionary *)item);
                        if (uri) [uris addObject:uri];
                    } else {
                        slCollectNodes(item, uris, depth + 1);
                    }
                }
            }
        }
        NSString *uri = slURIFromDict(d);
        if (uri && ![uris containsObject:uri]) [uris addObject:uri];
    }
}

#pragma mark - 主流程：注册(带邀请码) → 节点

static void slRunFlow(void) {
    slLog(@"===== 闪连自动流程开始 %@ =====", [NSDate date]);

    // 1) 注册（游客注册，密码随机，注册时直接带邀请码）
    NSString *pwd = [NSString stringWithFormat:@"ShanLian%u%u", arc4random() % 9000 + 1000, arc4random() % 9000 + 1000];
    NSDictionary *regBody = @{ @"password": pwd, @"inviteCode": @"88888888" };
    slLog(@"POST /app/tourist/slregister body=%@", regBody);

    slRequest(@"POST", @"/app/tourist/slregister", regBody, nil, ^(NSDictionary *json, NSString *raw, NSError *err) {
        if (err) {
            slLog(@"注册失败 err=%@ raw=%@", err, raw);
            slShowAlert(@"闪连助手", [NSString stringWithFormat:@"注册失败\n%@\n%@", err.localizedDescription, raw.length ? raw : @"(空响应)"]);
            return;
        }
        slLog(@"注册响应: %@", raw);

        NSDictionary *data = nil;
        if ([json isKindOfClass:[NSDictionary class]]) data = json[@"data"];
        if (![data isKindOfClass:[NSDictionary class]]) data = json;

        NSString *token = data[@"token"] ?: data[@"accessToken"] ?: data[@"authToken"] ?: data[@"sessionToken"] ?: data[@"ticket"] ?: json[@"token"] ?: data[@"userToken"];
        if (!token && [data isKindOfClass:[NSDictionary class]]) {
            // 再挖一层
            for (NSString *k in data.allKeys) {
                id v = data[k];
                if ([v isKindOfClass:[NSDictionary class]] && !token) {
                    token = v[@"token"] ?: v[@"accessToken"] ?: v[@"authToken"];
                }
            }
        }
        if (!token) {
            slLog(@"未解析到token，完整响应: %@", raw);
            slShowAlert(@"闪连助手", [NSString stringWithFormat:@"注册返回但未解析到token\n%@", raw.length ? raw : @"(空)"]);
            return;
        }
        slLog(@"token=%@", token);

        // 2) 确认填邀请码（注册已带的话这里可重复，一般幂等）
        slRequest(@"POST", @"/app/customer/slfillInviteCode", @{ @"inviteCode": @"88888888" }, token, ^(NSDictionary *j2, NSString *raw2, NSError *e2) {
            if (e2 || !j2) {
                slLog(@"填邀请码失败 err=%@ raw=%@", e2, raw2);
            } else {
                slLog(@"填邀请码响应: %@", raw2);
            }
            // 3) 拿节点
            slRequest(@"GET", @"/app/customer/slgetNodes", nil, token, ^(NSDictionary *j3, NSString *raw3, NSError *e3) {
                if (e3) {
                    slLog(@"节点请求失败 err=%@", e3);
                    slShowAlert(@"闪连助手", [NSString stringWithFormat:@"节点请求失败\n%@", e3.localizedDescription]);
                    return;
                }
                slLog(@"节点响应: %@", raw3.length > 3000 ? [raw3 substringToIndex:3000] : raw3);

                NSMutableArray *uris = [NSMutableArray array];
                if ([j3 isKindOfClass:[NSDictionary class]] || [j3 isKindOfClass:[NSArray class]]) {
                    slCollectNodes(j3, uris, 0);
                }

                NSString *docDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
                [raw3 writeToFile:[docDir stringByAppendingPathComponent:@"sl_nodes_raw.json"] atomically:YES encoding:NSUTF8StringEncoding error:nil];

                if (uris.count == 0) {
                    slLog(@"未解析到节点，原始数据已存 sl_nodes_raw.json");
                    slShowAlert(@"闪连助手", [NSString stringWithFormat:@"拿到数据但未解析出节点\n原始JSON已存 Documents/sl_nodes_raw.json\n%@", raw3.length ? [raw3 substringToIndex:500] : @"(空)"]);
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
        });
    });
}

__attribute__((constructor)) static void slInit(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
                       slRunFlow();
                   });
}
