//
//  UIDevice+LSUUID.m
//  ddd
//
//  Created by liushuai on 15/2/15.
//  Copyright (c) 2015年 liushuai. All rights reserved.
//

#import "UIDevice+LSUUID.h"
#import "LSKeychainItemWrapper.h"
@implementation UIDevice (LSUUID)
-(NSString *)lsUUID
{
    LSKeychainItemWrapper *keychainItem = [[LSKeychainItemWrapper alloc]
                                         initWithIdentifier:@"UUID"
                                         accessGroup:nil];
    NSString *strUUID = [keychainItem objectForKey:(__bridge id)kSecValueData];
    if ([strUUID isEqualToString:@""])
    {
        CFUUIDRef uuidRef = CFUUIDCreate(kCFAllocatorDefault);
        strUUID = (NSString *)CFBridgingRelease(CFUUIDCreateString (kCFAllocatorDefault,uuidRef));
        [keychainItem setObject:strUUID forKey:(__bridge id)kSecValueData];
        CFAutorelease(uuidRef);
    }
    return strUUID;
}
@end
