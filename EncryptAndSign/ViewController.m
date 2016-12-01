//
//  ViewController.m
//  EncryptAndSign
//
//  Created by apple on 16/11/30.
//  Copyright © 2016年 Wang. All rights reserved.
//

#import "ViewController.h"
#import "XYRSACryption.h"
#import "HBRSAHandler.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    // 加载公钥
    XYRSACryption *_rsa = [XYRSACryption new];
    NSString *derPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"rsacert" ofType:@"der"];
    [_rsa loadPublicKeyFromFile:derPath];
    
    // 加载私钥
    NSString *p12Path = [[NSBundle bundleForClass:[self class]] pathForResource:@"p" ofType:@"p12"];
    [_rsa loadPrivateKeyFromFile:p12Path password:@"123456"];
    
    NSString *enStr = @"请替换为你要加密的文本内容！";
    
    // 加密后的数据
    NSData *enData = [_rsa rsaEncryptData:
                      [enStr dataUsingEncoding:NSUTF8StringEncoding]];
    
    // 解密后的数据
    NSData *deData = [_rsa rsaDecryptData:enData];
    NSString *deStr = [[NSString alloc] initWithData:deData encoding:NSUTF8StringEncoding];
    NSLog(@"%@\n%@",enStr,deStr);
    
    //加密后的字符串
    NSString *encryptStr = [_rsa rsaEncryptString:enStr];
    
    //解密后的字符串
    NSString *decryptStr = [_rsa rsaDecryptString:encryptStr];
    
    NSLog(@"%@\n%@",encryptStr,decryptStr);
    
    
    // 签名
    NSData *signedData = [_rsa sha256WithRSA:enData];
    
    // 对前面进行验证
    BOOL result = [_rsa rsaSHA256VertifyingData:enData withSignature:signedData];
    NSLog(@"%@",result?@"YES":@"NO");
    


    NSString *publicKeyFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_public_key.pem" ofType:nil];
    
    NSString *privateKeyFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_private_key.pem" ofType:nil];
    
    HBRSAHandler* handler = [HBRSAHandler new];
    [handler importKeyWithType:KeyTypePublic andPath:publicKeyFilePath];
    [handler importKeyWithType:KeyTypePrivate andPath:privateKeyFilePath];
    NSString* sig = [handler signString:@"wangfeng"];
    NSString* sigMd5 = [handler signMD5String:@"wangfeng"];
    NSLog(@"%@      %@",sig,sigMd5);
    
    BOOL isMatch = [handler verifyString:@"wangfeng" withSign:sig];
    BOOL isMatchMd5 = [handler verifyMD5String:@"wangfeng" withSign:sigMd5];
    
    NSLog(@"%d      %d",isMatch,isMatchMd5);
    
    NSString* enString = [handler encryptWithPublicKey:@"wangfeng"];
    NSString* deString = [handler decryptWithPrivatecKey:enString];
    NSLog(@"%@",deString);

    
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
