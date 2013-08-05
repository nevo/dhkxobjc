/*
 * Copyright 2013 Xueliang Hua (sakur.deagod@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#import "DHKey.h"


@interface DHKey ()


@property(nonatomic, retain) DHGroup *group;


- (void)generateKey;
- (int)generatePublicKey:(BIGNUM *)pubKey
           forPrivateKey:(BIGNUM *)privKey;
- (NSData *)keyToData:(BIGNUM *)key;
- (void)resetKey;


@end


@implementation DHKey


@synthesize group;


- (id)initWithDHGroup:(DHGroup *)aGroup
{
    if ((self = [super init])) {
        self.group = aGroup;
        [self generateKey];
    }
    return self;
}


- (void)dealloc
{
    [self resetKey];
    self.group = nil;
    [super dealloc];
}


- (void)resetKey
{
    if (x) {
        BN_free(x);
        x = NULL;
    }
    if (y) {
        BN_free(y);
        y = NULL;
    }
}


- (int)generatePublicKey:(BIGNUM *)pubKey
           forPrivateKey:(BIGNUM *)privKey
{
    int ret;
    BN_CTX *ctx = BN_CTX_new();
    ret = BN_mod_exp(pubKey, self.group.g, privKey, self.group.p, ctx);
    BN_CTX_free(ctx);
    return ret;
}


- (void)generateKey
{
    int ret;

    x = BN_new();
    y = BN_new();

    // Generate DH private key
    do {
        /*
         * x should usually be in range (0, group.p).
         *
         * ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-3.asc
         *
         * There's a detailed discussion over this value:
         *   http://crypto.stackexchange.com/questions/1975/what-should-be-the-size-of-a-diffie-hellman-private-key
         *
         * An alternative way to ensure the range is:
         *   ret = 1 + RAND(x, self.group.p - 1)
         * But using loop is more time efficiently. See "GeneratePrivateKey" in:
         *    https://github.com/monnand/dhkx/blob/master/dhgroup.go
         */
        ret = BN_rand_range(x, self.group.p);
        if (ret == 0) {
            NSLog(@"Error: Failed to generate key");
            break;
        }
    } while (BN_is_zero(x));

    if (ret) {
        ret = [self generatePublicKey:y
                        forPrivateKey:x];
    }

    if (ret == 0) {
        [self resetKey];
    }
}


- (NSData *)keyToData:(BIGNUM *)key
{
    if (!key) {
        return nil;
    }

    NSData *data = nil;
    unsigned char *buf = malloc(BN_num_bytes(key));
    int ret = BN_bn2bin(key, buf);
    if (ret > 0) {
        data = [NSData dataWithBytes:buf
                              length:BN_num_bytes(key)];
    }
    free(buf);
    return data;
}


- (NSData *)publicKey
{
    return [self keyToData:y];
}


- (NSData *)computeSecretWithPublicKey:(NSData *)pubKey
{
    BIGNUM *pub = BN_bin2bn([pubKey bytes], [pubKey length], NULL);
    if (!pub) {
        return nil;
    }

    NSData *data = nil;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *k = BN_new();

    int ret = BN_mod_exp(k, pub, x, self.group.p, ctx);
    if (ret) {
        data = [self keyToData:k];
    }
    BN_CTX_free(ctx);
    BN_free(k);
    BN_free(pub);
    return data;
}


@end
