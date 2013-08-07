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

#import "dhkxTests.h"


@interface DHKey (UnitTestExport)


@property(nonatomic, retain) DHGroup *group;


- (NSData *)keyToData:(BIGNUM *)key;
- (int)generatePublicKey:(BIGNUM *)pubKey
           forPrivateKey:(BIGNUM *)privKey;
- (void)resetKey;


@end


@interface DHKey (UnitTest)


@property(nonatomic, readonly) BIGNUM *x;
@property(nonatomic, readonly) BIGNUM *y;


- (int)generatePublicKeyFromPrivateKey:(BIGNUM *)privKey;


@end

@implementation DHKey (UnitTest)


- (BIGNUM *)x
{
    return x;
}


- (BIGNUM *)y
{
    return y;
}


- (int)generatePublicKeyFromPrivateKey:(BIGNUM *)privKey
{
    [self resetKey];

    x = BN_dup(privKey);
    y = BN_new();

    return [self generatePublicKey:y
                     forPrivateKey:x];
}


@end


@implementation dhkxTests


- (void)setUp
{
    [super setUp];

    lP = BN_new();
    lG = BN_new();
    xa = BN_new();
    xb = BN_new();
    ya = BN_new();
    yb = BN_new();
    zz = BN_new();
}


- (void)tearDown
{
    BN_free(lP);
    BN_free(lG);
    BN_free(xa);
    BN_free(xb);
    BN_free(ya);
    BN_free(yb);
    BN_free(zz);

    [super tearDown];
}


/*
 * Test Subject:
 *   DH Key Exchange Algorithm
 */

- (void)testKeyExchange1
{
    DHGroup *group = [DHGroup groupWithGroupId:DHGROUP_FOURTEEN];
    STAssertTrue(group.p != NULL, @"A safe prime is required");
    STAssertTrue(group.g != NULL, @"A generator is required");

    DHKey *p1 = [[DHKey alloc] initWithDHGroup:group];
    STAssertTrue(p1.publicKey != nil, @"p1 has nil DH pub key");
    DHKey *p2 = [[DHKey alloc] initWithDHGroup:group];
    STAssertTrue(p2.publicKey != nil, @"p2 has nil DH pub key");

    NSData *s1 = [p1 computeSecretWithPublicKey:p2.publicKey];
    STAssertTrue(s1 != nil, @"p1 failed to compute shared secret");
    NSData *s2 = [p2 computeSecretWithPublicKey:p1.publicKey];
    STAssertTrue(s2 != nil, @"p2 failed to compute shared secret");

    STAssertTrue([s1 isEqualToData:s2], @"s1 and s2 are not equal");

    [p1 release];
    [p2 release];
}


- (void)testKeyExchange2
{
    int ret;
    ret = BN_hex2bn(&lP, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563");
    STAssertTrue(ret > 0, @"BN_hex2bn -> p failure");
    ret = BN_set_word(lG, 2);
    STAssertTrue(ret > 0, @"BN_set_word -> g failure");

    DHGroup *group = [DHGroup groupWithPrime:lP
                                    generate:lG];
    
    DHKey *p1 = [[DHKey alloc] initWithDHGroup:group];
    STAssertTrue(p1.publicKey != nil, @"p1 has nil DH pub key");
    DHKey *p2 = [[DHKey alloc] initWithDHGroup:group];
    STAssertTrue(p2.publicKey != nil, @"p2 has nil DH pub key");
    
    NSData *s1 = [p1 computeSecretWithPublicKey:p2.publicKey];
    STAssertTrue(s1 != nil, @"p1 failed to compute shared secret");
    NSData *s2 = [p2 computeSecretWithPublicKey:p1.publicKey];
    STAssertTrue(s2 != nil, @"p2 failed to compute shared secret");
    
    STAssertTrue([s1 isEqualToData:s2], @"s1 and s2 are not equal");
    
    [p1 release];
    [p2 release];
}


/*
 * Test Subject:
 *   NIST FCC DH static key validation scheme
 *
 * The test vector is from:
 *   http://csrc.nist.gov/groups/STM/cavp/documents/keymgmt/kastestvectors.zip
 *
 * The related doc is:
 *   http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf
 */

// The testKAS.inc will be generated via parseKAS.pl
#include "NIST/testKAS.inc"


@end
