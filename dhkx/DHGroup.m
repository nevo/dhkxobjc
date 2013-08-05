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

#import "DHGroup.h"

/*
 * DH Group for Diffie Hellman Key Exchange Method
 *
 * The DH groups are defined according to RFC 2409/3526
 *
 * This implementation is an ObjC port of:
 *   https://github.com/monnand/dhkx
 */


@interface DHGroup ()
- (id)initWithPrime:(BIGNUM *)aPrime
          generator:(BIGNUM *)aGenerator;
@end


@implementation DHGroup


@synthesize g;
@synthesize p;


- (id)init
{
    if ((self = [super init])) {
    }
    return self;
}


- (id)initWithPrime:(BIGNUM *)aPrime
          generator:(BIGNUM *)aGenerator
{
    if ((self = [super init])) {
        p = BN_dup(aPrime);
        g = BN_dup(aGenerator);
    }
    return self;
}


- (void)dealloc
{
    if (p) {
        BN_free(p);
    }
    if (g) {
        BN_free(g);
    }
    [super dealloc];
}


+ (DHGroup *)groupWithPrime:(BIGNUM *)p
                   generate:(BIGNUM *)g
{
    DHGroup *group = [[DHGroup alloc] initWithPrime:p
                                          generator:g];
    return [group autorelease];
}


+ (DHGroup *)groupWithGroupId:(int)groupId
{
    if (groupId <= 0) {
        groupId = 14;
    }

    BIGNUM *lP = BN_new();
    BIGNUM *lG = BN_new();

    switch (groupId) {
        case 1:
            BN_hex2bn(&lP, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF");
            BN_set_word(lG, 2);
            break;
        case 2:
            BN_hex2bn(&lP, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF");
            BN_set_word(lG, 2);
            break;
        case 14:
            BN_hex2bn(&lP, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF");
            BN_set_word(lG, 2);
            break;
        default:
            NSLog(@"Error: Unknown group");
            return nil;
    }

    DHGroup *group = [[DHGroup alloc] initWithPrime:lP
                                          generator:lG];
    BN_free(lP);
    BN_free(lG);
    return [group autorelease];
}


@end
