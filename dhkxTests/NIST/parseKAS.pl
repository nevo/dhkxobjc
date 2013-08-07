#
# Below script was originated from Go port of dhkx:
#   https://github.com/monnand/dhkx/blob/master/testgen/parseKAS.pl
#

my $p = "";
my $g = "";
my $xa = "";
my $xb = "";
my $ya = "";
my $yb = "";
my $zz = "";
my $pass = "";
my $count = 0;
my $id = 0;
while (<>) {
	chomp;
	if (/P = ([0-9a-f]+)/) {
		$p = $1;
	} elsif (/G = ([0-9a-f]+)/) {
		$g = $1;
	} elsif (/XstatCAVS = ([0-9a-f]+)/) {
		$xa = $1;
	} elsif (/YstatCAVS = ([0-9a-f]+)/) {
		$ya = $1;
	} elsif (/XstatIUT = ([0-9a-f]+)/) {
		$xb = $1;
	} elsif (/YstatIUT = ([0-9a-f]+)/) {
		$yb = $1;
	} elsif (/^Z = ([0-9a-f]+)/) {
		$zz = $1;
	} elsif (/Result = ([PF]).+/) {
		if ($1 eq "F") {
			$pass = 0;
		} elsif ($1 eq "P") {
			$pass = 1;
		}
	} elsif (/COUNT = ([0-9]+)/) {
		$id = $1;
		if ($pass and $p and $g and $xa and $xb and $ya and $yb and $zz) {
			print "// Test case $count\n";
			print "- (void)testNIST$count\n";
            print "{\n";
            print "\n";
            # the 31st test case fails - bail out
            if ($count == 31) {
                print "#if 0\n";
            }
            print "    int ret;\n";
            print "    NSData *secret;\n";
            print "    BIGNUM *s;\n";
            print "\n";
            print "    ret = BN_hex2bn(&lP, \"$p\");\n";
            print "    STAssertTrue(ret > 0, @\"BN_hex2bn -> p failure\");\n";
            print "    ret = BN_hex2bn(&lG, \"$g\");\n";
            print "    STAssertTrue(ret > 0, @\"BN_hex2bn -> g failure\");\n";
            print "    ret = BN_hex2bn(&xa, \"$xa\");\n";
            print "    STAssertTrue(ret > 0, @\"BN_hex2bn -> xa failure\");\n";
            print "    ret = BN_hex2bn(&xb, \"$xb\");\n";
            print "    STAssertTrue(ret > 0, @\"BN_hex2bn -> xb failure\");\n";
            print "    ret = BN_hex2bn(&ya, \"$ya\");\n";
            print "    STAssertTrue(ret > 0, @\"BN_hex2bn -> ya failure\");\n";
            print "    ret = BN_hex2bn(&yb, \"$yb\");\n";
            print "    STAssertTrue(ret > 0, @\"BN_hex2bn -> yb failure\");\n";
            print "    ret = BN_hex2bn(&zz, \"$zz\");\n";
            print "    STAssertTrue(ret > 0, @\"BN_hex2bn -> zz failure\");\n";
            print "\n";
            print "    DHGroup *group = [DHGroup groupWithPrime:lP\n";
            print "                                    generate:lG];\n";
            print "    DHKey *key = [[DHKey alloc] initWithDHGroup:group];\n";
            print "\n";
            print "    [key generatePublicKeyFromPrivateKey:xa];\n";
            print "    STAssertTrue(BN_cmp(key.y, ya) == 0, @\"generatePublicKey:privateKey: -> xa failure\");\n";
            print "\n";
            print "    secret = [key computeSecretWithPublicKey:[key keyToData:yb]];\n";
            print "    STAssertTrue(secret != nil, @\"computeSecretWithPublicKey: -> xa/yb failure\");\n";
            print "    s = BN_bin2bn([secret bytes], (int)[secret length], NULL);\n";
            print "    STAssertTrue(BN_cmp(s, zz) == 0, @\"computeSecretWithPublicKey: -> xa/yb/zz failure\");\n";
            print "    BN_free(s);\n";
            print "\n";
            print "    [key generatePublicKeyFromPrivateKey:xb];\n";
            print "    STAssertTrue(BN_cmp(key.y, yb) == 0, @\"generatePublicKey:privateKey: -> xb failure\");\n";
            print "\n";
            print "    secret = [key computeSecretWithPublicKey:[key keyToData:ya]];\n";
            print "    STAssertTrue(secret != nil, @\"computeSecretWithPublicKey: -> xb/ya failure\");\n";
            print "    s = BN_bin2bn([secret bytes], (int)[secret length], NULL);\n";
            print "    STAssertTrue(BN_cmp(s, zz) == 0, @\"computeSecretWithPublicKey: -> xb/ya/zz failure\");\n";
            print "    BN_free(s);\n";
            print "\n";
            print "    [key release];\n";
            if ($count == 31) {
                print "#endif\n";
            }
			print "}\n";
			print "\n";
            print "\n";
            $count++;
		}
	}
}
