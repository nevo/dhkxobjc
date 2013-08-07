Introduction
====================
This is an implementation of components in Objective C for Diffie Hellman Key Exchange algorithm [DH](http://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange). The APIs are pretty much self-explained in code.
The classes are inspired from Go version of [DHKX](monnand/dhkx)

Installation
====================
No installation is required. Open Xcode project and select targets based on your platform (iOS, Mac OSX). The product is a static library. Unit test is included (the implementation is validated using [NIST FCC DH static key validation scheme](http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf)).

How To Use
====================
Well, again, it's pretty simple and all APIs are self-explained in code. You can also look at Unit Test for how to use.

Notes
====================
This library is built on top of openssl, solely because its BN (bignumber) API is easy to use and itself is pretty portable. That means if you want to use other math/crypto API with support of big number math, it will be straight forward to replace all BN calls. [Here](http://stackoverflow.com/questions/1226949/biginteger-on-objective-c) are a couple of options if you're interested.