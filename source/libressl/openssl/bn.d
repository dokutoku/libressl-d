/* $OpenBSD: bn.h,v 1.57 2022/12/17 15:56:25 jsing Exp $ */
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the Eric Young open source
 * license provided above.
 *
 * The binary polynomial arithmetic software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */
module libressl.openssl.bn;


private static import core.stdc.config;
public import libressl.compat.stdio;
public import libressl.compat.stdlib;
public import libressl.openssl.bio;
public import libressl.openssl.crypto;
public import libressl.openssl.opensslconf;
public import libressl.openssl.ossl_typ;

enum HEADER_BN_H = true;

extern (C):
nothrow @nogc:

version (LIBRESSL_INTERNAL) {
	version = LIBRESSL_INTERNAL_OR_LIBRESSL_NEXT_API;
} else version (LIBRESSL_NEXT_API) {
	version = LIBRESSL_INTERNAL_OR_LIBRESSL_NEXT_API;
}

version (OPENSSL_SMALL_FOOTPRINT) {
} else {
	//#define BN_MUL_COMBA
	//#define BN_SQR_COMBA
	//#define BN_RECURSION
}

/*
 * This next option uses the C libraries (2 word)/(1 word) function.
 * If it is not defined, I use my C version (which is slower).
 * The reason for this flag is that when the particular C compiler
 * library routine is used, and the library is linked with a different
 * compiler, the library is missing.  This mostly happens when the
 * library is built with gcc and then linked using normal cc.  This would
 * be a common occurrence because gcc normally produces code that is
 * 2 times faster than system compilers for the big number stuff.
 * For machines with only one compiler (or shared libraries), this should
 * be on.  Again this in only really a problem on machines
 * using "long long's", are 32bit, and are not using my assembler code.
 */
/* version = BN_DIV2W; */

//ToDo:
version (Windows) {
} else {
	version (D_LP64) {
		version = C_LP64;
	}
}

//#if defined(_LP64)
version (C_LP64) {
	//#undef BN_LLONG
	alias BN_ULONG = core.stdc.config.c_ulong;
	alias BN_LONG = core.stdc.config.c_long;
	enum BN_BITS = 128;
	enum BN_BYTES = 8;
	enum BN_BITS2 = 64;
	enum BN_BITS4 = 32;
	enum BN_MASK2 = 0xFFFFFFFFFFFFFFFFL;
	enum BN_MASK2l = 0xFFFFFFFFL;
	enum BN_MASK2h = 0xFFFFFFFF00000000L;
	enum BN_MASK2h1 = 0xFFFFFFFF80000000L;
	enum BN_TBIT = 0x8000000000000000L;
	enum BN_DEC_CONV = 10000000000000000000UL;
	enum BN_DEC_FMT1 = "%lu";
	enum BN_DEC_FMT2 = "%019lu";
	enum BN_DEC_NUM = 19;
	enum BN_HEX_FMT1 = "%lX";
	enum BN_HEX_FMT2 = "%016lX";
} else {
	alias BN_ULLONG = core.stdc.config.cpp_ulonglong;
	//#define BN_LLONG
	alias BN_ULONG = uint;
	alias BN_LONG = int;
	enum BN_BITS = 64;
	enum BN_BYTES = 4;
	enum BN_BITS2 = 32;
	enum BN_BITS4 = 16;
	enum BN_MASK = 0xFFFFFFFFFFFFFFFFL;
	enum BN_MASK2 = 0xFFFFFFFFL;
	enum BN_MASK2l = 0xFFFF;
	enum BN_MASK2h1 = 0xFFFF8000L;
	enum BN_MASK2h = 0xFFFF0000L;
	enum BN_TBIT = 0x80000000L;
	enum BN_DEC_CONV = 1000000000L;
	enum BN_DEC_FMT1 = "%u";
	enum BN_DEC_FMT2 = "%09u";
	enum BN_DEC_NUM = 9;
	enum BN_HEX_FMT1 = "%X";
	enum BN_HEX_FMT2 = "%08X";
}

enum BN_FLG_MALLOCED = 0x01;
enum BN_FLG_STATIC_DATA = 0x02;

/**
 * avoid leaking exponent information through timing,
 * BN_mod_exp_mont() will call BN_mod_exp_mont_consttime,
 * BN_div() will call BN_div_no_branch,
 * BN_mod_inverse() will call BN_mod_inverse_no_branch.
 */
enum BN_FLG_CONSTTIME = 0x04;

version (OPENSSL_NO_DEPRECATED) {
} else {
	/**
	 * deprecated name for the flag
	 */
	enum BN_FLG_EXP_CONSTTIME = .BN_FLG_CONSTTIME;

	/*
	 * avoid leaking exponent information through timings
	 * (BN_mod_exp_mont() will call BN_mod_exp_mont_consttime)
	 */
}

version (OPENSSL_NO_DEPRECATED) {
} else {
	/**
	 * used for debugging
	 */
	enum BN_FLG_FREE = 0x8000;
}

void BN_set_flags(libressl.openssl.ossl_typ.BIGNUM* b, int n);
int BN_get_flags(const (libressl.openssl.ossl_typ.BIGNUM)* b, int n);
void BN_with_flags(libressl.openssl.ossl_typ.BIGNUM* dest, const (libressl.openssl.ossl_typ.BIGNUM)* src, int flags);

/**
 * Values for |top| in BN_rand()
 */
enum BN_RAND_TOP_ANY = -1;

///Ditto
enum BN_RAND_TOP_ONE = 0;

///Ditto
enum BN_RAND_TOP_TWO = 1;

/**
 * Values for |bottom| in BN_rand()
 */
enum BN_RAND_BOTTOM_ANY = 0;

///Ditto
enum BN_RAND_BOTTOM_ODD = 1;

libressl.openssl.ossl_typ.BN_GENCB* BN_GENCB_new();
void BN_GENCB_free(libressl.openssl.ossl_typ.BN_GENCB* cb);

/**
 * Wrapper function to make using BN_GENCB easier,
 */
int BN_GENCB_call(libressl.openssl.ossl_typ.BN_GENCB* cb, int a, int b);

/**
 * Populate a BN_GENCB structure with an "old"-style callback
 */
void BN_GENCB_set_old(libressl.openssl.ossl_typ.BN_GENCB* gencb, void function(int, int, void*) nothrow @nogc callback, void* cb_arg);

/**
 * Populate a BN_GENCB structure with a "new"-style callback
 */
void BN_GENCB_set(libressl.openssl.ossl_typ.BN_GENCB* gencb, int function(int, int, libressl.openssl.ossl_typ.BN_GENCB*) nothrow @nogc callback, void* cb_arg);

void* BN_GENCB_get_arg(libressl.openssl.ossl_typ.BN_GENCB* cb);

/**
 * default: select number of iterations
 * based on the size of the number
 */
enum BN_prime_checks = 0;

/*
 * BN_prime_checks_for_size() returns the number of Miller-Rabin
 * iterations that will be done for checking that a random number
 * is probably prime.  The error rate for accepting a composite
 * number as prime depends on the size of the prime |b|.  The error
 * rates used are for calculating an RSA key with 2 primes, and so
 * the level is what you would expect for a key of double the size
 * of the prime.
 *
 * This table is generated using the algorithm of FIPS PUB 186-4
 * Digital Signature Standard (DSS), section F.1, page 117.
 * (https://dx.doi.org/10.6028/NIST.FIPS.186-4)
 *
 * The following magma script was used to generate the output:
 * securitybits:=125;
 * k:=1024;
 * for t:=1 to 65 do
 *   for M:=3 to Floor(2*Sqrt(k-1)-1) do
 *     S:=0;
 *     // Sum over m
 *     for m:=3 to M do
 *       s:=0;
 *       // Sum over j
 *       for j:=2 to m do
 *         s+:=(RealField(32)!2)^-(j+(k-1)/j);
 *       end for;
 *       S+:=2^(m-(m-1)*t)*s;
 *     end for;
 *     A:=2^(k-2-M*t);
 *     B:=8*(Pi(RealField(32))^2-6)/3*2^(k-2)*S;
 *     pkt:=2.00743*Log(2)*k*2^-k*(A+B);
 *     seclevel:=Floor(-Log(2,pkt));
 *     if seclevel ge securitybits then
 *       printf "k: %5o, security: %o bits  (t: %o, M: %o)\n",k,seclevel,t,M;
 *       break;
 *     end if;
 *   end for;
 *   if seclevel ge securitybits then break; end if;
 * end for;
 *
 * It can be run online at:
 * http://magma.maths.usyd.edu.au/calc
 *
 * And will output:
 * k:  1024, security: 129 bits  (t: 6, M: 23)
 *
 * k is the number of bits of the prime, securitybits is the level
 * we want to reach.
 *
 * prime length | RSA key size | # MR tests | security level
 * -------------+--------------|------------+---------------
 *  (b) >= 6394 |     >= 12788 |          3 |        256 bit
 *  (b) >= 3747 |     >=  7494 |          3 |        192 bit
 *  (b) >= 1345 |     >=  2690 |          4 |        128 bit
 *  (b) >= 1080 |     >=  2160 |          5 |        128 bit
 *  (b) >=  852 |     >=  1704 |          5 |        112 bit
 *  (b) >=  476 |     >=   952 |          5 |         80 bit
 *  (b) >=  400 |     >=   800 |          6 |         80 bit
 *  (b) >=  347 |     >=   694 |          7 |         80 bit
 *  (b) >=  308 |     >=   616 |          8 |         80 bit
 *  (b) >=   55 |     >=   110 |         27 |         64 bit
 *  (b) >=    6 |     >=    12 |         34 |         64 bit
 */

pragma(inline, true)
pure nothrow @safe @nogc @live
int BN_prime_checks_for_size(B)(B b)
	if (B.max > 3747)

	do
	{
		return (b >= 3747) ? (3) : (b >= 1345) ? (4) : (b >= 476) ? (5) : (b >= 400) ? (6) : (b >= 347) ? (7) : (b >= 308) ? (8) : (b >= 55) ? (27) : (/* b >= 6 */ 34);
	}

pragma(inline, true)
int BN_num_bytes(const (libressl.openssl.ossl_typ.BIGNUM)* a)

	do
	{
		return (.BN_num_bits(a) + 7) / 8;
	}

int BN_abs_is_word(const (libressl.openssl.ossl_typ.BIGNUM)* a, const .BN_ULONG w);
int BN_is_zero(const (libressl.openssl.ossl_typ.BIGNUM)* a);
int BN_is_one(const (libressl.openssl.ossl_typ.BIGNUM)* a);
int BN_is_word(const (libressl.openssl.ossl_typ.BIGNUM)* a, const .BN_ULONG w);
int BN_is_odd(const (libressl.openssl.ossl_typ.BIGNUM)* a);

version (LIBRESSL_INTERNAL_OR_LIBRESSL_NEXT_API) {
	void BN_zero(libressl.openssl.ossl_typ.BIGNUM* a);
	int BN_one(libressl.openssl.ossl_typ.BIGNUM* a);
} else {
	pragma(inline, true)
	int BN_one(libressl.openssl.ossl_typ.BIGNUM* a)

		do
		{
			return .BN_set_word(a, 1);
		}

	void BN_zero_ex(libressl.openssl.ossl_typ.BIGNUM* a);

	version (OPENSSL_NO_DEPRECATED) {
		pragma(inline, true)
		void BN_zero(libressl.openssl.ossl_typ.BIGNUM* a)
			do
			{
				.BN_zero_ex(a);
			}
	} else {
		pragma(inline, true)
		int BN_zero(libressl.openssl.ossl_typ.BIGNUM* a)

			do
			{
				return .BN_set_word(a, 0);
			}
	}
}

const (libressl.openssl.ossl_typ.BIGNUM)* BN_value_one();
char* BN_options();
libressl.openssl.ossl_typ.BN_CTX* BN_CTX_new();

version (OPENSSL_NO_DEPRECATED) {
} else {
	void BN_CTX_init(libressl.openssl.ossl_typ.BN_CTX* c);
}

void BN_CTX_free(libressl.openssl.ossl_typ.BN_CTX* c);
void BN_CTX_start(libressl.openssl.ossl_typ.BN_CTX* ctx);
libressl.openssl.ossl_typ.BIGNUM* BN_CTX_get(libressl.openssl.ossl_typ.BN_CTX* ctx);
void BN_CTX_end(libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_rand(libressl.openssl.ossl_typ.BIGNUM* rnd, int bits, int top, int bottom);
int BN_pseudo_rand(libressl.openssl.ossl_typ.BIGNUM* rnd, int bits, int top, int bottom);
int BN_rand_range(libressl.openssl.ossl_typ.BIGNUM* rnd, const (libressl.openssl.ossl_typ.BIGNUM)* range);
int BN_pseudo_rand_range(libressl.openssl.ossl_typ.BIGNUM* rnd, const (libressl.openssl.ossl_typ.BIGNUM)* range);
int BN_num_bits(const (libressl.openssl.ossl_typ.BIGNUM)* a);
int BN_num_bits_word(.BN_ULONG);
libressl.openssl.ossl_typ.BIGNUM* BN_new();
void BN_init(libressl.openssl.ossl_typ.BIGNUM*);
void BN_clear_free(libressl.openssl.ossl_typ.BIGNUM* a);
libressl.openssl.ossl_typ.BIGNUM* BN_copy(libressl.openssl.ossl_typ.BIGNUM* a, const (libressl.openssl.ossl_typ.BIGNUM)* b);
void BN_swap(libressl.openssl.ossl_typ.BIGNUM* a, libressl.openssl.ossl_typ.BIGNUM* b);
libressl.openssl.ossl_typ.BIGNUM* BN_bin2bn(const (ubyte)* s, int len, libressl.openssl.ossl_typ.BIGNUM* ret);
int BN_bn2bin(const (libressl.openssl.ossl_typ.BIGNUM)* a, ubyte* to);
int BN_bn2binpad(const (libressl.openssl.ossl_typ.BIGNUM)* a, ubyte* to, int tolen);
libressl.openssl.ossl_typ.BIGNUM* BN_lebin2bn(const (ubyte)* s, int len, libressl.openssl.ossl_typ.BIGNUM* ret);
int BN_bn2lebinpad(const (libressl.openssl.ossl_typ.BIGNUM)* a, ubyte* to, int tolen);
libressl.openssl.ossl_typ.BIGNUM* BN_mpi2bn(const (ubyte)* s, int len, libressl.openssl.ossl_typ.BIGNUM* ret);
int BN_bn2mpi(const (libressl.openssl.ossl_typ.BIGNUM)* a, ubyte* to);
int BN_sub(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b);
int BN_usub(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b);
int BN_uadd(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b);
int BN_add(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b);
int BN_mul(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_sqr(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, libressl.openssl.ossl_typ.BN_CTX* ctx);

/**
 * sets sign of a BIGNUM
 *
 * Params:
 *      b = pointer to the BIGNUM object
 *      n = 0 if the BIGNUM b should be positive and a value != 0 otherwise
 */
void BN_set_negative(libressl.openssl.ossl_typ.BIGNUM* b, int n);

int BN_is_negative(const (libressl.openssl.ossl_typ.BIGNUM)* b);

version (LIBRESSL_INTERNAL) {
} else {
	int BN_div(libressl.openssl.ossl_typ.BIGNUM* dv, libressl.openssl.ossl_typ.BIGNUM* rem, const (libressl.openssl.ossl_typ.BIGNUM)* m, const (libressl.openssl.ossl_typ.BIGNUM)* d, libressl.openssl.ossl_typ.BN_CTX* ctx);

	pragma(inline, true)
	int BN_mod(libressl.openssl.ossl_typ.BIGNUM* rem, const (libressl.openssl.ossl_typ.BIGNUM)* m, const (libressl.openssl.ossl_typ.BIGNUM)* d, libressl.openssl.ossl_typ.BN_CTX* ctx)

		do
		{
			return .BN_div(null, rem, m, d, ctx);
		}
}

int BN_nnmod(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* m, const (libressl.openssl.ossl_typ.BIGNUM)* d, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_mod_add(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b, const (libressl.openssl.ossl_typ.BIGNUM)* m, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_mod_add_quick(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b, const (libressl.openssl.ossl_typ.BIGNUM)* m);
int BN_mod_sub(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b, const (libressl.openssl.ossl_typ.BIGNUM)* m, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_mod_sub_quick(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b, const (libressl.openssl.ossl_typ.BIGNUM)* m);
int BN_mod_mul(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b, const (libressl.openssl.ossl_typ.BIGNUM)* m, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_mod_sqr(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* m, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_mod_lshift1(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* m, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_mod_lshift1_quick(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* m);
int BN_mod_lshift(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, int n, const (libressl.openssl.ossl_typ.BIGNUM)* m, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_mod_lshift_quick(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, int n, const (libressl.openssl.ossl_typ.BIGNUM)* m);

.BN_ULONG BN_mod_word(const (libressl.openssl.ossl_typ.BIGNUM)* a, .BN_ULONG w);
.BN_ULONG BN_div_word(libressl.openssl.ossl_typ.BIGNUM* a, .BN_ULONG w);
int BN_mul_word(libressl.openssl.ossl_typ.BIGNUM* a, .BN_ULONG w);
int BN_add_word(libressl.openssl.ossl_typ.BIGNUM* a, .BN_ULONG w);
int BN_sub_word(libressl.openssl.ossl_typ.BIGNUM* a, .BN_ULONG w);
int BN_set_word(libressl.openssl.ossl_typ.BIGNUM* a, .BN_ULONG w);
.BN_ULONG BN_get_word(const (libressl.openssl.ossl_typ.BIGNUM)* a);

int BN_cmp(const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b);
void BN_free(libressl.openssl.ossl_typ.BIGNUM* a);
int BN_is_bit_set(const (libressl.openssl.ossl_typ.BIGNUM)* a, int n);
int BN_lshift(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, int n);
int BN_lshift1(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a);
int BN_exp(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

version (LIBRESSL_INTERNAL) {
} else {
	int BN_mod_exp(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p, const (libressl.openssl.ossl_typ.BIGNUM)* m, libressl.openssl.ossl_typ.BN_CTX* ctx);
	int BN_mod_exp_mont(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p, const (libressl.openssl.ossl_typ.BIGNUM)* m, libressl.openssl.ossl_typ.BN_CTX* ctx, libressl.openssl.ossl_typ.BN_MONT_CTX* m_ctx);
}

int BN_mod_exp_mont_consttime(libressl.openssl.ossl_typ.BIGNUM* rr, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p, const (libressl.openssl.ossl_typ.BIGNUM)* m, libressl.openssl.ossl_typ.BN_CTX* ctx, libressl.openssl.ossl_typ.BN_MONT_CTX* in_mont);
int BN_mod_exp_mont_word(libressl.openssl.ossl_typ.BIGNUM* r, .BN_ULONG a, const (libressl.openssl.ossl_typ.BIGNUM)* p, const (libressl.openssl.ossl_typ.BIGNUM)* m, libressl.openssl.ossl_typ.BN_CTX* ctx, libressl.openssl.ossl_typ.BN_MONT_CTX* m_ctx);
int BN_mod_exp2_mont(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a1, const (libressl.openssl.ossl_typ.BIGNUM)* p1, const (libressl.openssl.ossl_typ.BIGNUM)* a2, const (libressl.openssl.ossl_typ.BIGNUM)* p2, const (libressl.openssl.ossl_typ.BIGNUM)* m, libressl.openssl.ossl_typ.BN_CTX* ctx, libressl.openssl.ossl_typ.BN_MONT_CTX* m_ctx);
int BN_mod_exp_simple(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p, const (libressl.openssl.ossl_typ.BIGNUM)* m, libressl.openssl.ossl_typ.BN_CTX* ctx);

int BN_mask_bits(libressl.openssl.ossl_typ.BIGNUM* a, int n);
int BN_print_fp(libressl.compat.stdio.FILE* fp, const (libressl.openssl.ossl_typ.BIGNUM)* a);
int BN_print(libressl.openssl.ossl_typ.BIO* fp, const (libressl.openssl.ossl_typ.BIGNUM)* a);
int BN_reciprocal(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* m, int len, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_rshift(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, int n);
int BN_rshift1(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a);
void BN_clear(libressl.openssl.ossl_typ.BIGNUM* a);
libressl.openssl.ossl_typ.BIGNUM* BN_dup(const (libressl.openssl.ossl_typ.BIGNUM)* a);
int BN_ucmp(const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b);
int BN_set_bit(libressl.openssl.ossl_typ.BIGNUM* a, int n);
int BN_clear_bit(libressl.openssl.ossl_typ.BIGNUM* a, int n);
char* BN_bn2hex(const (libressl.openssl.ossl_typ.BIGNUM)* a);
char* BN_bn2dec(const (libressl.openssl.ossl_typ.BIGNUM)* a);
int BN_hex2bn(libressl.openssl.ossl_typ.BIGNUM** a, const (char)* str);
int BN_dec2bn(libressl.openssl.ossl_typ.BIGNUM** a, const (char)* str);
int BN_asc2bn(libressl.openssl.ossl_typ.BIGNUM** a, const (char)* str);

version (LIBRESSL_INTERNAL) {
} else {
	int BN_gcd(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b, libressl.openssl.ossl_typ.BN_CTX* ctx);
}

/**
 * returns -2 for error
 */
int BN_kronecker(const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b, libressl.openssl.ossl_typ.BN_CTX* ctx);

version (LIBRESSL_INTERNAL) {
} else {
	libressl.openssl.ossl_typ.BIGNUM* BN_mod_inverse(libressl.openssl.ossl_typ.BIGNUM* ret, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* n, libressl.openssl.ossl_typ.BN_CTX* ctx);
}

libressl.openssl.ossl_typ.BIGNUM* BN_mod_sqrt(libressl.openssl.ossl_typ.BIGNUM* ret, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* n, libressl.openssl.ossl_typ.BN_CTX* ctx);

void BN_consttime_swap(.BN_ULONG swap, libressl.openssl.ossl_typ.BIGNUM* a, libressl.openssl.ossl_typ.BIGNUM* b, int nwords);

int BN_security_bits(int L, int N);

/* Deprecated versions */
version (OPENSSL_NO_DEPRECATED) {
} else {
	libressl.openssl.ossl_typ.BIGNUM* BN_generate_prime(libressl.openssl.ossl_typ.BIGNUM* ret, int bits, int safe, const (libressl.openssl.ossl_typ.BIGNUM)* add, const (libressl.openssl.ossl_typ.BIGNUM)* rem, void function(int, int, void*) nothrow @nogc callback, void* cb_arg);
	int BN_is_prime(const (libressl.openssl.ossl_typ.BIGNUM)* p, int nchecks, void function(int, int, void*) nothrow @nogc callback, libressl.openssl.ossl_typ.BN_CTX* ctx, void* cb_arg);
	int BN_is_prime_fasttest(const (libressl.openssl.ossl_typ.BIGNUM)* p, int nchecks, void function(int, int, void*) nothrow @nogc callback, libressl.openssl.ossl_typ.BN_CTX* ctx, void* cb_arg, int do_trial_division);
}

/* Newer versions */
int BN_generate_prime_ex(libressl.openssl.ossl_typ.BIGNUM* ret, int bits, int safe, const (libressl.openssl.ossl_typ.BIGNUM)* add, const (libressl.openssl.ossl_typ.BIGNUM)* rem, libressl.openssl.ossl_typ.BN_GENCB* cb);
int BN_is_prime_ex(const (libressl.openssl.ossl_typ.BIGNUM)* p, int nchecks, libressl.openssl.ossl_typ.BN_CTX* ctx, libressl.openssl.ossl_typ.BN_GENCB* cb);
int BN_is_prime_fasttest_ex(const (libressl.openssl.ossl_typ.BIGNUM)* p, int nchecks, libressl.openssl.ossl_typ.BN_CTX* ctx, int do_trial_division, libressl.openssl.ossl_typ.BN_GENCB* cb);

int BN_X931_generate_Xpq(libressl.openssl.ossl_typ.BIGNUM* Xp, libressl.openssl.ossl_typ.BIGNUM* Xq, int nbits, libressl.openssl.ossl_typ.BN_CTX* ctx);

int BN_X931_derive_prime_ex(libressl.openssl.ossl_typ.BIGNUM* p, libressl.openssl.ossl_typ.BIGNUM* p1, libressl.openssl.ossl_typ.BIGNUM* p2, const (libressl.openssl.ossl_typ.BIGNUM)* Xp, const (libressl.openssl.ossl_typ.BIGNUM)* Xp1, const (libressl.openssl.ossl_typ.BIGNUM)* Xp2, const (libressl.openssl.ossl_typ.BIGNUM)* e, libressl.openssl.ossl_typ.BN_CTX* ctx, libressl.openssl.ossl_typ.BN_GENCB* cb);
int BN_X931_generate_prime_ex(libressl.openssl.ossl_typ.BIGNUM* p, libressl.openssl.ossl_typ.BIGNUM* p1, libressl.openssl.ossl_typ.BIGNUM* p2, libressl.openssl.ossl_typ.BIGNUM* Xp1, libressl.openssl.ossl_typ.BIGNUM* Xp2, const (libressl.openssl.ossl_typ.BIGNUM)* Xp, const (libressl.openssl.ossl_typ.BIGNUM)* e, libressl.openssl.ossl_typ.BN_CTX* ctx, libressl.openssl.ossl_typ.BN_GENCB* cb);

libressl.openssl.ossl_typ.BN_MONT_CTX* BN_MONT_CTX_new();
void BN_MONT_CTX_init(libressl.openssl.ossl_typ.BN_MONT_CTX* ctx);
int BN_mod_mul_montgomery(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b, libressl.openssl.ossl_typ.BN_MONT_CTX* mont, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_to_montgomery(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, libressl.openssl.ossl_typ.BN_MONT_CTX* mont, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_from_montgomery(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, libressl.openssl.ossl_typ.BN_MONT_CTX* mont, libressl.openssl.ossl_typ.BN_CTX* ctx);
void BN_MONT_CTX_free(libressl.openssl.ossl_typ.BN_MONT_CTX* mont);
int BN_MONT_CTX_set(libressl.openssl.ossl_typ.BN_MONT_CTX* mont, const (libressl.openssl.ossl_typ.BIGNUM)* mod, libressl.openssl.ossl_typ.BN_CTX* ctx);
libressl.openssl.ossl_typ.BN_MONT_CTX* BN_MONT_CTX_copy(libressl.openssl.ossl_typ.BN_MONT_CTX* to, libressl.openssl.ossl_typ.BN_MONT_CTX* from);
libressl.openssl.ossl_typ.BN_MONT_CTX* BN_MONT_CTX_set_locked(libressl.openssl.ossl_typ.BN_MONT_CTX** pmont, int lock, const (libressl.openssl.ossl_typ.BIGNUM)* mod, libressl.openssl.ossl_typ.BN_CTX* ctx);

/* libressl.openssl.ossl_typ.BN_BLINDING flags */
enum BN_BLINDING_NO_UPDATE = 0x00000001;
enum BN_BLINDING_NO_RECREATE = 0x00000002;

libressl.openssl.ossl_typ.BN_BLINDING* BN_BLINDING_new(const (libressl.openssl.ossl_typ.BIGNUM)* A, const (libressl.openssl.ossl_typ.BIGNUM)* Ai, libressl.openssl.ossl_typ.BIGNUM* mod);
void BN_BLINDING_free(libressl.openssl.ossl_typ.BN_BLINDING* b);
int BN_BLINDING_update(libressl.openssl.ossl_typ.BN_BLINDING* b, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_BLINDING_convert(libressl.openssl.ossl_typ.BIGNUM* n, libressl.openssl.ossl_typ.BN_BLINDING* b, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_BLINDING_invert(libressl.openssl.ossl_typ.BIGNUM* n, libressl.openssl.ossl_typ.BN_BLINDING* b, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_BLINDING_convert_ex(libressl.openssl.ossl_typ.BIGNUM* n, libressl.openssl.ossl_typ.BIGNUM* r, libressl.openssl.ossl_typ.BN_BLINDING* b, libressl.openssl.ossl_typ.BN_CTX*);
int BN_BLINDING_invert_ex(libressl.openssl.ossl_typ.BIGNUM* n, const (libressl.openssl.ossl_typ.BIGNUM)* r, libressl.openssl.ossl_typ.BN_BLINDING* b, libressl.openssl.ossl_typ.BN_CTX*);

version (OPENSSL_NO_DEPRECATED) {
} else {
	core.stdc.config.c_ulong BN_BLINDING_get_thread_id(const (libressl.openssl.ossl_typ.BN_BLINDING)*);
	void BN_BLINDING_set_thread_id(libressl.openssl.ossl_typ.BN_BLINDING*, core.stdc.config.c_ulong);
}

libressl.openssl.crypto.CRYPTO_THREADID* BN_BLINDING_thread_id(libressl.openssl.ossl_typ.BN_BLINDING*);
core.stdc.config.c_ulong BN_BLINDING_get_flags(const (libressl.openssl.ossl_typ.BN_BLINDING)*);
void BN_BLINDING_set_flags(libressl.openssl.ossl_typ.BN_BLINDING*, core.stdc.config.c_ulong);
libressl.openssl.ossl_typ.BN_BLINDING* BN_BLINDING_create_param(libressl.openssl.ossl_typ.BN_BLINDING* b, const (libressl.openssl.ossl_typ.BIGNUM)* e, libressl.openssl.ossl_typ.BIGNUM* m, libressl.openssl.ossl_typ.BN_CTX* ctx, int function(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p, const (libressl.openssl.ossl_typ.BIGNUM)* m, libressl.openssl.ossl_typ.BN_CTX* ctx, libressl.openssl.ossl_typ.BN_MONT_CTX* m_ctx) nothrow @nogc bn_mod_exp, libressl.openssl.ossl_typ.BN_MONT_CTX* m_ctx);

version (OPENSSL_NO_DEPRECATED) {
} else {
	void BN_set_params(int mul, int high, int low, int mont);

	/**
	 * 0, mul, 1 high, 2 low, 3 mont
	 */
	int BN_get_params(int which);
}

void BN_RECP_CTX_init(libressl.openssl.ossl_typ.BN_RECP_CTX* recp);
libressl.openssl.ossl_typ.BN_RECP_CTX* BN_RECP_CTX_new();
void BN_RECP_CTX_free(libressl.openssl.ossl_typ.BN_RECP_CTX* recp);
int BN_RECP_CTX_set(libressl.openssl.ossl_typ.BN_RECP_CTX* recp, const (libressl.openssl.ossl_typ.BIGNUM)* rdiv, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_mod_mul_reciprocal(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* x, const (libressl.openssl.ossl_typ.BIGNUM)* y, libressl.openssl.ossl_typ.BN_RECP_CTX* recp, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_mod_exp_recp(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p, const (libressl.openssl.ossl_typ.BIGNUM)* m, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_div_recp(libressl.openssl.ossl_typ.BIGNUM* dv, libressl.openssl.ossl_typ.BIGNUM* rem, const (libressl.openssl.ossl_typ.BIGNUM)* m, libressl.openssl.ossl_typ.BN_RECP_CTX* recp, libressl.openssl.ossl_typ.BN_CTX* ctx);

version (OPENSSL_NO_EC2M) {
} else {
	/*
	 * Functions for arithmetic over binary polynomials represented by BIGNUMs.
	 *
	 * The BIGNUM::neg property of BIGNUMs representing binary polynomials is
	 * ignored.
	 *
	 * Note that input arguments are not const so that their bit arrays can
	 * be expanded to the appropriate size if needed.
	 */

	/**
	 * r = a + b
	 */
	int BN_GF2m_add(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b);

	alias BN_GF2m_sub = .BN_GF2m_add;

	/**
	 * r = a mod p
	 */
	int BN_GF2m_mod(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p);

	/**
	 * r = (a * b) mod p
	 */
	int BN_GF2m_mod_mul(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b, const (libressl.openssl.ossl_typ.BIGNUM)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * r = (a * a) mod p
	 */
	int BN_GF2m_mod_sqr(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * r = (1 / b) mod p
	 */
	int BN_GF2m_mod_inv(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* b, const (libressl.openssl.ossl_typ.BIGNUM)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * r = (a / b) mod p
	 */
	int BN_GF2m_mod_div(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b, const (libressl.openssl.ossl_typ.BIGNUM)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * r = (a ^ b) mod p
	 */
	int BN_GF2m_mod_exp(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b, const (libressl.openssl.ossl_typ.BIGNUM)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * r = sqrt(a) mod p
	 */
	int BN_GF2m_mod_sqrt(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * r^2 + r = a mod p
	 */
	int BN_GF2m_mod_solve_quad(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

	alias BN_GF2m_cmp = .BN_ucmp;

	/*
	 * Some functions allow for representation of the irreducible polynomials
	 * as an uint[], say p.  The irreducible f(t) is then of the form:
	 *     t^p[0] + t^p[1] + ... + t^p[k]
	 * where m = p[0] > p[1] > ... > p[k] = 0.
	 */
	int BN_GF2m_mod_arr(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (int)* p);
	/* r = a mod p */

	/**
	 * r = (a * b) mod p
	 */
	int BN_GF2m_mod_mul_arr(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b, const (int)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * r = (a * a) mod p
	 */
	int BN_GF2m_mod_sqr_arr(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (int)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * r = (1 / b) mod p
	 */
	int BN_GF2m_mod_inv_arr(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* b, const (int)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * r = (a / b) mod p
	 */
	int BN_GF2m_mod_div_arr(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b, const (int)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * r = (a ^ b) mod p
	 */
	int BN_GF2m_mod_exp_arr(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* b, const (int)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * r = sqrt(a) mod p
	 */
	int BN_GF2m_mod_sqrt_arr(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (int)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * r^2 + r = a mod p
	 */
	int BN_GF2m_mod_solve_quad_arr(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (int)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

	int BN_GF2m_poly2arr(const (libressl.openssl.ossl_typ.BIGNUM)* a, int* p, int max);
	int BN_GF2m_arr2poly(const (int)* p, libressl.openssl.ossl_typ.BIGNUM* a);
}

/*
 * faster mod functions for the 'NIST primes'
 * 0 <= a < p^2
 */
int BN_nist_mod_192(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_nist_mod_224(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_nist_mod_256(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_nist_mod_384(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);
int BN_nist_mod_521(libressl.openssl.ossl_typ.BIGNUM* r, const (libressl.openssl.ossl_typ.BIGNUM)* a, const (libressl.openssl.ossl_typ.BIGNUM)* p, libressl.openssl.ossl_typ.BN_CTX* ctx);

const (libressl.openssl.ossl_typ.BIGNUM)* BN_get0_nist_prime_192();
const (libressl.openssl.ossl_typ.BIGNUM)* BN_get0_nist_prime_224();
const (libressl.openssl.ossl_typ.BIGNUM)* BN_get0_nist_prime_256();
const (libressl.openssl.ossl_typ.BIGNUM)* BN_get0_nist_prime_384();
const (libressl.openssl.ossl_typ.BIGNUM)* BN_get0_nist_prime_521();

/* Primes from RFC 2409 */
libressl.openssl.ossl_typ.BIGNUM* get_rfc2409_prime_768(libressl.openssl.ossl_typ.BIGNUM* bn);
libressl.openssl.ossl_typ.BIGNUM* get_rfc2409_prime_1024(libressl.openssl.ossl_typ.BIGNUM* bn);
libressl.openssl.ossl_typ.BIGNUM* BN_get_rfc2409_prime_768(libressl.openssl.ossl_typ.BIGNUM* bn);
libressl.openssl.ossl_typ.BIGNUM* BN_get_rfc2409_prime_1024(libressl.openssl.ossl_typ.BIGNUM* bn);

/* Primes from RFC 3526 */
libressl.openssl.ossl_typ.BIGNUM* get_rfc3526_prime_1536(libressl.openssl.ossl_typ.BIGNUM* bn);
libressl.openssl.ossl_typ.BIGNUM* get_rfc3526_prime_2048(libressl.openssl.ossl_typ.BIGNUM* bn);
libressl.openssl.ossl_typ.BIGNUM* get_rfc3526_prime_3072(libressl.openssl.ossl_typ.BIGNUM* bn);
libressl.openssl.ossl_typ.BIGNUM* get_rfc3526_prime_4096(libressl.openssl.ossl_typ.BIGNUM* bn);
libressl.openssl.ossl_typ.BIGNUM* get_rfc3526_prime_6144(libressl.openssl.ossl_typ.BIGNUM* bn);
libressl.openssl.ossl_typ.BIGNUM* get_rfc3526_prime_8192(libressl.openssl.ossl_typ.BIGNUM* bn);
libressl.openssl.ossl_typ.BIGNUM* BN_get_rfc3526_prime_1536(libressl.openssl.ossl_typ.BIGNUM* bn);
libressl.openssl.ossl_typ.BIGNUM* BN_get_rfc3526_prime_2048(libressl.openssl.ossl_typ.BIGNUM* bn);
libressl.openssl.ossl_typ.BIGNUM* BN_get_rfc3526_prime_3072(libressl.openssl.ossl_typ.BIGNUM* bn);
libressl.openssl.ossl_typ.BIGNUM* BN_get_rfc3526_prime_4096(libressl.openssl.ossl_typ.BIGNUM* bn);
libressl.openssl.ossl_typ.BIGNUM* BN_get_rfc3526_prime_6144(libressl.openssl.ossl_typ.BIGNUM* bn);
libressl.openssl.ossl_typ.BIGNUM* BN_get_rfc3526_prime_8192(libressl.openssl.ossl_typ.BIGNUM* bn);

void ERR_load_BN_strings();

/* Error codes for the BN functions. */

/* Function codes. */
enum BN_F_BNRAND = 127;
enum BN_F_BN_BLINDING_CONVERT_EX = 100;
enum BN_F_BN_BLINDING_CREATE_PARAM = 128;
enum BN_F_BN_BLINDING_INVERT_EX = 101;
enum BN_F_BN_BLINDING_NEW = 102;
enum BN_F_BN_BLINDING_UPDATE = 103;
enum BN_F_BN_BN2DEC = 104;
enum BN_F_BN_BN2HEX = 105;
enum BN_F_BN_CTX_GET = 116;
enum BN_F_BN_CTX_NEW = 106;
enum BN_F_BN_CTX_START = 129;
enum BN_F_BN_DIV = 107;
enum BN_F_BN_DIV_NO_BRANCH = 138;
enum BN_F_BN_DIV_RECP = 130;
enum BN_F_BN_EXP = 123;
enum BN_F_BN_EXPAND2 = 108;
enum BN_F_BN_GENERATE_PRIME_EX = 140;
enum BN_F_BN_EXPAND_INTERNAL = 120;
enum BN_F_BN_GF2M_MOD = 131;
enum BN_F_BN_GF2M_MOD_EXP = 132;
enum BN_F_BN_GF2M_MOD_MUL = 133;
enum BN_F_BN_GF2M_MOD_SOLVE_QUAD = 134;
enum BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR = 135;
enum BN_F_BN_GF2M_MOD_SQR = 136;
enum BN_F_BN_GF2M_MOD_SQRT = 137;
enum BN_F_BN_MOD_EXP2_MONT = 118;
enum BN_F_BN_MOD_EXP_MONT = 109;
enum BN_F_BN_MOD_EXP_MONT_CONSTTIME = 124;
enum BN_F_BN_MOD_EXP_MONT_WORD = 117;
enum BN_F_BN_MOD_EXP_RECP = 125;
enum BN_F_BN_MOD_EXP_SIMPLE = 126;
enum BN_F_BN_MOD_INVERSE = 110;
enum BN_F_BN_MOD_INVERSE_NO_BRANCH = 139;
enum BN_F_BN_MOD_LSHIFT_QUICK = 119;
enum BN_F_BN_MOD_MUL_RECIPROCAL = 111;
enum BN_F_BN_MOD_SQRT = 121;
enum BN_F_BN_MPI2BN = 112;
enum BN_F_BN_NEW = 113;
enum BN_F_BN_RAND = 114;
enum BN_F_BN_RAND_RANGE = 122;
enum BN_F_BN_USUB = 115;

/* Reason codes. */
enum BN_R_ARG2_LT_ARG3 = 100;
enum BN_R_BAD_RECIPROCAL = 101;
enum BN_R_BIGNUM_TOO_LONG = 114;
enum BN_R_BITS_TOO_SMALL = 117;
enum BN_R_CALLED_WITH_EVEN_MODULUS = 102;
enum BN_R_DIV_BY_ZERO = 103;
enum BN_R_ENCODING_ERROR = 104;
enum BN_R_EXPAND_ON_STATIC_BIGNUM_DATA = 105;
enum BN_R_INPUT_NOT_REDUCED = 110;
enum BN_R_INVALID_LENGTH = 106;
enum BN_R_INVALID_RANGE = 115;
enum BN_R_NOT_A_SQUARE = 111;
enum BN_R_NOT_INITIALIZED = 107;
enum BN_R_NO_INVERSE = 108;
enum BN_R_NO_SOLUTION = 116;
enum BN_R_P_IS_NOT_PRIME = 112;
enum BN_R_TOO_MANY_ITERATIONS = 113;
enum BN_R_TOO_MANY_TEMPORARY_VARIABLES = 109;
