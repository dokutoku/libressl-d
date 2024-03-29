/* $OpenBSD: rand.h,v 1.23 2022/07/12 14:42:50 kn Exp $ */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
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
module libressl.openssl.rand;


private static import core.stdc.config;
public import libressl.compat.stdlib;
public import libressl.openssl.opensslconf;
public import libressl.openssl.ossl_typ;

extern (C):
nothrow @nogc:

/* Already defined in ossl_typ.h */
/* alias RAND_METHOD = .rand_meth_st; */

struct rand_meth_st
{
	void function(const (void)* buf, int num) seed;
	int function(ubyte* buf, int num) bytes;
	void function() cleanup;
	void function(const (void)* buf, int num, double entropy) add;
	int function(ubyte* buf, int num) pseudorand;
	int function() status;
}

int RAND_set_rand_method(const (libressl.openssl.ossl_typ.RAND_METHOD)* meth);
const (libressl.openssl.ossl_typ.RAND_METHOD)* RAND_get_rand_method();

version (OPENSSL_NO_ENGINE) {
} else {
	int RAND_set_rand_engine(libressl.openssl.ossl_typ.ENGINE* engine);
}

libressl.openssl.ossl_typ.RAND_METHOD* RAND_SSLeay();

version (LIBRESSL_INTERNAL) {
} else {
	void RAND_cleanup();
	int RAND_bytes(ubyte* buf, int num);
	int RAND_pseudo_bytes(ubyte* buf, int num);
	void RAND_seed(const (void)* buf, int num);
	void RAND_add(const (void)* buf, int num, double entropy);
	int RAND_load_file(const (char)* file, core.stdc.config.c_long max_bytes);
	int RAND_write_file(const (char)* file);
	const (char)* RAND_file_name(char* file, size_t num);
	int RAND_status();
	int RAND_poll();
}

void ERR_load_RAND_strings();

/* Error codes for the RAND functions. (no longer used) */

/* Function codes. */
enum RAND_F_RAND_GET_RAND_METHOD = 101;
enum RAND_F_RAND_INIT_FIPS = 102;
enum RAND_F_SSLEAY_RAND_BYTES = 100;

/* Reason codes. */
enum RAND_R_DUAL_EC_DRBG_DISABLED = 104;
enum RAND_R_ERROR_INITIALISING_DRBG = 102;
enum RAND_R_ERROR_INSTANTIATING_DRBG = 103;
enum RAND_R_NO_FIPS_RANDOM_METHOD_SET = 101;
enum RAND_R_PRNG_NOT_SEEDED = 100;
