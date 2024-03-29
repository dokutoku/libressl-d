/* $OpenBSD: dh.h,v 1.35 2022/07/12 14:42:49 kn Exp $ */
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
module libressl.openssl.dh;


private static import core.stdc.config;
private static import libressl.compat.stdio;
private static import libressl.openssl.evp;
public import libressl.openssl.opensslconf;
public import libressl.openssl.ossl_typ;

version (OPENSSL_NO_DH) {
	static assert(false, "DH is disabled.");
}

version (OPENSSL_NO_BIO) {
} else {
	public import libressl.openssl.bio;
}

version (OPENSSL_NO_DEPRECATED) {
} else {
	public import libressl.openssl.bn;
}

//#if !defined(OPENSSL_DH_MAX_MODULUS_BITS)
	enum OPENSSL_DH_MAX_MODULUS_BITS = 10000;
//#endif

enum DH_FLAG_CACHE_MONT_P = 0x01;

/**
 * If this flag is set the DH method is FIPS compliant and can be used
 * in FIPS mode. This is set in the validated module method. If an
 * application sets this flag in its own methods it is its reposibility
 * to ensure the result is compliant.
 */
enum DH_FLAG_FIPS_METHOD = 0x0400;

/**
 * If this flag is set the operations normally disabled in FIPS mode are
 * permitted it is then the applications responsibility to ensure that the
 * usage is compliant.
 */
enum DH_FLAG_NON_FIPS_ALLOW = 0x0400;

extern (C):
nothrow @nogc:

enum DH_GENERATOR_2 = 2;
/* enum DH_GENERATOR_3 = 3; */
enum DH_GENERATOR_5 = 5;

/* DH_check error codes */
enum DH_CHECK_P_NOT_PRIME = 0x01;
enum DH_CHECK_P_NOT_SAFE_PRIME = 0x02;
enum DH_UNABLE_TO_CHECK_GENERATOR = 0x04;
enum DH_NOT_SUITABLE_GENERATOR = 0x08;
enum DH_CHECK_Q_NOT_PRIME = 0x10;
enum DH_CHECK_INVALID_Q_VALUE = 0x20;
enum DH_CHECK_INVALID_J_VALUE = 0x40;

/* DH_check_pub_key error codes */
enum DH_CHECK_PUBKEY_TOO_SMALL = 0x01;
enum DH_CHECK_PUBKEY_TOO_LARGE = 0x02;
enum DH_CHECK_PUBKEY_INVALID = 0x04;

/**
 * primes p where (p-1)/2 is prime too are called "safe"; we define
 * this for backward compatibility:
 */
enum DH_CHECK_P_NOT_STRONG_PRIME = .DH_CHECK_P_NOT_SAFE_PRIME;

libressl.openssl.ossl_typ.DH* d2i_DHparams_bio(libressl.openssl.ossl_typ.BIO* bp, libressl.openssl.ossl_typ.DH** a);
int i2d_DHparams_bio(libressl.openssl.ossl_typ.BIO* bp, libressl.openssl.ossl_typ.DH* a);
libressl.openssl.ossl_typ.DH* d2i_DHparams_fp(libressl.compat.stdio.FILE* fp, libressl.openssl.ossl_typ.DH** a);
int i2d_DHparams_fp(libressl.compat.stdio.FILE* fp, libressl.openssl.ossl_typ.DH* a);

libressl.openssl.ossl_typ.DH* DHparams_dup(libressl.openssl.ossl_typ.DH*);

const (libressl.openssl.ossl_typ.DH_METHOD)* DH_OpenSSL();

void DH_set_default_method(const (libressl.openssl.ossl_typ.DH_METHOD)* meth);
const (libressl.openssl.ossl_typ.DH_METHOD)* DH_get_default_method();
int DH_set_method(libressl.openssl.ossl_typ.DH* dh, const (libressl.openssl.ossl_typ.DH_METHOD)* meth);
libressl.openssl.ossl_typ.DH* DH_new_method(libressl.openssl.ossl_typ.ENGINE* engine);

libressl.openssl.ossl_typ.DH* DH_new();
void DH_free(libressl.openssl.ossl_typ.DH* dh);
int DH_up_ref(libressl.openssl.ossl_typ.DH* dh);
int DH_size(const (libressl.openssl.ossl_typ.DH)* dh);
int DH_bits(const (libressl.openssl.ossl_typ.DH)* dh);
int DH_get_ex_new_index(core.stdc.config.c_long argl, void* argp, libressl.openssl.ossl_typ.CRYPTO_EX_new new_func, libressl.openssl.ossl_typ.CRYPTO_EX_dup dup_func, libressl.openssl.ossl_typ.CRYPTO_EX_free free_func);
int DH_set_ex_data(libressl.openssl.ossl_typ.DH* d, int idx, void* arg);
void* DH_get_ex_data(libressl.openssl.ossl_typ.DH* d, int idx);
int DH_security_bits(const (libressl.openssl.ossl_typ.DH)* dh);

libressl.openssl.ossl_typ.ENGINE* DH_get0_engine(libressl.openssl.ossl_typ.DH* d);
void DH_get0_pqg(const (libressl.openssl.ossl_typ.DH)* dh, const (libressl.openssl.ossl_typ.BIGNUM)** p, const (libressl.openssl.ossl_typ.BIGNUM)** q, const (libressl.openssl.ossl_typ.BIGNUM)** g);
int DH_set0_pqg(libressl.openssl.ossl_typ.DH* dh, libressl.openssl.ossl_typ.BIGNUM* p, libressl.openssl.ossl_typ.BIGNUM* q, libressl.openssl.ossl_typ.BIGNUM* g);
void DH_get0_key(const (libressl.openssl.ossl_typ.DH)* dh, const (libressl.openssl.ossl_typ.BIGNUM)** pub_key, const (libressl.openssl.ossl_typ.BIGNUM)** priv_key);
int DH_set0_key(libressl.openssl.ossl_typ.DH* dh, libressl.openssl.ossl_typ.BIGNUM* pub_key, libressl.openssl.ossl_typ.BIGNUM* priv_key);
const (libressl.openssl.ossl_typ.BIGNUM)* DH_get0_p(const (libressl.openssl.ossl_typ.DH)* dh);
const (libressl.openssl.ossl_typ.BIGNUM)* DH_get0_q(const (libressl.openssl.ossl_typ.DH)* dh);
const (libressl.openssl.ossl_typ.BIGNUM)* DH_get0_g(const (libressl.openssl.ossl_typ.DH)* dh);
const (libressl.openssl.ossl_typ.BIGNUM)* DH_get0_priv_key(const (libressl.openssl.ossl_typ.DH)* dh);
const (libressl.openssl.ossl_typ.BIGNUM)* DH_get0_pub_key(const (libressl.openssl.ossl_typ.DH)* dh);
void DH_clear_flags(libressl.openssl.ossl_typ.DH* dh, int flags);
int DH_test_flags(const (libressl.openssl.ossl_typ.DH)* dh, int flags);
void DH_set_flags(libressl.openssl.ossl_typ.DH* dh, int flags);
core.stdc.config.c_long DH_get_length(const (libressl.openssl.ossl_typ.DH)* dh);
int DH_set_length(libressl.openssl.ossl_typ.DH* dh, core.stdc.config.c_long length_);

/* Deprecated version */
version (OPENSSL_NO_DEPRECATED) {
} else {
	libressl.openssl.ossl_typ.DH* DH_generate_parameters(int prime_len, int generator, void function(int, int, void*) nothrow @nogc callback, void* cb_arg);
}

/* New version */
int DH_generate_parameters_ex(libressl.openssl.ossl_typ.DH* dh, int prime_len, int generator, libressl.openssl.ossl_typ.BN_GENCB* cb);

int DH_check(const (libressl.openssl.ossl_typ.DH)* dh, int* codes);
int DH_check_pub_key(const (libressl.openssl.ossl_typ.DH)* dh, const (libressl.openssl.ossl_typ.BIGNUM)* pub_key, int* codes);
int DH_generate_key(libressl.openssl.ossl_typ.DH* dh);
int DH_compute_key(ubyte* key, const (libressl.openssl.ossl_typ.BIGNUM)* pub_key, libressl.openssl.ossl_typ.DH* dh);
libressl.openssl.ossl_typ.DH* d2i_DHparams(libressl.openssl.ossl_typ.DH** a, const (ubyte)** pp, core.stdc.config.c_long length_);
int i2d_DHparams(const (libressl.openssl.ossl_typ.DH)* a, ubyte** pp);
int DHparams_print_fp(libressl.compat.stdio.FILE* fp, const (libressl.openssl.ossl_typ.DH)* x);

version(OPENSSL_NO_BIO) {
	int DHparams_print(char* bp, const (libressl.openssl.ossl_typ.DH)* x);
} else {
	int DHparams_print(libressl.openssl.ossl_typ.BIO* bp, const (libressl.openssl.ossl_typ.DH)* x);
}

pragma(inline, true)
int EVP_PKEY_CTX_set_dh_paramgen_prime_len(libressl.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int len)

	do
	{
		return libressl.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl.openssl.evp.EVP_PKEY_DH, libressl.openssl.evp.EVP_PKEY_OP_PARAMGEN, .EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, len, null);
	}

pragma(inline, true)
int EVP_PKEY_CTX_set_dh_paramgen_generator(libressl.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int gen)

	do
	{
		return libressl.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl.openssl.evp.EVP_PKEY_DH, libressl.openssl.evp.EVP_PKEY_OP_PARAMGEN, .EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR, gen, null);
	}

enum EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN = libressl.openssl.evp.EVP_PKEY_ALG_CTRL + 1;
enum EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR = libressl.openssl.evp.EVP_PKEY_ALG_CTRL + 2;

void ERR_load_DH_strings();

/* Error codes for the DH functions. */

/* Function codes. */
enum DH_F_COMPUTE_KEY = 102;
enum DH_F_DHPARAMS_PRINT_FP = 101;
enum DH_F_DH_BUILTIN_GENPARAMS = 106;
enum DH_F_DH_COMPUTE_KEY = 114;
enum DH_F_DH_GENERATE_KEY = 115;
enum DH_F_DH_GENERATE_PARAMETERS_EX = 116;
enum DH_F_DH_NEW_METHOD = 105;
enum DH_F_DH_PARAM_DECODE = 107;
enum DH_F_DH_PRIV_DECODE = 110;
enum DH_F_DH_PRIV_ENCODE = 111;
enum DH_F_DH_PUB_DECODE = 108;
enum DH_F_DH_PUB_ENCODE = 109;
enum DH_F_DO_DH_PRINT = 100;
enum DH_F_GENERATE_KEY = 103;
enum DH_F_GENERATE_PARAMETERS = 104;
enum DH_F_PKEY_DH_DERIVE = 112;
enum DH_F_PKEY_DH_KEYGEN = 113;

/* Reason codes. */
enum DH_R_BAD_GENERATOR = 101;
enum DH_R_BN_DECODE_ERROR = 109;
enum DH_R_BN_ERROR = 106;
enum DH_R_DECODE_ERROR = 104;
enum DH_R_INVALID_PUBKEY = 102;
enum DH_R_KEYS_NOT_SET = 108;
enum DH_R_KEY_SIZE_TOO_SMALL = 110;
enum DH_R_MODULUS_TOO_LARGE = 103;
enum DH_R_NON_FIPS_METHOD = 111;
enum DH_R_NO_PARAMETERS_SET = 107;
enum DH_R_NO_PRIVATE_VALUE = 100;
enum DH_R_PARAMETER_ENCODING_ERROR = 105;
enum DH_R_CHECK_INVALID_J_VALUE = 115;
enum DH_R_CHECK_INVALID_Q_VALUE = 116;
enum DH_R_CHECK_PUBKEY_INVALID = 122;
enum DH_R_CHECK_PUBKEY_TOO_LARGE = 123;
enum DH_R_CHECK_PUBKEY_TOO_SMALL = 124;
enum DH_R_CHECK_P_NOT_PRIME = 117;
enum DH_R_CHECK_P_NOT_SAFE_PRIME = 118;
enum DH_R_CHECK_Q_NOT_PRIME = 119;
enum DH_R_MISSING_PUBKEY = 125;
enum DH_R_NOT_SUITABLE_GENERATOR = 120;
enum DH_R_UNABLE_TO_CHECK_GENERATOR = 121;
