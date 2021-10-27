/* $OpenBSD: dsa.h,v 1.30 2018/03/17 15:19:12 tb Exp $ */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as core.stdc.config.c_long as
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

/*
 * The DSS routines are based on patches supplied by
 * Steven Schoch <schoch@sheba.arc.nasa.gov>.  He basically did the
 * work and I have just tweaked them a little to fit into my
 * stylistic vision for SSLeay :-)
 */
module libressl_d.openssl.dsa;


private static import core.stdc.config;
private static import libressl_d.compat.stdio;
private static import libressl_d.openssl.evp;
public import libressl_d.openssl.bio;
public import libressl_d.openssl.bn;
public import libressl_d.openssl.crypto;
public import libressl_d.openssl.dh;
public import libressl_d.openssl.opensslconf;
public import libressl_d.openssl.ossl_typ;

version (OPENSSL_NO_DSA) {
	//static assert(false, "DSA is disabled.");
}

//#if !defined(OPENSSL_NO_BIO)
	//public import libressl_d.openssl.bio;
//#endif

//#if !defined(OPENSSL_NO_DEPRECATED)
	//public import libressl_d.openssl.bn;

	//#if !defined(OPENSSL_NO_DH)
		//public import libressl_d.openssl.dh;
	//#endif
//#endif

//#if !defined(OPENSSL_DSA_MAX_MODULUS_BITS)
	enum OPENSSL_DSA_MAX_MODULUS_BITS = 10000;
//#endif

enum DSA_FLAG_CACHE_MONT_P = 0x01;

/**
 * If this flag is set the DSA method is FIPS compliant and can be used
 * in FIPS mode. This is set in the validated module method. If an
 * application sets this flag in its own methods it is its reposibility
 * to ensure the result is compliant.
 */
enum DSA_FLAG_FIPS_METHOD = 0x0400;

/**
 * If this flag is set the operations normally disabled in FIPS mode are
 * permitted it is then the applications responsibility to ensure that the
 * usage is compliant.
 */
enum DSA_FLAG_NON_FIPS_ALLOW = 0x0400;

extern (C):
nothrow @nogc:

/* Already defined in ossl_typ.h */
/* alias DSA = .dsa.dsa_st; */
/* alias DSA_METHOD = .dsa_method; */

struct DSA_SIG_st
{
	libressl_d.openssl.ossl_typ.BIGNUM* r;
	libressl_d.openssl.ossl_typ.BIGNUM* s;
}

alias DSA_SIG = .DSA_SIG_st;

struct dsa_method
{
	const (char)* name;
	.DSA_SIG* function(const (ubyte)* dgst, int dlen, libressl_d.openssl.ossl_typ.DSA* dsa) dsa_do_sign;
	int function(libressl_d.openssl.ossl_typ.DSA* dsa, libressl_d.openssl.ossl_typ.BN_CTX* ctx_in, libressl_d.openssl.ossl_typ.BIGNUM** kinvp, libressl_d.openssl.ossl_typ.BIGNUM** rp) dsa_sign_setup;
	int function(const (ubyte)* dgst, int dgst_len, .DSA_SIG* sig, libressl_d.openssl.ossl_typ.DSA* dsa) dsa_do_verify;
	int function(libressl_d.openssl.ossl_typ.DSA* dsa, libressl_d.openssl.ossl_typ.BIGNUM* rr, libressl_d.openssl.ossl_typ.BIGNUM* a1, libressl_d.openssl.ossl_typ.BIGNUM* p1, libressl_d.openssl.ossl_typ.BIGNUM* a2, libressl_d.openssl.ossl_typ.BIGNUM* p2, libressl_d.openssl.ossl_typ.BIGNUM* m, libressl_d.openssl.ossl_typ.BN_CTX* ctx, libressl_d.openssl.ossl_typ.BN_MONT_CTX* in_mont) dsa_mod_exp;

	/**
	 * Can be null
	 */
	int function(libressl_d.openssl.ossl_typ.DSA* dsa, libressl_d.openssl.ossl_typ.BIGNUM* r, libressl_d.openssl.ossl_typ.BIGNUM* a, const (libressl_d.openssl.ossl_typ.BIGNUM)* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* m, libressl_d.openssl.ossl_typ.BN_CTX* ctx, libressl_d.openssl.ossl_typ.BN_MONT_CTX* m_ctx) bn_mod_exp;

	int function(libressl_d.openssl.ossl_typ.DSA* dsa) init;
	int function(libressl_d.openssl.ossl_typ.DSA* dsa) finish;
	int flags;
	char* app_data;

	/**
	 * If this is non-null, it is used to generate DSA parameters
	 */
	int function(libressl_d.openssl.ossl_typ.DSA* dsa, int bits, const (ubyte)* seed, int seed_len, int* counter_ret, core.stdc.config.c_ulong* h_ret, libressl_d.openssl.ossl_typ.BN_GENCB* cb) dsa_paramgen;

	/**
	 * If this is non-null, it is used to generate DSA keys
	 */
	int function(libressl_d.openssl.ossl_typ.DSA* dsa) dsa_keygen;
}

struct dsa_st
{
	/**
	 * This first variable is used to pick up errors where
	 * a DSA is passed instead of of a EVP_PKEY
	 */
	int pad;

	core.stdc.config.c_long version_;
	int write_params;
	libressl_d.openssl.ossl_typ.BIGNUM* p;

	/**
	 * == 20
	 */
	libressl_d.openssl.ossl_typ.BIGNUM* q;

	libressl_d.openssl.ossl_typ.BIGNUM* g;

	/**
	 * y public key
	 */
	libressl_d.openssl.ossl_typ.BIGNUM* pub_key;

	/**
	 * x private key
	 */
	libressl_d.openssl.ossl_typ.BIGNUM* priv_key;

	/**
	 * Signing pre-calc
	 */
	libressl_d.openssl.ossl_typ.BIGNUM* kinv;

	/**
	 * Signing pre-calc
	 */
	libressl_d.openssl.ossl_typ.BIGNUM* r;

	int flags;
	/* Normally used to cache montgomery values */
	libressl_d.openssl.ossl_typ.BN_MONT_CTX* method_mont_p;
	int references;
	libressl_d.openssl.ossl_typ.CRYPTO_EX_DATA ex_data;
	const (libressl_d.openssl.ossl_typ.DSA_METHOD)* meth;

	/**
	 * functional reference if 'meth' is ENGINE-provided
	 */
	libressl_d.openssl.ossl_typ.ENGINE* engine;
}

libressl_d.openssl.ossl_typ.DSA* d2i_DSAparams_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.DSA** a);
int i2d_DSAparams_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.DSA* a);
libressl_d.openssl.ossl_typ.DSA* d2i_DSAparams_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.DSA** a);
int i2d_DSAparams_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.DSA* a);

libressl_d.openssl.ossl_typ.DSA* DSAparams_dup(libressl_d.openssl.ossl_typ.DSA* x);
.DSA_SIG* DSA_SIG_new();
void DSA_SIG_free(.DSA_SIG* a);
int i2d_DSA_SIG(const (.DSA_SIG)* a, ubyte** pp);
.DSA_SIG* d2i_DSA_SIG(.DSA_SIG** v, const (ubyte)** pp, core.stdc.config.c_long length_);
void DSA_SIG_get0(const (.DSA_SIG)* sig, const (libressl_d.openssl.ossl_typ.BIGNUM)** pr, const (libressl_d.openssl.ossl_typ.BIGNUM)** ps);
int DSA_SIG_set0(.DSA_SIG* sig, libressl_d.openssl.ossl_typ.BIGNUM* r, libressl_d.openssl.ossl_typ.BIGNUM* s);

.DSA_SIG* DSA_do_sign(const (ubyte)* dgst, int dlen, libressl_d.openssl.ossl_typ.DSA* dsa);
int DSA_do_verify(const (ubyte)* dgst, int dgst_len, .DSA_SIG* sig, libressl_d.openssl.ossl_typ.DSA* dsa);

const (libressl_d.openssl.ossl_typ.DSA_METHOD)* DSA_OpenSSL();

void DSA_set_default_method(const (libressl_d.openssl.ossl_typ.DSA_METHOD)*);
const (libressl_d.openssl.ossl_typ.DSA_METHOD)* DSA_get_default_method();
int DSA_set_method(libressl_d.openssl.ossl_typ.DSA* dsa, const (libressl_d.openssl.ossl_typ.DSA_METHOD)*);

libressl_d.openssl.ossl_typ.DSA* DSA_new();
libressl_d.openssl.ossl_typ.DSA* DSA_new_method(libressl_d.openssl.ossl_typ.ENGINE* engine);
void DSA_free(libressl_d.openssl.ossl_typ.DSA* r);
/* "up" the DSA object's reference count */
int DSA_up_ref(libressl_d.openssl.ossl_typ.DSA* r);
int DSA_size(const (libressl_d.openssl.ossl_typ.DSA)*);
/* next 4 return -1 on error */
int DSA_sign_setup(libressl_d.openssl.ossl_typ.DSA* dsa, libressl_d.openssl.ossl_typ.BN_CTX* ctx_in, libressl_d.openssl.ossl_typ.BIGNUM** kinvp, libressl_d.openssl.ossl_typ.BIGNUM** rp);
int DSA_sign(int type, const (ubyte)* dgst, int dlen, ubyte* sig, uint* siglen, libressl_d.openssl.ossl_typ.DSA* dsa);
int DSA_verify(int type, const (ubyte)* dgst, int dgst_len, const (ubyte)* sigbuf, int siglen, libressl_d.openssl.ossl_typ.DSA* dsa);
int DSA_get_ex_new_index(core.stdc.config.c_long argl, void* argp, libressl_d.openssl.ossl_typ.CRYPTO_EX_new* new_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_dup* dup_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_free* free_func);
int DSA_set_ex_data(libressl_d.openssl.ossl_typ.DSA* d, int idx, void* arg);
void* DSA_get_ex_data(libressl_d.openssl.ossl_typ.DSA* d, int idx);

libressl_d.openssl.ossl_typ.DSA* d2i_DSAPublicKey(libressl_d.openssl.ossl_typ.DSA** a, const (ubyte)** pp, core.stdc.config.c_long length_);
int i2d_DSAPublicKey(const (libressl_d.openssl.ossl_typ.DSA)* a, ubyte** pp);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM DSAPublicKey_it;

libressl_d.openssl.ossl_typ.DSA* d2i_DSAPrivateKey(libressl_d.openssl.ossl_typ.DSA** a, const (ubyte)** pp, core.stdc.config.c_long length_);
int i2d_DSAPrivateKey(const (libressl_d.openssl.ossl_typ.DSA)* a, ubyte** pp);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM DSAPrivateKey_it;

libressl_d.openssl.ossl_typ.DSA* d2i_DSAparams(libressl_d.openssl.ossl_typ.DSA** a, const (ubyte)** pp, core.stdc.config.c_long length_);
int i2d_DSAparams(const (libressl_d.openssl.ossl_typ.DSA)* a, ubyte** pp);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM DSAparams_it;

/* Deprecated version */
//#if !defined(OPENSSL_NO_DEPRECATED)
libressl_d.openssl.ossl_typ.DSA* DSA_generate_parameters(int bits, ubyte* seed, int seed_len, int* counter_ret, core.stdc.config.c_ulong* h_ret, void function(int, int, void*) callback, void* cb_arg);
//#endif /* !defined(OPENSSL_NO_DEPRECATED) */

/* New version */
int DSA_generate_parameters_ex(libressl_d.openssl.ossl_typ.DSA* dsa, int bits, const (ubyte)* seed, int seed_len, int* counter_ret, core.stdc.config.c_ulong* h_ret, libressl_d.openssl.ossl_typ.BN_GENCB* cb);

int DSA_generate_key(libressl_d.openssl.ossl_typ.DSA* a);

//#if !defined(OPENSSL_NO_BIO)
int DSAparams_print(libressl_d.openssl.bio.BIO* bp, const (libressl_d.openssl.ossl_typ.DSA)* x);
int DSA_print(libressl_d.openssl.bio.BIO* bp, const (libressl_d.openssl.ossl_typ.DSA)* x, int off);
//#endif

int DSAparams_print_fp(libressl_d.compat.stdio.FILE* fp, const (libressl_d.openssl.ossl_typ.DSA)* x);
int DSA_print_fp(libressl_d.compat.stdio.FILE* bp, const (libressl_d.openssl.ossl_typ.DSA)* x, int off);

enum DSS_prime_checks = 50;
/*
 * Primality test according to FIPS PUB 186[-1], Appendix 2.1:
 * 50 rounds of Rabin-Miller
 */
pragma(inline, true)
int DSA_is_prime(const (libressl_d.openssl.ossl_typ.BIGNUM)* n, void function(int, int, void*) callback, void* cb_arg)

	do
	{
		return libressl_d.openssl.bn.BN_is_prime(n, .DSS_prime_checks, callback, null, cb_arg);
	}

//#if !defined(OPENSSL_NO_DH)
/*
 * Convert DSA structure (key or just parameters) into DH structure
 * (be careful to avoid small subgroup attacks when using this!)
 */
libressl_d.openssl.ossl_typ.DH* DSA_dup_DH(const (libressl_d.openssl.ossl_typ.DSA)* r);
//#endif

void DSA_get0_pqg(const (libressl_d.openssl.ossl_typ.DSA)* d, const (libressl_d.openssl.ossl_typ.BIGNUM)** p, const (libressl_d.openssl.ossl_typ.BIGNUM)** q, const (libressl_d.openssl.ossl_typ.BIGNUM)** g);
int DSA_set0_pqg(libressl_d.openssl.ossl_typ.DSA* d, libressl_d.openssl.ossl_typ.BIGNUM* p, libressl_d.openssl.ossl_typ.BIGNUM* q, libressl_d.openssl.ossl_typ.BIGNUM* g);
void DSA_get0_key(const (libressl_d.openssl.ossl_typ.DSA)* d, const (libressl_d.openssl.ossl_typ.BIGNUM)** pub_key, const (libressl_d.openssl.ossl_typ.BIGNUM)** priv_key);
int DSA_set0_key(libressl_d.openssl.ossl_typ.DSA* d, libressl_d.openssl.ossl_typ.BIGNUM* pub_key, libressl_d.openssl.ossl_typ.BIGNUM* priv_key);
void DSA_clear_flags(libressl_d.openssl.ossl_typ.DSA* d, int flags);
int DSA_test_flags(const (libressl_d.openssl.ossl_typ.DSA)* d, int flags);
void DSA_set_flags(libressl_d.openssl.ossl_typ.DSA* d, int flags);
libressl_d.openssl.ossl_typ.ENGINE* DSA_get0_engine(libressl_d.openssl.ossl_typ.DSA* d);

libressl_d.openssl.ossl_typ.DSA_METHOD* DSA_meth_new(const (char)* name, int flags);
void DSA_meth_free(libressl_d.openssl.ossl_typ.DSA_METHOD* meth);
libressl_d.openssl.ossl_typ.DSA_METHOD* DSA_meth_dup(const (libressl_d.openssl.ossl_typ.DSA_METHOD)* meth);
int DSA_meth_set_sign(libressl_d.openssl.ossl_typ.DSA_METHOD* meth, DSA_SIG* function(const (ubyte)*, int, libressl_d.openssl.ossl_typ.DSA*) sign);
int DSA_meth_set_finish(libressl_d.openssl.ossl_typ.DSA_METHOD* meth, int function(libressl_d.openssl.ossl_typ.DSA*) finish);

pragma(inline, true)
int EVP_PKEY_CTX_set_dsa_paramgen_bits(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int nbits)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_DSA, libressl_d.openssl.evp.EVP_PKEY_OP_PARAMGEN, .EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, nbits, null);
	}

enum EVP_PKEY_CTRL_DSA_PARAMGEN_BITS = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 1;
enum EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 2;
enum EVP_PKEY_CTRL_DSA_PARAMGEN_MD = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 3;

/* BEGIN ERROR CODES */
/**
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_DSA_strings();

/* Error codes for the DSA functions. */

/* Function codes. */
enum DSA_F_D2I_DSA_SIG = 110;
enum DSA_F_DO_DSA_PRINT = 104;
enum DSA_F_DSAPARAMS_PRINT = 100;
enum DSA_F_DSAPARAMS_PRINT_FP = 101;
enum DSA_F_DSA_DO_SIGN = 112;
enum DSA_F_DSA_DO_VERIFY = 113;
enum DSA_F_DSA_GENERATE_KEY = 124;
enum DSA_F_DSA_GENERATE_PARAMETERS_EX = 123;
enum DSA_F_DSA_NEW_METHOD = 103;
enum DSA_F_DSA_PARAM_DECODE = 119;
enum DSA_F_DSA_PRINT_FP = 105;
enum DSA_F_DSA_PRIV_DECODE = 115;
enum DSA_F_DSA_PRIV_ENCODE = 116;
enum DSA_F_DSA_PUB_DECODE = 117;
enum DSA_F_DSA_PUB_ENCODE = 118;
enum DSA_F_DSA_SIGN = 106;
enum DSA_F_DSA_SIGN_SETUP = 107;
enum DSA_F_DSA_SIG_NEW = 109;
enum DSA_F_DSA_SIG_PRINT = 125;
enum DSA_F_DSA_VERIFY = 108;
enum DSA_F_I2D_DSA_SIG = 111;
enum DSA_F_OLD_DSA_PRIV_DECODE = 122;
enum DSA_F_PKEY_DSA_CTRL = 120;
enum DSA_F_PKEY_DSA_KEYGEN = 121;
enum DSA_F_SIG_CB = 114;

/* Reason codes. */
enum DSA_R_BAD_Q_VALUE = 102;
enum DSA_R_BN_DECODE_ERROR = 108;
enum DSA_R_BN_ERROR = 109;
enum DSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE = 100;
enum DSA_R_DECODE_ERROR = 104;
enum DSA_R_INVALID_DIGEST_TYPE = 106;
enum DSA_R_MISSING_PARAMETERS = 101;
enum DSA_R_MODULUS_TOO_LARGE = 103;
enum DSA_R_NEED_NEW_SETUP_VALUES = 110;
enum DSA_R_NON_FIPS_DSA_METHOD = 111;
enum DSA_R_NO_PARAMETERS_SET = 107;
enum DSA_R_PARAMETER_ENCODING_ERROR = 105;
