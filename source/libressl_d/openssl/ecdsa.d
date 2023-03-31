/* $OpenBSD: ecdsa.h,v 1.13 2022/12/26 07:18:51 jmc Exp $ */
/**
 * Include file for the OpenSSL ECDSA functions
 *
 * Author: Written by Nils Larsch for the OpenSSL project
 */
/* ====================================================================
 * Copyright (c) 2000-2005 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
module libressl_d.openssl.ecdsa;


private static import core.stdc.config;
public import libressl_d.openssl.ec;
public import libressl_d.openssl.opensslconf;
public import libressl_d.openssl.ossl_typ;

version (OPENSSL_NO_ECDSA) {
	static assert(false, "ECDSA is disabled.");
}

version (OPENSSL_NO_DEPRECATED) {
} else {
	public import libressl_d.openssl.bn;
}

extern (C):
nothrow @nogc:

struct ECDSA_SIG_st;
alias ECDSA_SIG = .ECDSA_SIG_st;

struct ecdsa_method
{
	const (char)* name;
	.ECDSA_SIG* function(const (ubyte)* dgst, int dgst_len, const (libressl_d.openssl.ossl_typ.BIGNUM)* inv, const (libressl_d.openssl.ossl_typ.BIGNUM)* rp, libressl_d.openssl.ec.EC_KEY* eckey) ecdsa_do_sign;
	int function(libressl_d.openssl.ec.EC_KEY* eckey, libressl_d.openssl.ossl_typ.BN_CTX* ctx, libressl_d.openssl.ossl_typ.BIGNUM** kinv, libressl_d.openssl.ossl_typ.BIGNUM** r) ecdsa_sign_setup;
	int function(const (ubyte)* dgst, int dgst_len, const (.ECDSA_SIG)* sig, libressl_d.openssl.ec.EC_KEY* eckey) ecdsa_do_verify;
	int flags;
	char* app_data;
}

/*
 * If this flag is set the ECDSA method is FIPS compliant and can be used
 * in FIPS mode. This is set in the validated module method. If an
 * application sets this flag in its own methods it is its responsibility
 * to ensure the result is compliant.
 */

enum ECDSA_FLAG_FIPS_METHOD = 0x01;

/**
 * Allocates and initialize a ECDSA_SIG structure
 *
 * Returns: pointer to a ECDSA_SIG structure or null if an error occurred
 */
.ECDSA_SIG* ECDSA_SIG_new();

/**
 * frees a ECDSA_SIG structure
 *
 * Params:
 *      sig = pointer to the ECDSA_SIG structure
 */
void ECDSA_SIG_free(.ECDSA_SIG* sig);

/**
 * DER encode content of ECDSA_SIG object (note: this function modifies *pp
 *  (*pp += length of the DER encoded signature)).
 *
 * Params:
 *      sig = pointer to the ECDSA_SIG object
 *      pp = pointer to a ubyte pointer for the output or null
 *
 * Returns: the length of the DER encoded ECDSA_SIG object or 0
 */
int i2d_ECDSA_SIG(const (.ECDSA_SIG)* sig, ubyte** pp);

/**
 * Decodes a DER encoded ECDSA signature (note: this function changes *pp
 *  (*pp += len)).
 *
 * Params:
 *      sig = pointer to ECDSA_SIG pointer (may be null)
 *      pp = memory buffer with the DER encoded signature
 *      len = length of the buffer
 *
 * Returns: pointer to the decoded ECDSA_SIG structure (or null)
 */
.ECDSA_SIG* d2i_ECDSA_SIG(.ECDSA_SIG** sig, const (ubyte)** pp, core.stdc.config.c_long len);

/**
 * Accessor for r and s fields of ECDSA_SIG
 *
 * Params:
 *      sig = pointer to ECDSA_SIG pointer
 *      pr = pointer to BIGNUM pointer for r (may be null)
 *      ps = pointer to BIGNUM pointer for s (may be null)
 */
void ECDSA_SIG_get0(const (.ECDSA_SIG)* sig, const (libressl_d.openssl.ossl_typ.BIGNUM)** pr, const (libressl_d.openssl.ossl_typ.BIGNUM)** ps);

const (libressl_d.openssl.ossl_typ.BIGNUM)* ECDSA_SIG_get0_r(const (.ECDSA_SIG)* sig);
const (libressl_d.openssl.ossl_typ.BIGNUM)* ECDSA_SIG_get0_s(const (.ECDSA_SIG)* sig);

/**
 * Setter for r and s fields of ECDSA_SIG
 *
 * Params:
 *      sig = pointer to ECDSA_SIG pointer
 *      r = pointer to BIGNUM for r (may be null)
 *      s = pointer to BIGNUM for s (may be null)
 */
int ECDSA_SIG_set0(.ECDSA_SIG* sig, libressl_d.openssl.ossl_typ.BIGNUM* r, libressl_d.openssl.ossl_typ.BIGNUM* s);

/**
 * Computes the ECDSA signature of the given hash value using the supplied private key and returns the created signature.
 *
 * Params:
 *      dgst = pointer to the hash value
 *      dgst_len = length of the hash value
 *      eckey = EC_KEY object containing a private EC key
 *
 * Returns: pointer to a ECDSA_SIG structure or null if an error occurred
 */
.ECDSA_SIG* ECDSA_do_sign(const (ubyte)* dgst, int dgst_len, libressl_d.openssl.ec.EC_KEY* eckey);

/**
 * Computes ECDSA signature of a given hash value using the supplied private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
 *
 * Params:
 *      dgst = pointer to the hash value to sign
 *      dgstlen = length of the hash value
 *      kinv = BIGNUM with a pre-computed inverse k (optional)
 *      rp = BIGNUM with a pre-computed rp value (optional), see ECDSA_sign_setup
 *      eckey = EC_KEY object containing a private EC key
 *
 * Returns: pointer to a ECDSA_SIG structure or null if an error occurred
 */
.ECDSA_SIG* ECDSA_do_sign_ex(const (ubyte)* dgst, int dgstlen, const (libressl_d.openssl.ossl_typ.BIGNUM)* kinv, const (libressl_d.openssl.ossl_typ.BIGNUM)* rp, libressl_d.openssl.ec.EC_KEY* eckey);

/**
 * Verifies that the supplied signature is a valid ECDSA signature of the supplied hash value using the supplied public key.
 *
 * Params:
 *      dgst = pointer to the hash value
 *      dgst_len = length of the hash value
 *      sig = ECDSA_SIG structure
 *      eckey = EC_KEY object containing a public EC key
 *
 * Returns: 1 if the signature is valid, 0 if the signature is invalid and -1 on error
 */
int ECDSA_do_verify(const (ubyte)* dgst, int dgst_len, const (.ECDSA_SIG)* sig, libressl_d.openssl.ec.EC_KEY* eckey);

const (libressl_d.openssl.ossl_typ.ECDSA_METHOD)* ECDSA_OpenSSL();

/**
 * Sets the default ECDSA method
 *
 * Params:
 *      meth = new default ECDSA_METHOD
 */
void ECDSA_set_default_method(const (libressl_d.openssl.ossl_typ.ECDSA_METHOD)* meth);

/**
 * Returns the default ECDSA method
 *
 * Returns: pointer to ECDSA_METHOD structure containing the default method
 */
const (libressl_d.openssl.ossl_typ.ECDSA_METHOD)* ECDSA_get_default_method();

/**
 * Sets method to be used for the ECDSA operations
 *
 * Params:
 *      eckey = EC_KEY object
 *      meth = new method
 *
 * Returns: 1 on success and 0 otherwise
 */
int ECDSA_set_method(libressl_d.openssl.ec.EC_KEY* eckey, const (libressl_d.openssl.ossl_typ.ECDSA_METHOD)* meth);

/**
 * Returns the maximum length of the DER encoded signature
 *
 * Params:
 *      eckey = EC_KEY object
 *
 * Returns: numbers of bytes required for the DER encoded signature
 */
int ECDSA_size(const (libressl_d.openssl.ec.EC_KEY)* eckey);

/**
 * Precompute parts of the signing operation
 *
 * Params:
 *      eckey = EC_KEY object containing a private EC key
 *      ctx = BN_CTX object (optional)
 *      kinv = BIGNUM pointer for the inverse of k
 *      rp = BIGNUM pointer for x coordinate of k * generator
 *
 * Returns: 1 on success and 0 otherwise
 */
int ECDSA_sign_setup(libressl_d.openssl.ec.EC_KEY* eckey, libressl_d.openssl.ossl_typ.BN_CTX* ctx, libressl_d.openssl.ossl_typ.BIGNUM** kinv, libressl_d.openssl.ossl_typ.BIGNUM** rp);

/**
 * Computes ECDSA signature of a given hash value using the supplied private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
 *
 * Params:
 *      type = this parameter is ignored
 *      dgst = pointer to the hash value to sign
 *      dgstlen = length of the hash value
 *      sig = memory for the DER encoded created signature
 *      siglen = pointer to the length of the returned signature
 *      eckey = EC_KEY object containing a private EC key
 *
 * Returns: 1 on success and 0 otherwise
 */
int ECDSA_sign(int type, const (ubyte)* dgst, int dgstlen, ubyte* sig, uint* siglen, libressl_d.openssl.ec.EC_KEY* eckey);

/**
 * Computes ECDSA signature of a given hash value using the supplied private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
 *
 * Params:
 *      type = this parameter is ignored
 *      dgst = pointer to the hash value to sign
 *      dgstlen = length of the hash value
 *      sig = buffer to hold the DER encoded signature
 *      siglen = pointer to the length of the returned signature
 *      kinv = BIGNUM with a pre-computed inverse k (optional)
 *      rp = BIGNUM with a pre-computed rp value (optional), see ECDSA_sign_setup
 *      eckey = EC_KEY object containing a private EC key
 *
 * Returns: 1 on success and 0 otherwise
 */
int ECDSA_sign_ex(int type, const (ubyte)* dgst, int dgstlen, ubyte* sig, uint* siglen, const (libressl_d.openssl.ossl_typ.BIGNUM)* kinv, const (libressl_d.openssl.ossl_typ.BIGNUM)* rp, libressl_d.openssl.ec.EC_KEY* eckey);

/**
 * Verifies that the given signature is valid ECDSA signature of the supplied hash value using the specified public key.
 *
 * Params:
 *      type = this parameter is ignored
 *      dgst = pointer to the hash value
 *      dgstlen = length of the hash value
 *      sig = pointer to the DER encoded signature
 *      siglen = length of the DER encoded signature
 *      eckey = EC_KEY object containing a public EC key
 *
 * Returns: 1 if the signature is valid, 0 if the signature is invalid and -1 on error
 */
int ECDSA_verify(int type, const (ubyte)* dgst, int dgstlen, const (ubyte)* sig, int siglen, libressl_d.openssl.ec.EC_KEY* eckey);

/* the standard ex_data functions */
int ECDSA_get_ex_new_index(core.stdc.config.c_long argl, void* argp, libressl_d.openssl.ossl_typ.CRYPTO_EX_new new_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_dup dup_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_free free_func);
int ECDSA_set_ex_data(libressl_d.openssl.ec.EC_KEY* d, int idx, void* arg);
void* ECDSA_get_ex_data(libressl_d.openssl.ec.EC_KEY* d, int idx);

/* XXX should be in ec.h, but needs ECDSA_SIG */

private alias EC_KEY_METHOD_set_sign_func1 = /* Temporary type */ extern (C) nothrow @nogc int function(int type, const (ubyte)* dgst, int dlen, ubyte* sig, uint* siglen, const (libressl_d.openssl.ossl_typ.BIGNUM)* kinv, const (libressl_d.openssl.ossl_typ.BIGNUM)* r, libressl_d.openssl.ec.EC_KEY* eckey);
private alias EC_KEY_METHOD_set_sign_func2 = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ec.EC_KEY* eckey, libressl_d.openssl.ossl_typ.BN_CTX* ctx_in, libressl_d.openssl.ossl_typ.BIGNUM** kinvp, libressl_d.openssl.ossl_typ.BIGNUM** rp);
private alias EC_KEY_METHOD_set_sign_func3 = /* Temporary type */ extern (C) nothrow @nogc .ECDSA_SIG* function(const (ubyte)* dgst, int dgst_len, const (libressl_d.openssl.ossl_typ.BIGNUM)* in_kinv, const (libressl_d.openssl.ossl_typ.BIGNUM)* in_r, libressl_d.openssl.ec.EC_KEY* eckey);
void EC_KEY_METHOD_set_sign(libressl_d.openssl.ec.EC_KEY_METHOD* meth, .EC_KEY_METHOD_set_sign_func1 sign, .EC_KEY_METHOD_set_sign_func2 sign_setup, .EC_KEY_METHOD_set_sign_func3 sign_sig);

private alias EC_KEY_METHOD_set_verify_func1 = /* Temporary type */ extern (C) nothrow @nogc int function(int type, const (ubyte)* dgst, int dgst_len, const (ubyte)* sigbuf, int sig_len, libressl_d.openssl.ec.EC_KEY* eckey);
private alias EC_KEY_METHOD_set_verify_func2 = /* Temporary type */ extern (C) nothrow @nogc int function(const (ubyte)* dgst, int dgst_len, const (.ECDSA_SIG)* sig, libressl_d.openssl.ec.EC_KEY* eckey);
void EC_KEY_METHOD_set_verify(libressl_d.openssl.ec.EC_KEY_METHOD* meth, .EC_KEY_METHOD_set_verify_func1 verify, .EC_KEY_METHOD_set_verify_func2 verify_sig);

private alias EC_KEY_METHOD_get_sign_func1 = /* Temporary type */ extern (C) nothrow @nogc int function(int type, const (ubyte)* dgst, int dlen, ubyte* sig, uint* siglen, const (libressl_d.openssl.ossl_typ.BIGNUM)* kinv, const (libressl_d.openssl.ossl_typ.BIGNUM)* r, libressl_d.openssl.ec.EC_KEY* eckey);
private alias EC_KEY_METHOD_get_sign_func2 = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ec.EC_KEY* eckey, libressl_d.openssl.ossl_typ.BN_CTX* ctx_in, libressl_d.openssl.ossl_typ.BIGNUM** kinvp, libressl_d.openssl.ossl_typ.BIGNUM** rp);
private alias EC_KEY_METHOD_get_sign_func3 = /* Temporary type */ extern (C) nothrow @nogc .ECDSA_SIG* function(const (ubyte)* dgst, int dgst_len, const (libressl_d.openssl.ossl_typ.BIGNUM)* in_kinv, const (libressl_d.openssl.ossl_typ.BIGNUM)* in_r, libressl_d.openssl.ec.EC_KEY* eckey);
void EC_KEY_METHOD_get_sign(const (libressl_d.openssl.ec.EC_KEY_METHOD)* meth, .EC_KEY_METHOD_get_sign_func1* psign, .EC_KEY_METHOD_get_sign_func2* psign_setup, .EC_KEY_METHOD_get_sign_func3* psign_sig);

private alias EC_KEY_METHOD_get_verify_func1 = /* Temporary type */ extern (C) nothrow @nogc int function(int type, const (ubyte)* dgst, int dgst_len, const (ubyte)* sigbuf, int sig_len, libressl_d.openssl.ec.EC_KEY* eckey);
private alias EC_KEY_METHOD_get_verify_func2 = /* Temporary type */ extern (C) nothrow @nogc int function(const (ubyte)* dgst, int dgst_len, const (.ECDSA_SIG)* sig, libressl_d.openssl.ec.EC_KEY* eckey);
void EC_KEY_METHOD_get_verify(const (libressl_d.openssl.ec.EC_KEY_METHOD)* meth, .EC_KEY_METHOD_get_verify_func1* pverify, .EC_KEY_METHOD_get_verify_func2* pverify_sig);

void ERR_load_ECDSA_strings();

/* Error codes for the ECDSA functions. */

/* Function codes. */
enum ECDSA_F_ECDSA_CHECK = 104;
enum ECDSA_F_ECDSA_DATA_NEW_METHOD = 100;
enum ECDSA_F_ECDSA_DO_SIGN = 101;
enum ECDSA_F_ECDSA_DO_VERIFY = 102;
enum ECDSA_F_ECDSA_SIGN_SETUP = 103;

/* Reason codes. */
enum ECDSA_R_BAD_SIGNATURE = 100;
enum ECDSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE = 101;
enum ECDSA_R_ERR_EC_LIB = 102;
enum ECDSA_R_MISSING_PARAMETERS = 103;
enum ECDSA_R_NEED_NEW_SETUP_VALUES = 106;
enum ECDSA_R_NON_FIPS_METHOD = 107;
enum ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED = 104;
enum ECDSA_R_SIGNATURE_MALLOC_FAILED = 105;
