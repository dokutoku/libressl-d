/* $OpenBSD: ecdsa.h,v 1.8 2019/01/19 01:17:41 tb Exp $ */
/**
 * \file   crypto/ecdsa/ecdsa.h Include file for the OpenSSL ECDSA functions
 * \author Written by Nils Larsch for the OpenSSL project
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
public import libressl_d.openssl.bn;
public import libressl_d.openssl.ec;
public import libressl_d.openssl.opensslconf;
public import libressl_d.openssl.ossl_typ;

version (OPENSSL_NO_ECDSA) {
	//static assert(false, "ECDSA is disabled.");
}

//#if !defined(OPENSSL_NO_DEPRECATED)
	//public import libressl_d.openssl.bn;
//#endif

extern (C):
nothrow @nogc:

alias ECDSA_SIG = .ECDSA_SIG_st;

struct ecdsa_method
{
	const (char)* name;
	.ECDSA_SIG* function(const (ubyte)* dgst, int dgst_len, const (libressl_d.openssl.ossl_typ.BIGNUM)* inv, const (libressl_d.openssl.ossl_typ.BIGNUM)* rp, libressl_d.openssl.ec.EC_KEY* eckey) ecdsa_do_sign;
	int function(libressl_d.openssl.ec.EC_KEY* eckey, libressl_d.openssl.ossl_typ.BN_CTX* ctx, libressl_d.openssl.ossl_typ.BIGNUM** kinv, libressl_d.openssl.ossl_typ.BIGNUM** r) ecdsa_sign_setup;
	int function(const (ubyte)* dgst, int dgst_len, const (.ECDSA_SIG)* sig, libressl_d.openssl.ec.EC_KEY* eckey) ecdsa_do_verify;

	version (none) {
		int function(libressl_d.openssl.ec.EC_KEY* eckey) init;
		int function(libressl_d.openssl.ec.EC_KEY* eckey) finish;
	}

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

struct ECDSA_SIG_st
{
	libressl_d.openssl.ossl_typ.BIGNUM* r;
	libressl_d.openssl.ossl_typ.BIGNUM* s;
}

/**
 * Allocates and initialize a ECDSA_SIG structure
 *  \return pointer to a ECDSA_SIG structure or null if an error occurred
 */
.ECDSA_SIG* ECDSA_SIG_new();

/**
 * frees a ECDSA_SIG structure
 *  \param  sig  pointer to the ECDSA_SIG structure
 */
void ECDSA_SIG_free(.ECDSA_SIG* sig);

/**
 * DER encode content of ECDSA_SIG object (note: this function modifies *pp
 *  (*pp += length of the DER encoded signature)).
 *  \param  sig  pointer to the ECDSA_SIG object
 *  \param  pp   pointer to a ubyte pointer for the output or null
 *  \return the length of the DER encoded ECDSA_SIG object or 0
 */
int i2d_ECDSA_SIG(const (.ECDSA_SIG)* sig, ubyte** pp);

/**
 * Decodes a DER encoded ECDSA signature (note: this function changes *pp
 *  (*pp += len)).
 *  \param  sig  pointer to ECDSA_SIG pointer (may be null)
 *  \param  pp   memory buffer with the DER encoded signature
 *  \param  len  length of the buffer
 *  \return pointer to the decoded ECDSA_SIG structure (or null)
 */
.ECDSA_SIG* d2i_ECDSA_SIG(.ECDSA_SIG** sig, const (ubyte)** pp, core.stdc.config.c_long len);

/**
 * Accessor for r and s fields of ECDSA_SIG
 *  \param  sig  pointer to ECDSA_SIG pointer
 *  \param  pr   pointer to BIGNUM pointer for r (may be null)
 *  \param  ps   pointer to BIGNUM pointer for s (may be null)
 */
void ECDSA_SIG_get0(const (.ECDSA_SIG)* sig, const (libressl_d.openssl.ossl_typ.BIGNUM)** pr, const (libressl_d.openssl.ossl_typ.BIGNUM)** ps);

/**
 * Setter for r and s fields of ECDSA_SIG
 *  \param  sig  pointer to ECDSA_SIG pointer
 *  \param  r    pointer to BIGNUM for r (may be null)
 *  \param  s    pointer to BIGNUM for s (may be null)
 */
int ECDSA_SIG_set0(.ECDSA_SIG* sig, libressl_d.openssl.ossl_typ.BIGNUM* r, libressl_d.openssl.ossl_typ.BIGNUM* s);

/**
 * Computes the ECDSA signature of the given hash value using
 *  the supplied private key and returns the created signature.
 *  \param  dgst      pointer to the hash value
 *  \param  dgst_len  length of the hash value
 *  \param  eckey     EC_KEY object containing a private EC key
 *  \return pointer to a ECDSA_SIG structure or null if an error occurred
 */
.ECDSA_SIG* ECDSA_do_sign(const (ubyte)* dgst, int dgst_len, libressl_d.openssl.ec.EC_KEY* eckey);

/**
 * Computes ECDSA signature of a given hash value using the supplied
 *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
 *  \param  dgst     pointer to the hash value to sign
 *  \param  dgstlen  length of the hash value
 *  \param  kinv     BIGNUM with a pre-computed inverse k (optional)
 *  \param  rp       BIGNUM with a pre-computed rp value (optioanl),
 *                   see ECDSA_sign_setup
 *  \param  eckey    EC_KEY object containing a private EC key
 *  \return pointer to a ECDSA_SIG structure or null if an error occurred
 */
.ECDSA_SIG* ECDSA_do_sign_ex(const (ubyte)* dgst, int dgstlen, const (libressl_d.openssl.ossl_typ.BIGNUM)* kinv, const (libressl_d.openssl.ossl_typ.BIGNUM)* rp, libressl_d.openssl.ec.EC_KEY* eckey);

/**
 * Verifies that the supplied signature is a valid ECDSA
 *  signature of the supplied hash value using the supplied public key.
 *  \param  dgst      pointer to the hash value
 *  \param  dgst_len  length of the hash value
 *  \param  sig       ECDSA_SIG structure
 *  \param  eckey     EC_KEY object containing a public EC key
 *  \return 1 if the signature is valid, 0 if the signature is invalid
 *          and -1 on error
 */
int ECDSA_do_verify(const (ubyte)* dgst, int dgst_len, const (.ECDSA_SIG)* sig, libressl_d.openssl.ec.EC_KEY* eckey);

const (libressl_d.openssl.ossl_typ.ECDSA_METHOD)* ECDSA_OpenSSL();

/**
 * Sets the default ECDSA method
 *  \param  meth  new default ECDSA_METHOD
 */
void ECDSA_set_default_method(const (libressl_d.openssl.ossl_typ.ECDSA_METHOD)* meth);

/**
 * Returns the default ECDSA method
 *  \return pointer to ECDSA_METHOD structure containing the default method
 */
const (libressl_d.openssl.ossl_typ.ECDSA_METHOD)* ECDSA_get_default_method();

/**
 * Sets method to be used for the ECDSA operations
 *  \param  eckey  EC_KEY object
 *  \param  meth   new method
 *  \return 1 on success and 0 otherwise
 */
int ECDSA_set_method(libressl_d.openssl.ec.EC_KEY* eckey, const (libressl_d.openssl.ossl_typ.ECDSA_METHOD)* meth);

/**
 * Returns the maximum length of the DER encoded signature
 *  \param  eckey  EC_KEY object
 *  \return numbers of bytes required for the DER encoded signature
 */
int ECDSA_size(const (libressl_d.openssl.ec.EC_KEY)* eckey);

/**
 * Precompute parts of the signing operation
 *  \param  eckey  EC_KEY object containing a private EC key
 *  \param  ctx    BN_CTX object (optional)
 *  \param  kinv   BIGNUM pointer for the inverse of k
 *  \param  rp     BIGNUM pointer for x coordinate of k * generator
 *  \return 1 on success and 0 otherwise
 */
int ECDSA_sign_setup(libressl_d.openssl.ec.EC_KEY* eckey, libressl_d.openssl.ossl_typ.BN_CTX* ctx, libressl_d.openssl.ossl_typ.BIGNUM** kinv, libressl_d.openssl.ossl_typ.BIGNUM** rp);

/**
 * Computes ECDSA signature of a given hash value using the supplied
 *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
 *  \param  type     this parameter is ignored
 *  \param  dgst     pointer to the hash value to sign
 *  \param  dgstlen  length of the hash value
 *  \param  sig      memory for the DER encoded created signature
 *  \param  siglen   pointer to the length of the returned signature
 *  \param  eckey    EC_KEY object containing a private EC key
 *  \return 1 on success and 0 otherwise
 */
int ECDSA_sign(int type, const (ubyte)* dgst, int dgstlen, ubyte* sig, uint* siglen, libressl_d.openssl.ec.EC_KEY* eckey);

/**
 * Computes ECDSA signature of a given hash value using the supplied
 *  private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
 *  \param  type     this parameter is ignored
 *  \param  dgst     pointer to the hash value to sign
 *  \param  dgstlen  length of the hash value
 *  \param  sig      buffer to hold the DER encoded signature
 *  \param  siglen   pointer to the length of the returned signature
 *  \param  kinv     BIGNUM with a pre-computed inverse k (optional)
 *  \param  rp       BIGNUM with a pre-computed rp value (optioanl),
 *                   see ECDSA_sign_setup
 *  \param  eckey    EC_KEY object containing a private EC key
 *  \return 1 on success and 0 otherwise
 */
int ECDSA_sign_ex(int type, const (ubyte)* dgst, int dgstlen, ubyte* sig, uint* siglen, const (libressl_d.openssl.ossl_typ.BIGNUM)* kinv, const (libressl_d.openssl.ossl_typ.BIGNUM)* rp, libressl_d.openssl.ec.EC_KEY* eckey);

/**
 * Verifies that the given signature is valid ECDSA signature
 *  of the supplied hash value using the specified public key.
 *  \param  type     this parameter is ignored
 *  \param  dgst     pointer to the hash value
 *  \param  dgstlen  length of the hash value
 *  \param  sig      pointer to the DER encoded signature
 *  \param  siglen   length of the DER encoded signature
 *  \param  eckey    EC_KEY object containing a public EC key
 *  \return 1 if the signature is valid, 0 if the signature is invalid
 *          and -1 on error
 */
int ECDSA_verify(int type, const (ubyte)* dgst, int dgstlen, const (ubyte)* sig, int siglen, libressl_d.openssl.ec.EC_KEY* eckey);

/* the standard ex_data functions */
int ECDSA_get_ex_new_index(core.stdc.config.c_long argl, void* argp, libressl_d.openssl.ossl_typ.CRYPTO_EX_new* new_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_dup* dup_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_free* free_func);
int ECDSA_set_ex_data(libressl_d.openssl.ec.EC_KEY* d, int idx, void* arg);
void* ECDSA_get_ex_data(libressl_d.openssl.ec.EC_KEY* d, int idx);

/* XXX should be in ec.h, but needs ECDSA_SIG */
void EC_KEY_METHOD_set_sign(libressl_d.openssl.ec.EC_KEY_METHOD* meth, int function(int type, const (ubyte)* dgst, int dlen, ubyte* sig, uint* siglen, const (libressl_d.openssl.ossl_typ.BIGNUM)* kinv, const (libressl_d.openssl.ossl_typ.BIGNUM)* r, libressl_d.openssl.ec.EC_KEY* eckey) sign, int function(libressl_d.openssl.ec.EC_KEY* eckey, libressl_d.openssl.ossl_typ.BN_CTX* ctx_in, libressl_d.openssl.ossl_typ.BIGNUM** kinvp, libressl_d.openssl.ossl_typ.BIGNUM** rp) sign_setup, .ECDSA_SIG* function(const (ubyte)* dgst, int dgst_len, const (libressl_d.openssl.ossl_typ.BIGNUM)* in_kinv, const (libressl_d.openssl.ossl_typ.BIGNUM)* in_r, libressl_d.openssl.ec.EC_KEY* eckey) sign_sig);
void EC_KEY_METHOD_set_verify(libressl_d.openssl.ec.EC_KEY_METHOD* meth, int function(int type, const (ubyte)* dgst, int dgst_len, const (ubyte)* sigbuf, int sig_len, libressl_d.openssl.ec.EC_KEY* eckey) verify, int function(const (ubyte)* dgst, int dgst_len, const (.ECDSA_SIG)* sig, libressl_d.openssl.ec.EC_KEY* eckey) verify_sig);
void EC_KEY_METHOD_get_sign(const (libressl_d.openssl.ec.EC_KEY_METHOD)* meth, int function(int type, const (ubyte)* dgst, int dlen, ubyte* sig, uint* siglen, const (libressl_d.openssl.ossl_typ.BIGNUM)* kinv, const (libressl_d.openssl.ossl_typ.BIGNUM)* r, libressl_d.openssl.ec.EC_KEY* eckey)* psign, int function(libressl_d.openssl.ec.EC_KEY* eckey, libressl_d.openssl.ossl_typ.BN_CTX* ctx_in, libressl_d.openssl.ossl_typ.BIGNUM** kinvp, libressl_d.openssl.ossl_typ.BIGNUM** rp)* psign_setup, .ECDSA_SIG* function(const (ubyte)* dgst, int dgst_len, const (libressl_d.openssl.ossl_typ.BIGNUM)* in_kinv, const (libressl_d.openssl.ossl_typ.BIGNUM)* in_r, libressl_d.openssl.ec.EC_KEY* eckey)* psign_sig);
void EC_KEY_METHOD_get_verify(const (libressl_d.openssl.ec.EC_KEY_METHOD)* meth, int function(int type, const (ubyte)* dgst, int dgst_len, const (ubyte)* sigbuf, int sig_len, libressl_d.openssl.ec.EC_KEY* eckey)* pverify, int function(const (ubyte)* dgst, int dgst_len, const (.ECDSA_SIG)* sig, libressl_d.openssl.ec.EC_KEY* eckey)* pverify_sig);

/* BEGIN ERROR CODES */
/**
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
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
