/* $OpenBSD: ecdh.h,v 1.6 2022/07/12 14:42:49 kn Exp $ */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * The Elliptic Curve Public-Key Crypto Library (ECC Code) included
 * herein is developed by SUN MICROSYSTEMS, INC., and is contributed
 * to the OpenSSL project.
 *
 * The ECC Code is licensed pursuant to the OpenSSL open source
 * license provided below.
 *
 * The ECDH software is originally written by Douglas Stebila of
 * Sun Microsystems Laboratories.
 *
 */
/* ====================================================================
 * Copyright (c) 2000-2002 The OpenSSL Project.  All rights reserved.
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
module libressl_d.openssl.ecdh;


private static import core.stdc.config;
public import libressl_d.openssl.ec;
public import libressl_d.openssl.opensslconf;
public import libressl_d.openssl.ossl_typ;

version (OPENSSL_NO_ECDH) {
	static assert(false, "ECDH is disabled.");
}

version (OPENSSL_NO_DEPRECATED) {
} else {
	public import libressl_d.openssl.bn;
}

extern (C):
nothrow @nogc:

const (libressl_d.openssl.ossl_typ.ECDH_METHOD)* ECDH_OpenSSL();

void ECDH_set_default_method(const (libressl_d.openssl.ossl_typ.ECDH_METHOD)*);
const (libressl_d.openssl.ossl_typ.ECDH_METHOD)* ECDH_get_default_method();
int ECDH_set_method(libressl_d.openssl.ec.EC_KEY*, const (libressl_d.openssl.ossl_typ.ECDH_METHOD)*);

int ECDH_size(const (libressl_d.openssl.ec.EC_KEY)* ecdh);

private alias ECDH_compute_key_func = /* Temporary type */ extern (C) nothrow @nogc void* function(const (void)* in_, size_t inlen, void* out_, size_t* outlen);
int ECDH_compute_key(void* out_, size_t outlen, const (libressl_d.openssl.ec.EC_POINT)* pub_key, libressl_d.openssl.ec.EC_KEY* ecdh, .ECDH_compute_key_func KDF);

int ECDH_get_ex_new_index(core.stdc.config.c_long argl, void* argp, libressl_d.openssl.ossl_typ.CRYPTO_EX_new new_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_dup dup_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_free free_func);
int ECDH_set_ex_data(libressl_d.openssl.ec.EC_KEY* d, int idx, void* arg);
void* ECDH_get_ex_data(libressl_d.openssl.ec.EC_KEY* d, int idx);

void ERR_load_ECDH_strings();

/* Error codes for the ECDH functions. */

/* Function codes. */
enum ECDH_F_ECDH_CHECK = 102;
enum ECDH_F_ECDH_COMPUTE_KEY = 100;
enum ECDH_F_ECDH_DATA_NEW_METHOD = 101;

/* Reason codes. */
enum ECDH_R_KDF_FAILED = 102;
enum ECDH_R_KEY_TRUNCATION = 104;
enum ECDH_R_NON_FIPS_METHOD = 103;
enum ECDH_R_NO_PRIVATE_VALUE = 100;
enum ECDH_R_POINT_ARITHMETIC_FAILURE = 101;
