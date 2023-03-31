/*	$OpenBSD: kdf.h,v 1.8 2022/07/12 14:42:49 kn Exp $ */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2016-2018 The OpenSSL Project.  All rights reserved.
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
 */
module libressl.openssl.kdf;


private static import libressl.openssl.evp;
private static import libressl.openssl.ossl_typ;

extern (C):
nothrow @nogc:

///
enum EVP_PKEY_CTRL_HKDF_MD = libressl.openssl.evp.EVP_PKEY_ALG_CTRL + 3;

///Ditto
enum EVP_PKEY_CTRL_HKDF_SALT = libressl.openssl.evp.EVP_PKEY_ALG_CTRL + 4;

///Ditto
enum EVP_PKEY_CTRL_HKDF_KEY = libressl.openssl.evp.EVP_PKEY_ALG_CTRL + 5;

///Ditto
enum EVP_PKEY_CTRL_HKDF_INFO = libressl.openssl.evp.EVP_PKEY_ALG_CTRL + 6;

///Ditto
enum EVP_PKEY_CTRL_HKDF_MODE = libressl.openssl.evp.EVP_PKEY_ALG_CTRL + 7;

///
enum EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND = 0;

///Ditto
enum EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY = 1;

///Ditto
enum EVP_PKEY_HKDEF_MODE_EXPAND_ONLY = 2;

pragma(inline, true)
int EVP_PKEY_CTX_set_hkdf_md(libressl.openssl.ossl_typ.EVP_PKEY_CTX* pctx, void* md)

	do
	{
		return libressl.openssl.evp.EVP_PKEY_CTX_ctrl(pctx, -1, libressl.openssl.evp.EVP_PKEY_OP_DERIVE, .EVP_PKEY_CTRL_HKDF_MD, 0, cast(void*)(md));
	}

pragma(inline, true)
int EVP_PKEY_CTX_set1_hkdf_salt(libressl.openssl.ossl_typ.EVP_PKEY_CTX* pctx, void* salt, int saltlen)

	do
	{
		return libressl.openssl.evp.EVP_PKEY_CTX_ctrl(pctx, -1, libressl.openssl.evp.EVP_PKEY_OP_DERIVE, .EVP_PKEY_CTRL_HKDF_SALT, saltlen, cast(void*)(salt));
	}

pragma(inline, true)
int EVP_PKEY_CTX_set1_hkdf_key(libressl.openssl.ossl_typ.EVP_PKEY_CTX* pctx, void* key, int keylen)

	do
	{
		return libressl.openssl.evp.EVP_PKEY_CTX_ctrl(pctx, -1, libressl.openssl.evp.EVP_PKEY_OP_DERIVE, .EVP_PKEY_CTRL_HKDF_KEY, keylen, cast(void*)(key));
	}

pragma(inline, true)
int EVP_PKEY_CTX_add1_hkdf_info(libressl.openssl.ossl_typ.EVP_PKEY_CTX* pctx, void* info, int infolen)

	do
	{
		return libressl.openssl.evp.EVP_PKEY_CTX_ctrl(pctx, -1, libressl.openssl.evp.EVP_PKEY_OP_DERIVE, .EVP_PKEY_CTRL_HKDF_INFO, infolen, cast(void*)(info));
	}

pragma(inline, true)
int EVP_PKEY_CTX_hkdf_mode(libressl.openssl.ossl_typ.EVP_PKEY_CTX* pctx, int mode)

	do
	{
		return libressl.openssl.evp.EVP_PKEY_CTX_ctrl(pctx, -1, libressl.openssl.evp.EVP_PKEY_OP_DERIVE, .EVP_PKEY_CTRL_HKDF_MODE, mode, null);
	}

int ERR_load_KDF_strings();

/**
 * KDF function codes.
 */
enum KDF_F_PKEY_HKDF_CTRL_STR = 103;

///Ditto
enum KDF_F_PKEY_HKDF_DERIVE = 102;

///Ditto
enum KDF_F_PKEY_HKDF_INIT = 108;

/**
 * KDF reason codes.
 */
enum KDF_R_MISSING_KEY = 104;

///Ditto
enum KDF_R_MISSING_MESSAGE_DIGEST = 105;

///Ditto
enum KDF_R_UNKNOWN_PARAMETER_TYPE = 103;
