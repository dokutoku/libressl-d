/* $OpenBSD: hmac.h,v 1.16 2022/01/14 08:06:03 tb Exp $ */
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
module libressl.openssl.hmac;


private static import core.stdc.config;
private static import libressl.openssl.ossl_typ;
public import libressl.openssl.evp;
public import libressl.openssl.opensslconf;

version (OPENSSL_NO_HMAC) {
	static assert(false, "HMAC is disabled.");
}

/**
 * largest known is SHA512
 */
enum HMAC_MAX_MD_CBLOCK = 128;

extern (C):
nothrow @nogc:

alias HMAC_CTX = .hmac_ctx_st;

pragma(inline, true)
int HMAC_size(const (libressl.openssl.ossl_typ.HMAC_CTX)* e)

	do
	{
		return libressl.openssl.evp.EVP_MD_size(.HMAC_CTX_get_md(e));
	}

libressl.openssl.ossl_typ.HMAC_CTX* HMAC_CTX_new();
void HMAC_CTX_free(libressl.openssl.ossl_typ.HMAC_CTX* ctx);
int HMAC_CTX_reset(libressl.openssl.ossl_typ.HMAC_CTX* ctx);

deprecated
int HMAC_Init(libressl.openssl.ossl_typ.HMAC_CTX* ctx, const (void)* key, int len, const (libressl.openssl.ossl_typ.EVP_MD)* md);

int HMAC_Init_ex(libressl.openssl.ossl_typ.HMAC_CTX* ctx, const (void)* key, int len, const (libressl.openssl.ossl_typ.EVP_MD)* md, libressl.openssl.ossl_typ.ENGINE* impl);
int HMAC_Update(libressl.openssl.ossl_typ.HMAC_CTX* ctx, const (ubyte)* data, size_t len);
int HMAC_Final(libressl.openssl.ossl_typ.HMAC_CTX* ctx, ubyte* md, uint* len);
ubyte* HMAC(const (libressl.openssl.ossl_typ.EVP_MD)* evp_md, const (void)* key, int key_len, const (ubyte)* d, size_t n, ubyte* md, uint* md_len);
int HMAC_CTX_copy(libressl.openssl.ossl_typ.HMAC_CTX* dctx, libressl.openssl.ossl_typ.HMAC_CTX* sctx);

void HMAC_CTX_set_flags(libressl.openssl.ossl_typ.HMAC_CTX* ctx, core.stdc.config.c_ulong flags);
const (libressl.openssl.ossl_typ.EVP_MD)* HMAC_CTX_get_md(const (libressl.openssl.ossl_typ.HMAC_CTX)* ctx);
