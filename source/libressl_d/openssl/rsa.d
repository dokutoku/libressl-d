/* $OpenBSD: rsa.h,v 1.58 2022/07/12 14:42:50 kn Exp $ */
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
module libressl_d.openssl.rsa;


private static import core.stdc.config;
private static import libressl_d.compat.stdio;
private static import libressl_d.openssl.evp;
public import libressl_d.openssl.asn1;
public import libressl_d.openssl.crypto;
public import libressl_d.openssl.opensslconf;
public import libressl_d.openssl.ossl_typ;

version (OPENSSL_NO_BIO) {
} else {
	public import libressl_d.openssl.bio;
}

version (OPENSSL_NO_DEPRECATED) {
} else {
	public import libressl_d.openssl.bn;
}

version (OPENSSL_NO_RSA) {
	static assert(false, "RSA is disabled.");
}

extern (C):
nothrow @nogc:

struct rsa_pss_params_st
{
	libressl_d.openssl.ossl_typ.X509_ALGOR* hashAlgorithm;
	libressl_d.openssl.ossl_typ.X509_ALGOR* maskGenAlgorithm;
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* saltLength;
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* trailerField;

	/* Hash algorithm decoded from maskGenAlgorithm. */
	libressl_d.openssl.ossl_typ.X509_ALGOR* maskHash;
}

/* alias RSA_PSS_PARAMS = .rsa_pss_params_st; */

struct rsa_oaep_params_st
{
	libressl_d.openssl.ossl_typ.X509_ALGOR* hashFunc;
	libressl_d.openssl.ossl_typ.X509_ALGOR* maskGenFunc;
	libressl_d.openssl.ossl_typ.X509_ALGOR* pSourceFunc;

	/* Hash algorithm decoded from maskGenFunc. */
	libressl_d.openssl.ossl_typ.X509_ALGOR* maskHash;
}

alias RSA_OAEP_PARAMS = .rsa_oaep_params_st;

//#if !defined(OPENSSL_RSA_MAX_MODULUS_BITS)
	enum OPENSSL_RSA_MAX_MODULUS_BITS = 16384;
//#endif

//#if !defined(OPENSSL_RSA_SMALL_MODULUS_BITS)
	enum OPENSSL_RSA_SMALL_MODULUS_BITS = 3072;
//#endif

//#if !defined(OPENSSL_RSA_MAX_PUBEXP_BITS)
	/**
	 * exponent limit enforced for "large" modulus only
	 */
	enum OPENSSL_RSA_MAX_PUBEXP_BITS = 64;
//#endif

enum RSA_3 = 0x03L;
enum RSA_F4 = 0x010001L;

/**
 * Don't check pub/private match.
 */
enum RSA_METHOD_FLAG_NO_CHECK = 0x0001;

enum RSA_FLAG_CACHE_PUBLIC = 0x0002;
enum RSA_FLAG_CACHE_PRIVATE = 0x0004;
enum RSA_FLAG_BLINDING = 0x0008;
enum RSA_FLAG_THREAD_SAFE = 0x0010;

/**
 * This flag means the private key operations will be handled by rsa_mod_exp
 * and that they do not depend on the private key components being present:
 * for example a key stored in external hardware. Without this flag bn_mod_exp
 * gets called when private key components are absent.
 */
enum RSA_FLAG_EXT_PKEY = 0x0020;

/**
 * This flag in the RSA_METHOD enables the new rsa_sign, rsa_verify functions.
 */
enum RSA_FLAG_SIGN_VER = 0x0040;

/**
 * The built-in RSA implementation uses blinding by default, but other engines
 * might not need it.
 */
enum RSA_FLAG_NO_BLINDING = 0x0080;

/**
 * Salt length matches digest
 */
enum RSA_PSS_SALTLEN_DIGEST = -1;

/**
 * Verify only: auto detect salt length
 */
enum RSA_PSS_SALTLEN_AUTO = -2;

/**
 * Set salt length to maximum possible
 */
enum RSA_PSS_SALTLEN_MAX = -3;

pragma(inline, true)
int EVP_PKEY_CTX_set_rsa_padding(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int pad)

	do
	{
		return .RSA_pkey_ctx_ctrl(ctx, -1, .EVP_PKEY_CTRL_RSA_PADDING, pad, null);
	}

pragma(inline, true)
int EVP_PKEY_CTX_get_rsa_padding(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* ppad)

	do
	{
		return .RSA_pkey_ctx_ctrl(ctx, -1, .EVP_PKEY_CTRL_GET_RSA_PADDING, 0, ppad);
	}

pragma(inline, true)
int EVP_PKEY_CTX_set_rsa_pss_saltlen(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int len)

	do
	{
		return .RSA_pkey_ctx_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_OP_SIGN | libressl_d.openssl.evp.EVP_PKEY_OP_VERIFY, .EVP_PKEY_CTRL_RSA_PSS_SALTLEN, len, null);
	}

pragma(inline, true)
int EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int len)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_RSA_PSS, libressl_d.openssl.evp.EVP_PKEY_OP_KEYGEN, .EVP_PKEY_CTRL_RSA_PSS_SALTLEN, len, null);
	}

pragma(inline, true)
int EVP_PKEY_CTX_get_rsa_pss_saltlen(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* plen)

	do
	{
		return .RSA_pkey_ctx_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_OP_SIGN | libressl_d.openssl.evp.EVP_PKEY_OP_VERIFY, .EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, 0, plen);
	}

pragma(inline, true)
int EVP_PKEY_CTX_set_rsa_keygen_bits(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int bits)

	do
	{
		return .RSA_pkey_ctx_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_OP_KEYGEN, .EVP_PKEY_CTRL_RSA_KEYGEN_BITS, bits, null);
	}

pragma(inline, true)
int EVP_PKEY_CTX_set_rsa_keygen_pubexp(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* pubexp)

	do
	{
		return .RSA_pkey_ctx_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_OP_KEYGEN, .EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 0, pubexp);
	}

pragma(inline, true)
int EVP_PKEY_CTX_set_rsa_mgf1_md(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* md)

	do
	{
		return .RSA_pkey_ctx_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_OP_TYPE_SIG | libressl_d.openssl.evp.EVP_PKEY_OP_TYPE_CRYPT, .EVP_PKEY_CTRL_RSA_MGF1_MD, 0, md);
	}

pragma(inline, true)
int EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* md)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_RSA_PSS, libressl_d.openssl.evp.EVP_PKEY_OP_KEYGEN, .EVP_PKEY_CTRL_RSA_MGF1_MD, 0, md);
	}

pragma(inline, true)
int EVP_PKEY_CTX_set_rsa_oaep_md(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* md)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_RSA, libressl_d.openssl.evp.EVP_PKEY_OP_TYPE_CRYPT, .EVP_PKEY_CTRL_RSA_OAEP_MD, 0, md);
	}

pragma(inline, true)
int EVP_PKEY_CTX_get_rsa_mgf1_md(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* pmd)

	do
	{
		return .RSA_pkey_ctx_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_OP_TYPE_SIG | libressl_d.openssl.evp.EVP_PKEY_OP_TYPE_CRYPT, .EVP_PKEY_CTRL_GET_RSA_MGF1_MD, 0, pmd);
	}

pragma(inline, true)
int EVP_PKEY_CTX_get_rsa_oaep_md(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* pmd)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_RSA, libressl_d.openssl.evp.EVP_PKEY_OP_TYPE_CRYPT, .EVP_PKEY_CTRL_GET_RSA_OAEP_MD, 0, pmd);
	}

pragma(inline, true)
int EVP_PKEY_CTX_set0_rsa_oaep_label(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* l, int llen)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_RSA, libressl_d.openssl.evp.EVP_PKEY_OP_TYPE_CRYPT, .EVP_PKEY_CTRL_RSA_OAEP_LABEL, llen, l);
	}

pragma(inline, true)
int EVP_PKEY_CTX_get0_rsa_oaep_label(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* l)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_RSA, libressl_d.openssl.evp.EVP_PKEY_OP_TYPE_CRYPT, .EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL, 0, l);
	}

pragma(inline, true)
int s(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* md)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_RSA_PSS, libressl_d.openssl.evp.EVP_PKEY_OP_KEYGEN, libressl_d.openssl.evp.EVP_PKEY_CTRL_MD, 0, md);
	}

enum EVP_PKEY_CTRL_RSA_PADDING = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 1;
enum EVP_PKEY_CTRL_RSA_PSS_SALTLEN = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 2;

enum EVP_PKEY_CTRL_RSA_KEYGEN_BITS = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 3;
enum EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 4;
enum EVP_PKEY_CTRL_RSA_MGF1_MD = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 5;

enum EVP_PKEY_CTRL_GET_RSA_PADDING = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 6;
enum EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 7;
enum EVP_PKEY_CTRL_GET_RSA_MGF1_MD = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 8;

enum EVP_PKEY_CTRL_RSA_OAEP_MD = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 9;
enum EVP_PKEY_CTRL_RSA_OAEP_LABEL = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 10;

enum EVP_PKEY_CTRL_GET_RSA_OAEP_MD = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 11;
enum EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 12;

enum RSA_PKCS1_PADDING = 1;
enum RSA_SSLV23_PADDING = 2;
enum RSA_NO_PADDING = 3;
enum RSA_PKCS1_OAEP_PADDING = 4;
enum RSA_X931_PADDING = 5;
/* EVP_PKEY_ only */
enum RSA_PKCS1_PSS_PADDING = 6;

enum RSA_PKCS1_PADDING_SIZE = 11;

pragma(inline, true)
int RSA_set_app_data(libressl_d.openssl.ossl_typ.RSA* s, void* arg)

	do
	{
		return .RSA_set_ex_data(s, 0, arg);
	}

pragma(inline, true)
void* RSA_get_app_data(const (libressl_d.openssl.ossl_typ.RSA)* s)

	do
	{
		return .RSA_get_ex_data(s, 0);
	}

libressl_d.openssl.ossl_typ.RSA* RSA_new();
libressl_d.openssl.ossl_typ.RSA* RSA_new_method(libressl_d.openssl.ossl_typ.ENGINE* engine);
int RSA_bits(const (libressl_d.openssl.ossl_typ.RSA)* rsa);
int RSA_size(const (libressl_d.openssl.ossl_typ.RSA)* rsa);

/* Deprecated version */
version (OPENSSL_NO_DEPRECATED) {
} else {
	private alias RSA_generate_key_callback = /* Temporary type */ extern (C) nothrow @nogc void function(int, int, void*);
	libressl_d.openssl.ossl_typ.RSA* RSA_generate_key(int bits, core.stdc.config.c_ulong e, .RSA_generate_key_callback callback, void* cb_arg);
}

/**
 * New version
 */
int RSA_generate_key_ex(libressl_d.openssl.ossl_typ.RSA* rsa, int bits, libressl_d.openssl.ossl_typ.BIGNUM* e, libressl_d.openssl.ossl_typ.BN_GENCB* cb);

int RSA_check_key(const (libressl_d.openssl.ossl_typ.RSA)*);
/* next 4 return -1 on error */
int RSA_public_encrypt(int flen, const (ubyte)* from, ubyte* to, libressl_d.openssl.ossl_typ.RSA* rsa, int padding);
int RSA_private_encrypt(int flen, const (ubyte)* from, ubyte* to, libressl_d.openssl.ossl_typ.RSA* rsa, int padding);
int RSA_public_decrypt(int flen, const (ubyte)* from, ubyte* to, libressl_d.openssl.ossl_typ.RSA* rsa, int padding);
int RSA_private_decrypt(int flen, const (ubyte)* from, ubyte* to, libressl_d.openssl.ossl_typ.RSA* rsa, int padding);
void RSA_free(libressl_d.openssl.ossl_typ.RSA* r);

/**
 * "up" the RSA object's reference count
 */
int RSA_up_ref(libressl_d.openssl.ossl_typ.RSA* r);

int RSA_flags(const (libressl_d.openssl.ossl_typ.RSA)* r);

void RSA_set_default_method(const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth);
const (libressl_d.openssl.ossl_typ.RSA_METHOD)* RSA_get_default_method();
const (libressl_d.openssl.ossl_typ.RSA_METHOD)* RSA_get_method(const (libressl_d.openssl.ossl_typ.RSA)* rsa);
int RSA_set_method(libressl_d.openssl.ossl_typ.RSA* rsa, const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth);

const (libressl_d.openssl.ossl_typ.RSA_METHOD)* RSA_PKCS1_OpenSSL();
const (libressl_d.openssl.ossl_typ.RSA_METHOD)* RSA_PKCS1_SSLeay();

const (libressl_d.openssl.ossl_typ.RSA_METHOD)* RSA_null_method();

int RSA_pkey_ctx_ctrl(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int optype, int cmd, int p1, void* p2);

libressl_d.openssl.ossl_typ.RSA* d2i_RSAPublicKey(libressl_d.openssl.ossl_typ.RSA** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_RSAPublicKey(const (libressl_d.openssl.ossl_typ.RSA)* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM RSAPublicKey_it;
libressl_d.openssl.ossl_typ.RSA* d2i_RSAPrivateKey(libressl_d.openssl.ossl_typ.RSA** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_RSAPrivateKey(const (libressl_d.openssl.ossl_typ.RSA)* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM RSAPrivateKey_it;

libressl_d.openssl.ossl_typ.RSA_PSS_PARAMS* RSA_PSS_PARAMS_new();
void RSA_PSS_PARAMS_free(libressl_d.openssl.ossl_typ.RSA_PSS_PARAMS* a);
libressl_d.openssl.ossl_typ.RSA_PSS_PARAMS* d2i_RSA_PSS_PARAMS(libressl_d.openssl.ossl_typ.RSA_PSS_PARAMS** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_RSA_PSS_PARAMS(libressl_d.openssl.ossl_typ.RSA_PSS_PARAMS* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM RSA_PSS_PARAMS_it;

.RSA_OAEP_PARAMS* RSA_OAEP_PARAMS_new();
void RSA_OAEP_PARAMS_free(.RSA_OAEP_PARAMS* a);
.RSA_OAEP_PARAMS* d2i_RSA_OAEP_PARAMS(.RSA_OAEP_PARAMS** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_RSA_OAEP_PARAMS(.RSA_OAEP_PARAMS* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM RSA_OAEP_PARAMS_it;

int RSA_print_fp(libressl_d.compat.stdio.FILE* fp, const (libressl_d.openssl.ossl_typ.RSA)* r, int offset);

version (OPENSSL_NO_BIO) {
} else {
	int RSA_print(libressl_d.openssl.ossl_typ.BIO* bp, const (libressl_d.openssl.ossl_typ.RSA)* r, int offset);
}

/*
 * The following 2 functions sign and verify a X509_SIG ASN1 object
 * inside PKCS#1 padded RSA encryption
 */
int RSA_sign(int type, const (ubyte)* m, uint m_length, ubyte* sigret, uint* siglen, libressl_d.openssl.ossl_typ.RSA* rsa);
int RSA_verify(int type, const (ubyte)* m, uint m_length, const (ubyte)* sigbuf, uint siglen, libressl_d.openssl.ossl_typ.RSA* rsa);

/*
 * The following 2 function sign and verify a ASN1_OCTET_STRING
 * object inside PKCS#1 padded RSA encryption
 */
int RSA_sign_ASN1_OCTET_STRING(int type, const (ubyte)* m, uint m_length, ubyte* sigret, uint* siglen, libressl_d.openssl.ossl_typ.RSA* rsa);
int RSA_verify_ASN1_OCTET_STRING(int type, const (ubyte)* m, uint m_length, ubyte* sigbuf, uint siglen, libressl_d.openssl.ossl_typ.RSA* rsa);

int RSA_blinding_on(libressl_d.openssl.ossl_typ.RSA* rsa, libressl_d.openssl.ossl_typ.BN_CTX* ctx);
void RSA_blinding_off(libressl_d.openssl.ossl_typ.RSA* rsa);
libressl_d.openssl.ossl_typ.BN_BLINDING* RSA_setup_blinding(libressl_d.openssl.ossl_typ.RSA* rsa, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

int RSA_padding_add_PKCS1_type_1(ubyte* to, int tlen, const (ubyte)* f, int fl);
int RSA_padding_check_PKCS1_type_1(ubyte* to, int tlen, const (ubyte)* f, int fl, int rsa_len);
int RSA_padding_add_PKCS1_type_2(ubyte* to, int tlen, const (ubyte)* f, int fl);
int RSA_padding_check_PKCS1_type_2(ubyte* to, int tlen, const (ubyte)* f, int fl, int rsa_len);
int PKCS1_MGF1(ubyte* mask, core.stdc.config.c_long len, const (ubyte)* seed, core.stdc.config.c_long seedlen, const (libressl_d.openssl.ossl_typ.EVP_MD)* dgst);
int RSA_padding_add_PKCS1_OAEP(ubyte* to, int tlen, const (ubyte)* f, int fl, const (ubyte)* p, int pl);
int RSA_padding_check_PKCS1_OAEP(ubyte* to, int tlen, const (ubyte)* f, int fl, int rsa_len, const (ubyte)* p, int pl);
int RSA_padding_add_PKCS1_OAEP_mgf1(ubyte* to, int tlen, const (ubyte)* from, int flen, const (ubyte)* param, int plen, const (libressl_d.openssl.ossl_typ.EVP_MD)* md, const (libressl_d.openssl.ossl_typ.EVP_MD)* mgf1md);
int RSA_padding_check_PKCS1_OAEP_mgf1(ubyte* to, int tlen, const (ubyte)* from, int flen, int num, const (ubyte)* param, int plen, const (libressl_d.openssl.ossl_typ.EVP_MD)* md, const (libressl_d.openssl.ossl_typ.EVP_MD)* mgf1md);
int RSA_padding_add_none(ubyte* to, int tlen, const (ubyte)* f, int fl);
int RSA_padding_check_none(ubyte* to, int tlen, const (ubyte)* f, int fl, int rsa_len);
int RSA_padding_add_X931(ubyte* to, int tlen, const (ubyte)* f, int fl);
int RSA_padding_check_X931(ubyte* to, int tlen, const (ubyte)* f, int fl, int rsa_len);
int RSA_X931_hash_id(int nid);

int RSA_verify_PKCS1_PSS(libressl_d.openssl.ossl_typ.RSA* rsa, const (ubyte)* mHash, const (libressl_d.openssl.ossl_typ.EVP_MD)* Hash, const (ubyte)* EM, int sLen);
int RSA_padding_add_PKCS1_PSS(libressl_d.openssl.ossl_typ.RSA* rsa, ubyte* EM, const (ubyte)* mHash, const (libressl_d.openssl.ossl_typ.EVP_MD)* Hash, int sLen);

int RSA_verify_PKCS1_PSS_mgf1(libressl_d.openssl.ossl_typ.RSA* rsa, const (ubyte)* mHash, const (libressl_d.openssl.ossl_typ.EVP_MD)* Hash, const (libressl_d.openssl.ossl_typ.EVP_MD)* mgf1Hash, const (ubyte)* EM, int sLen);

int RSA_padding_add_PKCS1_PSS_mgf1(libressl_d.openssl.ossl_typ.RSA* rsa, ubyte* EM, const (ubyte)* mHash, const (libressl_d.openssl.ossl_typ.EVP_MD)* Hash, const (libressl_d.openssl.ossl_typ.EVP_MD)* mgf1Hash, int sLen);

int RSA_get_ex_new_index(core.stdc.config.c_long argl, void* argp, libressl_d.openssl.ossl_typ.CRYPTO_EX_new new_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_dup dup_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_free free_func);
int RSA_set_ex_data(libressl_d.openssl.ossl_typ.RSA* r, int idx, void* arg);
void* RSA_get_ex_data(const (libressl_d.openssl.ossl_typ.RSA)* r, int idx);

int RSA_security_bits(const (libressl_d.openssl.ossl_typ.RSA)* rsa);

void RSA_get0_key(const (libressl_d.openssl.ossl_typ.RSA)* r, const (libressl_d.openssl.ossl_typ.BIGNUM)** n, const (libressl_d.openssl.ossl_typ.BIGNUM)** e, const (libressl_d.openssl.ossl_typ.BIGNUM)** d);
int RSA_set0_key(libressl_d.openssl.ossl_typ.RSA* r, libressl_d.openssl.ossl_typ.BIGNUM* n, libressl_d.openssl.ossl_typ.BIGNUM* e, libressl_d.openssl.ossl_typ.BIGNUM* d);
void RSA_get0_crt_params(const (libressl_d.openssl.ossl_typ.RSA)* r, const (libressl_d.openssl.ossl_typ.BIGNUM)** dmp1, const (libressl_d.openssl.ossl_typ.BIGNUM)** dmq1, const (libressl_d.openssl.ossl_typ.BIGNUM)** iqmp);
int RSA_set0_crt_params(libressl_d.openssl.ossl_typ.RSA* r, libressl_d.openssl.ossl_typ.BIGNUM* dmp1, libressl_d.openssl.ossl_typ.BIGNUM* dmq1, libressl_d.openssl.ossl_typ.BIGNUM* iqmp);
void RSA_get0_factors(const (libressl_d.openssl.ossl_typ.RSA)* r, const (libressl_d.openssl.ossl_typ.BIGNUM)** p, const (libressl_d.openssl.ossl_typ.BIGNUM)** q);
int RSA_set0_factors(libressl_d.openssl.ossl_typ.RSA* r, libressl_d.openssl.ossl_typ.BIGNUM* p, libressl_d.openssl.ossl_typ.BIGNUM* q);
const (libressl_d.openssl.ossl_typ.BIGNUM)* RSA_get0_n(const (libressl_d.openssl.ossl_typ.RSA)* r);
const (libressl_d.openssl.ossl_typ.BIGNUM)* RSA_get0_e(const (libressl_d.openssl.ossl_typ.RSA)* r);
const (libressl_d.openssl.ossl_typ.BIGNUM)* RSA_get0_d(const (libressl_d.openssl.ossl_typ.RSA)* r);
const (libressl_d.openssl.ossl_typ.BIGNUM)* RSA_get0_p(const (libressl_d.openssl.ossl_typ.RSA)* r);
const (libressl_d.openssl.ossl_typ.BIGNUM)* RSA_get0_q(const (libressl_d.openssl.ossl_typ.RSA)* r);
const (libressl_d.openssl.ossl_typ.BIGNUM)* RSA_get0_dmp1(const (libressl_d.openssl.ossl_typ.RSA)* r);
const (libressl_d.openssl.ossl_typ.BIGNUM)* RSA_get0_dmq1(const (libressl_d.openssl.ossl_typ.RSA)* r);
const (libressl_d.openssl.ossl_typ.BIGNUM)* RSA_get0_iqmp(const (libressl_d.openssl.ossl_typ.RSA)* r);
const (libressl_d.openssl.ossl_typ.RSA_PSS_PARAMS)* RSA_get0_pss_params(const (libressl_d.openssl.ossl_typ.RSA)* r);
void RSA_clear_flags(libressl_d.openssl.ossl_typ.RSA* r, int flags);
int RSA_test_flags(const (libressl_d.openssl.ossl_typ.RSA)* r, int flags);
void RSA_set_flags(libressl_d.openssl.ossl_typ.RSA* r, int flags);

libressl_d.openssl.ossl_typ.RSA* RSAPublicKey_dup(libressl_d.openssl.ossl_typ.RSA* rsa);
libressl_d.openssl.ossl_typ.RSA* RSAPrivateKey_dup(libressl_d.openssl.ossl_typ.RSA* rsa);

/**
 * If this flag is set the RSA method is FIPS compliant and can be used
 * in FIPS mode. This is set in the validated module method. If an
 * application sets this flag in its own methods it is its responsibility
 * to ensure the result is compliant.
 */
enum RSA_FLAG_FIPS_METHOD = 0x0400;

/**
 * If this flag is set the operations normally disabled in FIPS mode are
 * permitted it is then the applications responsibility to ensure that the
 * usage is compliant.
 */
enum RSA_FLAG_NON_FIPS_ALLOW = 0x0400;

/**
 * Application has decided PRNG is good enough to generate a key: don't
 * check.
 */
enum RSA_FLAG_CHECKED = 0x0800;

libressl_d.openssl.ossl_typ.RSA_METHOD* RSA_meth_new(const (char)* name, int flags);
void RSA_meth_free(libressl_d.openssl.ossl_typ.RSA_METHOD* meth);
libressl_d.openssl.ossl_typ.RSA_METHOD* RSA_meth_dup(const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth);
int RSA_meth_set1_name(libressl_d.openssl.ossl_typ.RSA_METHOD* meth, const (char)* name);

private alias RSA_meth_set_priv_enc_func = /* Temporary type */ extern (C) nothrow @nogc int function(int flen, const (ubyte)* from, ubyte* to, libressl_d.openssl.ossl_typ.RSA* rsa, int padding);
int RSA_meth_set_priv_enc(libressl_d.openssl.ossl_typ.RSA_METHOD* meth, .RSA_meth_set_priv_enc_func priv_enc);

private alias RSA_meth_set_priv_dec_func = /* Temporary type */ extern (C) nothrow @nogc int function(int flen, const (ubyte)* from, ubyte* to, libressl_d.openssl.ossl_typ.RSA* rsa, int padding);
int RSA_meth_set_priv_dec(libressl_d.openssl.ossl_typ.RSA_METHOD* meth, .RSA_meth_set_priv_dec_func priv_dec);
//int (*RSA_meth_get_finish(const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth))(libressl_d.openssl.ossl_typ.RSA* rsa);

private alias RSA_meth_set_finish_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.RSA* rsa);
int RSA_meth_set_finish(libressl_d.openssl.ossl_typ.RSA_METHOD* meth, .RSA_meth_set_finish_func finish);

private alias RSA_meth_set_pub_enc_func = /* Temporary type */ extern (C) nothrow @nogc int function(int flen, const (ubyte)* from, ubyte* to, libressl_d.openssl.ossl_typ.RSA* rsa, int padding);
int RSA_meth_set_pub_enc(libressl_d.openssl.ossl_typ.RSA_METHOD* meth, .RSA_meth_set_pub_enc_func pub_enc);

private alias RSA_meth_set_pub_dec_func = /* Temporary type */ extern (C) nothrow @nogc int function(int flen, const (ubyte)* from, ubyte* to, libressl_d.openssl.ossl_typ.RSA* rsa, int padding);
int RSA_meth_set_pub_dec(libressl_d.openssl.ossl_typ.RSA_METHOD* meth, .RSA_meth_set_pub_dec_func pub_dec);

private alias RSA_meth_set_mod_exp_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.BIGNUM* r0, const (libressl_d.openssl.ossl_typ.BIGNUM)* i, libressl_d.openssl.ossl_typ.RSA* rsa, libressl_d.openssl.ossl_typ.BN_CTX* ctx);
int RSA_meth_set_mod_exp(libressl_d.openssl.ossl_typ.RSA_METHOD* meth, .RSA_meth_set_mod_exp_func mod_exp);

private alias RSA_meth_set_bn_mod_exp_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.BIGNUM* r, const (libressl_d.openssl.ossl_typ.BIGNUM)* a, const (libressl_d.openssl.ossl_typ.BIGNUM)* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* m, libressl_d.openssl.ossl_typ.BN_CTX* ctx, libressl_d.openssl.ossl_typ.BN_MONT_CTX* m_ctx);
int RSA_meth_set_bn_mod_exp(libressl_d.openssl.ossl_typ.RSA_METHOD* meth, .RSA_meth_set_bn_mod_exp_func bn_mod_exp);

private alias RSA_meth_set_init_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.RSA* rsa);
int RSA_meth_set_init(libressl_d.openssl.ossl_typ.RSA_METHOD* meth, .RSA_meth_set_init_func init);

private alias RSA_meth_set_keygen_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.RSA* rsa, int bits, libressl_d.openssl.ossl_typ.BIGNUM* e, libressl_d.openssl.ossl_typ.BN_GENCB* cb);
int RSA_meth_set_keygen(libressl_d.openssl.ossl_typ.RSA_METHOD* meth, .RSA_meth_set_keygen_func keygen);
int RSA_meth_set_flags(libressl_d.openssl.ossl_typ.RSA_METHOD* meth, int flags);
int RSA_meth_set0_app_data(libressl_d.openssl.ossl_typ.RSA_METHOD* meth, void* app_data);
const (char)* RSA_meth_get0_name(const (libressl_d.openssl.ossl_typ.RSA_METHOD)*);
//int (*RSA_meth_get_pub_enc(const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth))(int flen, const (ubyte)* from, ubyte* to, libressl_d.openssl.ossl_typ.RSA* rsa, int padding);
//int (*RSA_meth_get_pub_dec(const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth))(int flen, const (ubyte)* from, ubyte* to, libressl_d.openssl.ossl_typ.RSA* rsa, int padding);
//int (*RSA_meth_get_priv_enc(const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth))(int flen, const (ubyte)* from, ubyte* to, libressl_d.openssl.ossl_typ.RSA* rsa, int padding);
//int (*RSA_meth_get_priv_dec(const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth))(int flen, const (ubyte)* from, ubyte* to, libressl_d.openssl.ossl_typ.RSA* rsa, int padding);
//int (*RSA_meth_get_mod_exp(const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth))(libressl_d.openssl.ossl_typ.BIGNUM* r0, const (libressl_d.openssl.ossl_typ.BIGNUM)* i, libressl_d.openssl.ossl_typ.RSA* rsa, libressl_d.openssl.ossl_typ.BN_CTX* ctx);
//int (*RSA_meth_get_bn_mod_exp(const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth))(libressl_d.openssl.ossl_typ.BIGNUM* r, const (libressl_d.openssl.ossl_typ.BIGNUM)* a, const (libressl_d.openssl.ossl_typ.BIGNUM)* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* m, libressl_d.openssl.ossl_typ.BN_CTX* ctx, libressl_d.openssl.ossl_typ.BN_MONT_CTX* m_ctx);
//int (*RSA_meth_get_init(const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth))(libressl_d.openssl.ossl_typ.RSA* rsa);
//int (*RSA_meth_get_keygen(const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth))(libressl_d.openssl.ossl_typ.RSA* rsa, int bits, libressl_d.openssl.ossl_typ.BIGNUM* e, libressl_d.openssl.ossl_typ.BN_GENCB* cb);
int RSA_meth_get_flags(const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth);
void* RSA_meth_get0_app_data(const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth);
//int (*RSA_meth_get_sign(const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth))(int type, const (ubyte)* m, uint m_length, ubyte* sigret, uint* siglen, const (libressl_d.openssl.ossl_typ.RSA)* rsa);

private alias RSA_meth_set_sign_func = /* Temporary type */ extern (C) nothrow @nogc int function(int type, const (ubyte)* m, uint m_length, ubyte* sigret, uint* siglen, const (libressl_d.openssl.ossl_typ.RSA)* rsa);
int RSA_meth_set_sign(libressl_d.openssl.ossl_typ.RSA_METHOD* rsa, .RSA_meth_set_sign_func sign);
//int (*RSA_meth_get_verify(const (libressl_d.openssl.ossl_typ.RSA_METHOD)* meth))(int dtype, const (ubyte)* m, uint m_length, const (ubyte)* sigbuf, uint siglen, const (libressl_d.openssl.ossl_typ.RSA)* rsa);

private alias RSA_meth_set_verify_func = /* Temporary type */ extern (C) nothrow @nogc int function(int dtype, const (ubyte)* m, uint m_length, const (ubyte)* sigbuf, uint siglen, const (libressl_d.openssl.ossl_typ.RSA)* rsa);
int RSA_meth_set_verify(libressl_d.openssl.ossl_typ.RSA_METHOD* rsa, .RSA_meth_set_verify_func verify);

void ERR_load_RSA_strings();

/* Error codes for the RSA functions. */

/* Function codes. */
enum RSA_F_CHECK_PADDING_MD = 140;
enum RSA_F_DO_RSA_PRINT = 146;
enum RSA_F_INT_RSA_VERIFY = 145;
enum RSA_F_MEMORY_LOCK = 100;
enum RSA_F_OLD_RSA_PRIV_DECODE = 147;
enum RSA_F_PKEY_RSA_CTRL = 143;
enum RSA_F_PKEY_RSA_CTRL_STR = 144;
enum RSA_F_PKEY_RSA_SIGN = 142;
enum RSA_F_PKEY_RSA_VERIFY = 154;
enum RSA_F_PKEY_RSA_VERIFYRECOVER = 141;
enum RSA_F_RSA_BUILTIN_KEYGEN = 129;
enum RSA_F_RSA_CHECK_KEY = 123;
enum RSA_F_RSA_EAY_MOD_EXP = 157;
enum RSA_F_RSA_EAY_PRIVATE_DECRYPT = 101;
enum RSA_F_RSA_EAY_PRIVATE_ENCRYPT = 102;
enum RSA_F_RSA_EAY_PUBLIC_DECRYPT = 103;
enum RSA_F_RSA_EAY_PUBLIC_ENCRYPT = 104;
enum RSA_F_RSA_GENERATE_KEY = 105;
enum RSA_F_RSA_GENERATE_KEY_EX = 155;
enum RSA_F_RSA_ITEM_VERIFY = 156;
enum RSA_F_RSA_MEMORY_LOCK = 130;
enum RSA_F_RSA_NEW_METHOD = 106;
enum RSA_F_RSA_NULL = 124;
enum RSA_F_RSA_NULL_MOD_EXP = 131;
enum RSA_F_RSA_NULL_PRIVATE_DECRYPT = 132;
enum RSA_F_RSA_NULL_PRIVATE_ENCRYPT = 133;
enum RSA_F_RSA_NULL_PUBLIC_DECRYPT = 134;
enum RSA_F_RSA_NULL_PUBLIC_ENCRYPT = 135;
enum RSA_F_RSA_PADDING_ADD_NONE = 107;
enum RSA_F_RSA_PADDING_ADD_PKCS1_OAEP = 121;
enum RSA_F_RSA_PADDING_ADD_PKCS1_PSS = 125;
enum RSA_F_RSA_PADDING_ADD_PKCS1_PSS_MGF1 = 148;
enum RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1 = 108;
enum RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2 = 109;
enum RSA_F_RSA_PADDING_ADD_X931 = 127;
enum RSA_F_RSA_PADDING_CHECK_NONE = 111;
enum RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP = 122;
enum RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1 = 112;
enum RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2 = 113;
enum RSA_F_RSA_PADDING_CHECK_X931 = 128;
enum RSA_F_RSA_PRINT = 115;
enum RSA_F_RSA_PRINT_FP = 116;
enum RSA_F_RSA_PRIVATE_DECRYPT = 150;
enum RSA_F_RSA_PRIVATE_ENCRYPT = 151;
enum RSA_F_RSA_PRIV_DECODE = 137;
enum RSA_F_RSA_PRIV_ENCODE = 138;
enum RSA_F_RSA_PUBLIC_DECRYPT = 152;
enum RSA_F_RSA_PUBLIC_ENCRYPT = 153;
enum RSA_F_RSA_PUB_DECODE = 139;
enum RSA_F_RSA_SETUP_BLINDING = 136;
enum RSA_F_RSA_SIGN = 117;
enum RSA_F_RSA_SIGN_ASN1_OCTET_STRING = 118;
enum RSA_F_RSA_VERIFY = 119;
enum RSA_F_RSA_VERIFY_ASN1_OCTET_STRING = 120;
enum RSA_F_RSA_VERIFY_PKCS1_PSS = 126;
enum RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1 = 149;

/* Reason codes. */
enum RSA_R_ALGORITHM_MISMATCH = 100;
enum RSA_R_BAD_E_VALUE = 101;
enum RSA_R_BAD_FIXED_HEADER_DECRYPT = 102;
enum RSA_R_BAD_PAD_BYTE_COUNT = 103;
enum RSA_R_BAD_SIGNATURE = 104;
enum RSA_R_BLOCK_TYPE_IS_NOT_01 = 106;
enum RSA_R_BLOCK_TYPE_IS_NOT_02 = 107;
enum RSA_R_DATA_GREATER_THAN_MOD_LEN = 108;
enum RSA_R_DATA_TOO_LARGE = 109;
enum RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE = 110;
enum RSA_R_DATA_TOO_LARGE_FOR_MODULUS = 132;
enum RSA_R_DATA_TOO_SMALL = 111;
enum RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE = 122;
enum RSA_R_DIGEST_DOES_NOT_MATCH = 158;
enum RSA_R_DIGEST_NOT_ALLOWED = 145;
enum RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY = 112;
enum RSA_R_DMP1_NOT_CONGRUENT_TO_D = 124;
enum RSA_R_DMQ1_NOT_CONGRUENT_TO_D = 125;
enum RSA_R_D_E_NOT_CONGRUENT_TO_1 = 123;
enum RSA_R_FIRST_OCTET_INVALID = 133;
enum RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE = 144;
enum RSA_R_INVALID_DIGEST = 157;
enum RSA_R_INVALID_DIGEST_LENGTH = 143;
enum RSA_R_INVALID_HEADER = 137;
enum RSA_R_INVALID_KEYBITS = 145;
enum RSA_R_INVALID_LABEL = 160;
enum RSA_R_INVALID_MESSAGE_LENGTH = 131;
enum RSA_R_INVALID_MGF1_MD = 156;
enum RSA_R_INVALID_OAEP_PARAMETERS = 161;
enum RSA_R_INVALID_PADDING = 138;
enum RSA_R_INVALID_PADDING_MODE = 141;
enum RSA_R_INVALID_PSS_PARAMETERS = 149;
enum RSA_R_INVALID_PSS_SALTLEN = 146;
enum RSA_R_INVALID_SALT_LENGTH = 150;
enum RSA_R_INVALID_TRAILER = 139;
enum RSA_R_INVALID_X931_DIGEST = 142;
enum RSA_R_IQMP_NOT_INVERSE_OF_Q = 126;
enum RSA_R_KEY_SIZE_TOO_SMALL = 120;
enum RSA_R_LAST_OCTET_INVALID = 134;
enum RSA_R_MODULUS_TOO_LARGE = 105;
enum RSA_R_MGF1_DIGEST_NOT_ALLOWED = 152;
enum RSA_R_NON_FIPS_RSA_METHOD = 157;
enum RSA_R_NO_PUBLIC_EXPONENT = 140;
enum RSA_R_NULL_BEFORE_BLOCK_MISSING = 113;
enum RSA_R_N_DOES_NOT_EQUAL_P_Q = 127;
enum RSA_R_OAEP_DECODING_ERROR = 121;
enum RSA_R_OPERATION_NOT_ALLOWED_IN_FIPS_MODE = 158;
enum RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE = 148;
enum RSA_R_PADDING_CHECK_FAILED = 114;
enum RSA_R_PSS_SALTLEN_TOO_SMALL = 164;
enum RSA_R_P_NOT_PRIME = 128;
enum RSA_R_Q_NOT_PRIME = 129;
enum RSA_R_RSA_OPERATIONS_NOT_SUPPORTED = 130;
enum RSA_R_SLEN_CHECK_FAILED = 136;
enum RSA_R_SLEN_RECOVERY_FAILED = 135;
enum RSA_R_SSLV3_ROLLBACK_ATTACK = 115;
enum RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 116;
enum RSA_R_UNKNOWN_ALGORITHM_TYPE = 117;
enum RSA_R_UNKNOWN_DIGEST = 166;
enum RSA_R_UNKNOWN_MASK_DIGEST = 151;
enum RSA_R_UNKNOWN_PADDING_TYPE = 118;
enum RSA_R_UNKNOWN_PSS_DIGEST = 152;
enum RSA_R_UNSUPPORTED_ENCRYPTION_TYPE = 162;
enum RSA_R_UNSUPPORTED_LABEL_SOURCE = 163;
enum RSA_R_UNSUPPORTED_MASK_ALGORITHM = 153;
enum RSA_R_UNSUPPORTED_MASK_PARAMETER = 154;
enum RSA_R_UNSUPPORTED_SIGNATURE_TYPE = 155;
enum RSA_R_VALUE_MISSING = 147;
enum RSA_R_WRONG_SIGNATURE_LENGTH = 119;
