/* $OpenBSD: evp.h,v 1.112 2022/11/13 14:04:13 tb Exp $ */
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
module libressl_d.openssl.evp;


private static import core.stdc.config;
private static import libressl_d.openssl.asn1;
private static import libressl_d.openssl.ec;
private static import libressl_d.openssl.obj_mac;
public import libressl_d.openssl.objects;
public import libressl_d.openssl.opensslconf;
public import libressl_d.openssl.ossl_typ;

version (OPENSSL_NO_BIO) {
	private struct bio_method_st;
	private alias BIO_METHOD = .bio_method_st;
} else {
	public import libressl_d.openssl.bio;

	private alias BIO_METHOD = libressl_d.openssl.bio.BIO_METHOD;
}

/*
enum EVP_RC2_KEY_SIZE = 16;
enum EVP_RC4_KEY_SIZE = 16;
enum EVP_BLOWFISH_KEY_SIZE = 16;
enum EVP_CAST5_KEY_SIZE = 16;
enum EVP_RC5_32_12_16_KEY_SIZE = 16;
 */

/**
 * longest known is SHA512
 */
enum EVP_MAX_MD_SIZE = 64;

enum EVP_MAX_KEY_LENGTH = 64;
enum EVP_MAX_IV_LENGTH = 16;
enum EVP_MAX_BLOCK_LENGTH = 32;

enum PKCS5_SALT_LEN = 8;
/* Default PKCS#5 iteration count */
enum PKCS5_DEFAULT_ITER = 2048;

enum EVP_PK_RSA = 0x0001;
enum EVP_PK_DSA = 0x0002;
enum EVP_PK_DH = 0x0004;
enum EVP_PK_EC = 0x0008;
enum EVP_PKT_SIGN = 0x0010;
enum EVP_PKT_ENC = 0x0020;
enum EVP_PKT_EXCH = 0x0040;
enum EVP_PKS_RSA = 0x0100;
enum EVP_PKS_DSA = 0x0200;
enum EVP_PKS_EC = 0x0400;

/**
 * <= 512 bit key
 */
enum EVP_PKT_EXP = 0x1000;

alias EVP_PKEY_NONE = libressl_d.openssl.objects.NID_undef;
alias EVP_PKEY_RSA = libressl_d.openssl.objects.NID_rsaEncryption;
alias EVP_PKEY_RSA_PSS = libressl_d.openssl.objects.NID_rsassaPss;
alias EVP_PKEY_RSA2 = libressl_d.openssl.objects.NID_rsa;
alias EVP_PKEY_DSA = libressl_d.openssl.objects.NID_dsa;
alias EVP_PKEY_DSA1 = libressl_d.openssl.objects.NID_dsa_2;
alias EVP_PKEY_DSA2 = libressl_d.openssl.objects.NID_dsaWithSHA;
alias EVP_PKEY_DSA3 = libressl_d.openssl.objects.NID_dsaWithSHA1;
alias EVP_PKEY_DSA4 = libressl_d.openssl.objects.NID_dsaWithSHA1_2;
alias EVP_PKEY_DH = libressl_d.openssl.objects.NID_dhKeyAgreement;
alias EVP_PKEY_EC = libressl_d.openssl.objects.NID_X9_62_id_ecPublicKey;
alias EVP_PKEY_GOSTR01 = libressl_d.openssl.objects.NID_id_GostR3410_2001;
alias EVP_PKEY_GOSTIMIT = libressl_d.openssl.objects.NID_id_Gost28147_89_MAC;
alias EVP_PKEY_HMAC = libressl_d.openssl.objects.NID_hmac;
alias EVP_PKEY_CMAC = libressl_d.openssl.objects.NID_cmac;
alias EVP_PKEY_HKDF = libressl_d.openssl.obj_mac.NID_hkdf;
alias EVP_PKEY_GOSTR12_256 = libressl_d.openssl.objects.NID_id_tc26_gost3410_2012_256;
alias EVP_PKEY_GOSTR12_512 = libressl_d.openssl.objects.NID_id_tc26_gost3410_2012_512;
alias EVP_PKEY_ED25519 = libressl_d.openssl.objects.NID_ED25519;
alias EVP_PKEY_X25519 = libressl_d.openssl.obj_mac.NID_X25519;

extern (C):
nothrow @nogc:

enum EVP_PKEY_MO_SIGN = 0x0001;
enum EVP_PKEY_MO_VERIFY = 0x0002;
enum EVP_PKEY_MO_ENCRYPT = 0x0004;
enum EVP_PKEY_MO_DECRYPT = 0x0008;

//static if (!__traits(compiles, libressl_d.openssl.ossl_typ.EVP_MD))
version (all) {
	/**
	 * digest can only handle a single
	 * block
	 */
	enum EVP_MD_FLAG_ONESHOT = 0x0001;

	/**
	 * DigestAlgorithmIdentifier flags...
	 */
	enum EVP_MD_FLAG_DIGALGID_MASK = 0x0018;

	/**
	 * null or absent parameter accepted. Use null
	 */
	enum EVP_MD_FLAG_DIGALGID_NULL = 0x0000;

	/**
	 * null or absent parameter accepted. Use null for PKCS#1 otherwise absent
	 */
	enum EVP_MD_FLAG_DIGALGID_ABSENT = 0x0008;

	/**
	 * Custom handling via ctrl
	 */
	enum EVP_MD_FLAG_DIGALGID_CUSTOM = 0x0018;

	/**
	 * Note if suitable for use in FIPS mode
	 */
	enum EVP_MD_FLAG_FIPS = 0x0400;

	/* Digest ctrls */

	enum EVP_MD_CTRL_DIGALGID = 0x01;
	enum EVP_MD_CTRL_MICALG = 0x02;
	enum EVP_MD_CTRL_SET_KEY = 0x03;
	enum EVP_MD_CTRL_GOST_SET_SBOX = 0x04;

	/**
	 * Minimum Algorithm specific ctrl value
	 */
	enum EVP_MD_CTRL_ALG_CTRL = 0x1000;
}

/* values for EVP_MD_CTX flags */

/**
 * digest update will be called
 * once only
 */
enum EVP_MD_CTX_FLAG_ONESHOT = 0x0001;

/**
 * context has already been
 * cleaned
 */
enum EVP_MD_CTX_FLAG_CLEANED = 0x0002;

/**
 * Don't free up ctx.md_data
 * in EVP_MD_CTX_cleanup
 */
enum EVP_MD_CTX_FLAG_REUSE = 0x0004;

/*
 * FIPS and pad options are ignored in 1.0.0, definitions are here
 * so we don't accidentally reuse the values for other purposes.
 */

/**
 * Allow use of non FIPS digest
 * in FIPS mode
 */
enum EVP_MD_CTX_FLAG_NON_FIPS_ALLOW = 0x0008;

/*
 * The following PAD options are also currently ignored in 1.0.0, digest
 * parameters are handled through EVP_DigestSign*() and EVP_DigestVerify*()
 * instead.
 */

/**
 * RSA mode to use
 */
enum EVP_MD_CTX_FLAG_PAD_MASK = 0xF0;

/**
 * PKCS#1 v1.5 mode
 */
enum EVP_MD_CTX_FLAG_PAD_PKCS1 = 0x00;

/**
 * X9.31 mode
 */
enum EVP_MD_CTX_FLAG_PAD_X931 = 0x10;

/**
 * PSS mode
 */
enum EVP_MD_CTX_FLAG_PAD_PSS = 0x20;

/**
 * Don't initialize md_data
 */
enum EVP_MD_CTX_FLAG_NO_INIT = 0x0100;

/* Values for cipher flags */

/* Modes for ciphers */

enum EVP_CIPH_STREAM_CIPHER = 0x00;
enum EVP_CIPH_ECB_MODE = 0x01;
enum EVP_CIPH_CBC_MODE = 0x02;
enum EVP_CIPH_CFB_MODE = 0x03;
enum EVP_CIPH_OFB_MODE = 0x04;
enum EVP_CIPH_CTR_MODE = 0x05;
enum EVP_CIPH_GCM_MODE = 0x06;
enum EVP_CIPH_CCM_MODE = 0x07;
enum EVP_CIPH_XTS_MODE = 0x010001;
enum EVP_CIPH_WRAP_MODE = 0x010002;
enum EVP_CIPH_MODE = 0x0F0007;

/**
 * Set if variable length cipher
 */
enum EVP_CIPH_VARIABLE_LENGTH = 0x08;

/**
 * Set if the iv handling should be done by the cipher itself
 */
enum EVP_CIPH_CUSTOM_IV = 0x10;

/**
 * Set if the cipher's init() function should be called if key is null
 */
enum EVP_CIPH_ALWAYS_CALL_INIT = 0x20;

/**
 * Call ctrl() to init cipher parameters
 */
enum EVP_CIPH_CTRL_INIT = 0x40;

/**
 * Don't use standard key length function
 */
enum EVP_CIPH_CUSTOM_KEY_LENGTH = 0x80;

/**
 * Don't use standard block padding
 */
enum EVP_CIPH_NO_PADDING = 0x0100;

/**
 * cipher handles random key generation
 */
enum EVP_CIPH_RAND_KEY = 0x0200;

/**
 * cipher has its own additional copying logic
 */
enum EVP_CIPH_CUSTOM_COPY = 0x0400;

/**
 * Allow use default ASN1 get/set iv
 */
enum EVP_CIPH_FLAG_DEFAULT_ASN1 = 0x1000;

/**
 * Buffer length in bits not bytes: CFB1 mode only
 */
enum EVP_CIPH_FLAG_LENGTH_BITS = 0x2000;

/**
 * Note if suitable for use in FIPS mode
 */
enum EVP_CIPH_FLAG_FIPS = 0x4000;

/**
 * Allow non FIPS cipher in FIPS mode
 */
enum EVP_CIPH_FLAG_NON_FIPS_ALLOW = 0x8000;

/*
 * Cipher handles any and all padding logic as well
 * as finalisation.
 */
enum EVP_CIPH_FLAG_CUSTOM_CIPHER = 0x100000;
enum EVP_CIPH_FLAG_AEAD_CIPHER = 0x200000;

/**
 * Cipher context flag to indicate that we can handle wrap mode: if allowed in
 * older applications, it could overflow buffers.
 */
enum EVP_CIPHER_CTX_FLAG_WRAP_ALLOW = 0x01;

/* ctrl() values */

enum EVP_CTRL_INIT = 0x00;
enum EVP_CTRL_SET_KEY_LENGTH = 0x01;
enum EVP_CTRL_GET_RC2_KEY_BITS = 0x02;
enum EVP_CTRL_SET_RC2_KEY_BITS = 0x03;
enum EVP_CTRL_GET_RC5_ROUNDS = 0x04;
enum EVP_CTRL_SET_RC5_ROUNDS = 0x05;
enum EVP_CTRL_RAND_KEY = 0x06;
enum EVP_CTRL_PBE_PRF_NID = 0x07;
enum EVP_CTRL_COPY = 0x08;
enum EVP_CTRL_AEAD_SET_IVLEN = 0x09;
enum EVP_CTRL_AEAD_GET_TAG = 0x10;
enum EVP_CTRL_AEAD_SET_TAG = 0x11;
enum EVP_CTRL_AEAD_SET_IV_FIXED = 0x12;
enum EVP_CTRL_GCM_SET_IVLEN = .EVP_CTRL_AEAD_SET_IVLEN;
enum EVP_CTRL_GCM_GET_TAG = .EVP_CTRL_AEAD_GET_TAG;
enum EVP_CTRL_GCM_SET_TAG = .EVP_CTRL_AEAD_SET_TAG;
enum EVP_CTRL_GCM_SET_IV_FIXED = .EVP_CTRL_AEAD_SET_IV_FIXED;
enum EVP_CTRL_GCM_IV_GEN = 0x13;
enum EVP_CTRL_CCM_SET_IVLEN = .EVP_CTRL_AEAD_SET_IVLEN;
enum EVP_CTRL_CCM_GET_TAG = .EVP_CTRL_AEAD_GET_TAG;
enum EVP_CTRL_CCM_SET_TAG = .EVP_CTRL_AEAD_SET_TAG;
enum EVP_CTRL_CCM_SET_L = 0x14;
enum EVP_CTRL_CCM_SET_MSGLEN = 0x15;

/**
 * AEAD cipher deduces payload length and returns number of bytes
 * required to store MAC and eventual padding. Subsequent call to
 * EVP_Cipher even appends/verifies MAC.
 */
enum EVP_CTRL_AEAD_TLS1_AAD = 0x16;

/**
 * Used by composite AEAD ciphers, no-op in GCM, CCM...
 */
enum EVP_CTRL_AEAD_SET_MAC_KEY = 0x17;

/**
 * Set the GCM invocation field, decrypt only
 */
enum EVP_CTRL_GCM_SET_IV_INV = 0x18;

/**
 * Set the S-BOX NID for GOST ciphers
 */
enum EVP_CTRL_GOST_SET_SBOX = 0x19;

/* GCM TLS constants */
/**
 * Length of fixed part of IV derived from PRF
 */
enum EVP_GCM_TLS_FIXED_IV_LEN = 4;

/**
 * Length of explicit part of IV part of TLS records
 */
enum EVP_GCM_TLS_EXPLICIT_IV_LEN = 8;

/**
 * Length of tag for TLS
 */
enum EVP_GCM_TLS_TAG_LEN = 16;

/* CCM TLS constants */
/**
 * Length of fixed part of IV derived from PRF
 */
enum EVP_CCM_TLS_FIXED_IV_LEN = 4;

/**
 * Length of explicit part of IV part of TLS records
 */
enum EVP_CCM_TLS_EXPLICIT_IV_LEN = 8;

/**
 * Total length of CCM IV length for TLS
 */
enum EVP_CCM_TLS_IV_LEN = 12;

/**
 * Length of tag for TLS
 */
enum EVP_CCM_TLS_TAG_LEN = 16;

/**
 * Length of CCM8 tag for TLS
 */
enum EVP_CCM8_TLS_TAG_LEN = 8;

/**
 * Length of tag for TLS
 */
enum EVP_CHACHAPOLY_TLS_TAG_LEN = 16;

/* XXX - do we want to expose these? */
version (LIBRESSL_INTERNAL) {
	enum ED25519_KEYLEN = 32;
	enum X25519_KEYLEN = 32;
}

struct evp_cipher_info_st
{
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher;
	ubyte[.EVP_MAX_IV_LENGTH] iv;
}

alias EVP_CIPHER_INFO = .evp_cipher_info_st;

/**
 * Password based encryption function
 */
private alias EVP_PBE_KEYGEN = /* Not a function pointer type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, const (char)* pass, int passlen, libressl_d.openssl.asn1.ASN1_TYPE* param, const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher, const (libressl_d.openssl.ossl_typ.EVP_MD)* md, int en_de);

version (OPENSSL_NO_RSA) {
} else {
	pragma(inline, true)
	int EVP_PKEY_assign_RSA(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, char* rsa)

		do
		{
			return .EVP_PKEY_assign(pkey, .EVP_PKEY_RSA, rsa);
		}
}

version (OPENSSL_NO_DSA) {
} else {
	pragma(inline, true)
	int EVP_PKEY_assign_DSA(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, char* dsa)

		do
		{
			return .EVP_PKEY_assign(pkey, .EVP_PKEY_DSA, dsa);
		}
}

version (OPENSSL_NO_DH) {
} else {
	pragma(inline, true)
	int EVP_PKEY_assign_DH(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, char* dh)

		do
		{
			return .EVP_PKEY_assign(pkey, .EVP_PKEY_DH, dh);
		}
}

version (OPENSSL_NO_EC) {
} else {
	pragma(inline, true)
	int EVP_PKEY_assign_EC_KEY(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, char* eckey)

		do
		{
			return .EVP_PKEY_assign(pkey, .EVP_PKEY_EC, eckey);
		}
}

version (OPENSSL_NO_GOST) {
} else {
	pragma(inline, true)
	int EVP_PKEY_assign_GOST(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, char* gostkey)

		do
		{
			return .EVP_PKEY_assign(pkey, .EVP_PKEY_GOSTR01, gostkey);
		}
}

/* Add some extra combinations */
pragma(inline, true)
const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_get_digestbynid(int a)

	do
	{
		return .EVP_get_digestbyname(libressl_d.openssl.objects.OBJ_nid2sn(a));
	}

pragma(inline, true)
const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_get_digestbyobj(const (libressl_d.openssl.ossl_typ.ASN1_OBJECT)* a)

	do
	{
		return .EVP_get_digestbynid(libressl_d.openssl.objects.OBJ_obj2nid(a));
	}

pragma(inline, true)
const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_get_cipherbynid(int a)

	do
	{
		return .EVP_get_cipherbyname(libressl_d.openssl.objects.OBJ_nid2sn(a));
	}

pragma(inline, true)
const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_get_cipherbyobj(const (libressl_d.openssl.ossl_typ.ASN1_OBJECT)* a)

	do
	{
		return EVP_get_cipherbynid(libressl_d.openssl.objects.OBJ_obj2nid(a));
	}

int EVP_MD_type(const (libressl_d.openssl.ossl_typ.EVP_MD)* md);

pragma(inline, true)
int EVP_MD_nid(const (libressl_d.openssl.ossl_typ.EVP_MD)* e)

	do
	{
		return .EVP_MD_type(e);
	}

pragma(inline, true)
const (char)* EVP_MD_name(const (libressl_d.openssl.ossl_typ.EVP_MD)* e)

	do
	{
		return libressl_d.openssl.objects.OBJ_nid2sn(.EVP_MD_nid(e));
	}

int EVP_MD_pkey_type(const (libressl_d.openssl.ossl_typ.EVP_MD)* md);
int EVP_MD_size(const (libressl_d.openssl.ossl_typ.EVP_MD)* md);
int EVP_MD_block_size(const (libressl_d.openssl.ossl_typ.EVP_MD)* md);
core.stdc.config.c_ulong EVP_MD_flags(const (libressl_d.openssl.ossl_typ.EVP_MD)* md);

libressl_d.openssl.ossl_typ.EVP_MD* EVP_MD_meth_new(int md_type, int pkey_type);
void EVP_MD_meth_free(libressl_d.openssl.ossl_typ.EVP_MD* md);
libressl_d.openssl.ossl_typ.EVP_MD* EVP_MD_meth_dup(const (libressl_d.openssl.ossl_typ.EVP_MD)* md);
int EVP_MD_meth_set_input_blocksize(libressl_d.openssl.ossl_typ.EVP_MD* md, int blocksize);
int EVP_MD_meth_set_result_size(libressl_d.openssl.ossl_typ.EVP_MD* md, int resultsize);
int EVP_MD_meth_set_app_datasize(libressl_d.openssl.ossl_typ.EVP_MD* md, int datasize);
int EVP_MD_meth_set_flags(libressl_d.openssl.ossl_typ.EVP_MD* md, core.stdc.config.c_ulong flags);

private alias EVP_MD_meth_set_init_func = /* Temporary type */ extern (C) nothrow int function(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx);
int EVP_MD_meth_set_init(libressl_d.openssl.ossl_typ.EVP_MD* md, .EVP_MD_meth_set_init_func init);

private alias EVP_MD_meth_set_update_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, const (void)* data, size_t count);
int EVP_MD_meth_set_update(libressl_d.openssl.ossl_typ.EVP_MD* md, .EVP_MD_meth_set_update_func update);

private alias EVP_MD_meth_set_final_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, ubyte* md);
int EVP_MD_meth_set_final(libressl_d.openssl.ossl_typ.EVP_MD* md, .EVP_MD_meth_set_final_func final_);

private alias EVP_MD_meth_set_copy_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_MD_CTX* to, const (libressl_d.openssl.ossl_typ.EVP_MD_CTX)* from);
int EVP_MD_meth_set_copy(libressl_d.openssl.ossl_typ.EVP_MD* md, .EVP_MD_meth_set_copy_func copy);

private alias EVP_MD_meth_set_cleanup_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx);
int EVP_MD_meth_set_cleanup(libressl_d.openssl.ossl_typ.EVP_MD* md, .EVP_MD_meth_set_cleanup_func cleanup);

private alias EVP_MD_meth_set_ctrl_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, int cmd, int p1, void* p2);
int EVP_MD_meth_set_ctrl(libressl_d.openssl.ossl_typ.EVP_MD* md, .EVP_MD_meth_set_ctrl_func ctrl);

const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_MD_CTX_md(const (libressl_d.openssl.ossl_typ.EVP_MD_CTX)* ctx);
void* EVP_MD_CTX_md_data(const (libressl_d.openssl.ossl_typ.EVP_MD_CTX)* ctx);
libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* EVP_MD_CTX_pkey_ctx(const (libressl_d.openssl.ossl_typ.EVP_MD_CTX)* ctx);
void EVP_MD_CTX_set_pkey_ctx(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* pctx);

pragma(inline, true)
int EVP_MD_CTX_size(const (libressl_d.openssl.ossl_typ.EVP_MD_CTX)* e)

	do
	{
		return .EVP_MD_size(.EVP_MD_CTX_md(e));
	}

pragma(inline, true)
int EVP_MD_CTX_block_size(const (libressl_d.openssl.ossl_typ.EVP_MD_CTX)* e)

	do
	{
		return .EVP_MD_block_size(.EVP_MD_CTX_md(e));
	}

pragma(inline, true)
int EVP_MD_CTX_type(const (libressl_d.openssl.ossl_typ.EVP_MD_CTX)* e)

	do
	{
		return .EVP_MD_type(.EVP_MD_CTX_md(e));
	}

int EVP_CIPHER_nid(const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher);

pragma(inline, true)
const (char)* EVP_CIPHER_name(const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* e)

	do
	{
		return libressl_d.openssl.objects.OBJ_nid2sn(.EVP_CIPHER_nid(e));
	}

int EVP_CIPHER_block_size(const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher);
int EVP_CIPHER_key_length(const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher);
int EVP_CIPHER_iv_length(const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher);
core.stdc.config.c_ulong EVP_CIPHER_flags(const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher);

pragma(inline, true)
core.stdc.config.c_ulong EVP_CIPHER_mode(const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* e)

	do
	{
		return .EVP_CIPHER_flags(e) & .EVP_CIPH_MODE;
	}

const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_CIPHER_CTX_cipher(const (libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_encrypting(const (libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_nid(const (libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_block_size(const (libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_key_length(const (libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_iv_length(const (libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_get_iv(const (libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX)* ctx, ubyte* iv, size_t len);
int EVP_CIPHER_CTX_set_iv(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, const (ubyte)* iv, size_t len);
int EVP_CIPHER_CTX_copy(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* out_, const (libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX)* in_);
void* EVP_CIPHER_CTX_get_app_data(const (libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX)* ctx);
void EVP_CIPHER_CTX_set_app_data(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, void* data);
void* EVP_CIPHER_CTX_get_cipher_data(const (libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX)* ctx);
void* EVP_CIPHER_CTX_set_cipher_data(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, void* cipher_data);
ubyte* EVP_CIPHER_CTX_buf_noconst(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx);

pragma(inline, true)
int EVP_CIPHER_CTX_type(const (libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX)* c)

	do
	{
		return .EVP_CIPHER_type(.EVP_CIPHER_CTX_cipher(c));
	}

core.stdc.config.c_ulong EVP_CIPHER_CTX_flags(const (libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX)* ctx);

pragma(inline, true)
core.stdc.config.c_ulong EVP_CIPHER_CTX_mode(const (libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX)* e)

	do
	{
		return .EVP_CIPHER_CTX_flags(e) & .EVP_CIPH_MODE;
	}

libressl_d.openssl.ossl_typ.EVP_PKEY* EVP_PKEY_new_raw_private_key(int type, libressl_d.openssl.ossl_typ.ENGINE* engine, const (ubyte)* private_key, size_t len);
libressl_d.openssl.ossl_typ.EVP_PKEY* EVP_PKEY_new_raw_public_key(int type, libressl_d.openssl.ossl_typ.ENGINE* engine, const (ubyte)* public_key, size_t len);
int EVP_PKEY_get_raw_private_key(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey, ubyte* out_private_key, size_t* out_len);
int EVP_PKEY_get_raw_public_key(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey, ubyte* out_public_key, size_t* out_len);

pragma(inline, true)
pure nothrow @safe @nogc @live
auto EVP_ENCODE_LENGTH(L)(L l)

	do
	{
		return ((l + 2) / 3 * 4) + (((l / 48) + 1) * 2) + 80;
	}

pragma(inline, true)
pure nothrow @safe @nogc @live
auto EVP_DECODE_LENGTH(L)(L l)

	do
	{
		return ((l + 3) / 4 * 3) + 80;
	}

alias EVP_SignInit_ex = .EVP_DigestInit_ex;
alias EVP_SignInit = .EVP_DigestInit;
alias EVP_SignUpdate = .EVP_DigestUpdate;
alias EVP_VerifyInit_ex = .EVP_DigestInit_ex;
alias EVP_VerifyInit = .EVP_DigestInit;
alias EVP_VerifyUpdate = .EVP_DigestUpdate;
alias EVP_OpenUpdate = .EVP_DecryptUpdate;
alias EVP_SealUpdate = .EVP_EncryptUpdate;
alias EVP_DigestSignUpdate = .EVP_DigestUpdate;
alias EVP_DigestVerifyUpdate = .EVP_DigestUpdate;

version (OPENSSL_NO_BIO) {
} else {
	pragma(inline, true)
	core.stdc.config.c_long BIO_set_md(libressl_d.openssl.ossl_typ.BIO* b, char* md)

		do
		{
			return libressl_d.openssl.bio.BIO_ctrl(b, libressl_d.openssl.bio.BIO_C_SET_MD, 0, md);
		}

	pragma(inline, true)
	core.stdc.config.c_long BIO_get_md(libressl_d.openssl.ossl_typ.BIO* b, char* mdp)

		do
		{
			return libressl_d.openssl.bio.BIO_ctrl(b, libressl_d.openssl.bio.BIO_C_GET_MD, 0, mdp);
		}

	pragma(inline, true)
	core.stdc.config.c_long BIO_get_md_ctx(libressl_d.openssl.ossl_typ.BIO* b, char* mdcp)

		do
		{
			return libressl_d.openssl.bio.BIO_ctrl(b, libressl_d.openssl.bio.BIO_C_GET_MD_CTX, 0, mdcp);
		}

	pragma(inline, true)
	core.stdc.config.c_long BIO_set_md_ctx(libressl_d.openssl.ossl_typ.BIO* b, char* mdcp)

		do
		{
			return libressl_d.openssl.bio.BIO_ctrl(b, libressl_d.openssl.bio.BIO_C_SET_MD_CTX, 0, mdcp);
		}

	pragma(inline, true)
	core.stdc.config.c_long BIO_get_cipher_status(libressl_d.openssl.ossl_typ.BIO* b)

		do
		{
			return libressl_d.openssl.bio.BIO_ctrl(b, libressl_d.openssl.bio.BIO_C_GET_CIPHER_STATUS, 0, null);
		}

	pragma(inline, true)
	core.stdc.config.c_long BIO_get_cipher_ctx(libressl_d.openssl.ossl_typ.BIO* b, char* c_pp)

		do
		{
			return libressl_d.openssl.bio.BIO_ctrl(b, libressl_d.openssl.bio.BIO_C_GET_CIPHER_CTX, 0, c_pp);
		}
}

int EVP_Cipher(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* c, ubyte* out_, const (ubyte)* in_, uint inl);

//#define EVP_add_cipher_alias(n, alias) libressl_d.openssl.objects.OBJ_NAME_add(alias, libressl_d.openssl.objects.OBJ_NAME_TYPE_CIPHER_METH | libressl_d.openssl.objects.OBJ_NAME_ALIAS, n)
//#define EVP_add_digest_alias(n, alias) libressl_d.openssl.objects.OBJ_NAME_add(alias, libressl_d.openssl.objects.OBJ_NAME_TYPE_MD_METH | libressl_d.openssl.objects.OBJ_NAME_ALIAS, n)
//#define EVP_delete_cipher_alias(alias) libressl_d.openssl.objects.OBJ_NAME_remove(alias, libressl_d.openssl.objects.OBJ_NAME_TYPE_CIPHER_METH | libressl_d.openssl.objects.OBJ_NAME_ALIAS);
//#define EVP_delete_digest_alias(alias) libressl_d.openssl.objects.OBJ_NAME_remove(alias, libressl_d.openssl.objects.OBJ_NAME_TYPE_MD_METH | libressl_d.openssl.objects.OBJ_NAME_ALIAS);

libressl_d.openssl.ossl_typ.EVP_MD_CTX* EVP_MD_CTX_new();
void EVP_MD_CTX_free(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx);
void EVP_MD_CTX_init(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx);
int EVP_MD_CTX_reset(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx);
libressl_d.openssl.ossl_typ.EVP_MD_CTX* EVP_MD_CTX_create();
void EVP_MD_CTX_destroy(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx);
int EVP_MD_CTX_cleanup(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx);
int EVP_MD_CTX_copy_ex(libressl_d.openssl.ossl_typ.EVP_MD_CTX* out_, const (libressl_d.openssl.ossl_typ.EVP_MD_CTX)* in_);
void EVP_MD_CTX_set_flags(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, int flags);
void EVP_MD_CTX_clear_flags(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, int flags);
int EVP_MD_CTX_ctrl(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, int type, int arg, void* ptr_);
int EVP_MD_CTX_test_flags(const (libressl_d.openssl.ossl_typ.EVP_MD_CTX)* ctx, int flags);

int EVP_DigestInit_ex(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, const (libressl_d.openssl.ossl_typ.EVP_MD)* type, libressl_d.openssl.ossl_typ.ENGINE* impl);
int EVP_DigestUpdate(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, const (void)* d, size_t cnt);
int EVP_DigestFinal_ex(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, ubyte* md, uint* s);
int EVP_Digest(const (void)* data, size_t count, ubyte* md, uint* size, const (libressl_d.openssl.ossl_typ.EVP_MD)* type, libressl_d.openssl.ossl_typ.ENGINE* impl);

int EVP_MD_CTX_copy(libressl_d.openssl.ossl_typ.EVP_MD_CTX* out_, const (libressl_d.openssl.ossl_typ.EVP_MD_CTX)* in_);
int EVP_DigestInit(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, const (libressl_d.openssl.ossl_typ.EVP_MD)* type);
int EVP_DigestFinal(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, ubyte* md, uint* s);

int EVP_read_pw_string(char* buf, int length, const (char)* prompt, int verify);
int EVP_read_pw_string_min(char* buf, int minlen, int maxlen, const (char)* prompt, int verify);
void EVP_set_pw_prompt(const (char)* prompt);
char* EVP_get_pw_prompt();

int EVP_BytesToKey(const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* type, const (libressl_d.openssl.ossl_typ.EVP_MD)* md, const (ubyte)* salt, const (ubyte)* data, int datal, int count, ubyte* key, ubyte* iv);

void EVP_CIPHER_CTX_set_flags(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, int flags);
void EVP_CIPHER_CTX_clear_flags(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, int flags);
int EVP_CIPHER_CTX_test_flags(const (libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX)* ctx, int flags);

int EVP_EncryptInit(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher, const (ubyte)* key, const (ubyte)* iv);
int EVP_EncryptInit_ex(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher, libressl_d.openssl.ossl_typ.ENGINE* impl, const (ubyte)* key, const (ubyte)* iv);
int EVP_EncryptUpdate(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl, const (ubyte)* in_, int inl);
int EVP_EncryptFinal_ex(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl);

version (LIBRESSL_INTERNAL) {
} else {
	int EVP_EncryptFinal(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl);
}

int EVP_DecryptInit(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher, const (ubyte)* key, const (ubyte)* iv);
int EVP_DecryptInit_ex(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher, libressl_d.openssl.ossl_typ.ENGINE* impl, const (ubyte)* key, const (ubyte)* iv);
int EVP_DecryptUpdate(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl, const (ubyte)* in_, int inl);
int EVP_DecryptFinal_ex(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, ubyte* outm, int* outl);

version (LIBRESSL_INTERNAL) {
} else {
	int EVP_DecryptFinal(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, ubyte* outm, int* outl);
}

int EVP_CipherInit(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher, const (ubyte)* key, const (ubyte)* iv, int enc);
int EVP_CipherInit_ex(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher, libressl_d.openssl.ossl_typ.ENGINE* impl, const (ubyte)* key, const (ubyte)* iv, int enc);
int EVP_CipherUpdate(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl, const (ubyte)* in_, int inl);
int EVP_CipherFinal_ex(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, ubyte* outm, int* outl);

version (LIBRESSL_INTERNAL) {
} else {
	int EVP_CipherFinal(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, ubyte* outm, int* outl);
}

int EVP_SignFinal(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, ubyte* md, uint* s, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);

int EVP_VerifyFinal(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, const (ubyte)* sigbuf, uint siglen, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);

int EVP_DigestSignInit(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, libressl_d.openssl.ossl_typ.EVP_PKEY_CTX** pctx, const (libressl_d.openssl.ossl_typ.EVP_MD)* type, libressl_d.openssl.ossl_typ.ENGINE* e, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
int EVP_DigestSignFinal(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, ubyte* sigret, size_t* siglen);

int EVP_DigestSign(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, ubyte* sigret, size_t* siglen, const (ubyte)* tbs, size_t tbslen);

int EVP_DigestVerifyInit(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, libressl_d.openssl.ossl_typ.EVP_PKEY_CTX** pctx, const (libressl_d.openssl.ossl_typ.EVP_MD)* type, libressl_d.openssl.ossl_typ.ENGINE* e, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
int EVP_DigestVerifyFinal(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, const (ubyte)* sig, size_t siglen);

int EVP_DigestVerify(libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx, const (ubyte)* sigret, size_t siglen, const (ubyte)* tbs, size_t tbslen);

int EVP_OpenInit(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* type, const (ubyte)* ek, int ekl, const (ubyte)* iv, libressl_d.openssl.ossl_typ.EVP_PKEY* priv);
int EVP_OpenFinal(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl);

int EVP_SealInit(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* type, ubyte** ek, int* ekl, ubyte* iv, libressl_d.openssl.ossl_typ.EVP_PKEY** pubk, int npubk);
int EVP_SealFinal(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl);

libressl_d.openssl.ossl_typ.EVP_ENCODE_CTX* EVP_ENCODE_CTX_new();
void EVP_ENCODE_CTX_free(libressl_d.openssl.ossl_typ.EVP_ENCODE_CTX* ctx);
void EVP_EncodeInit(libressl_d.openssl.ossl_typ.EVP_ENCODE_CTX* ctx);
int EVP_EncodeUpdate(libressl_d.openssl.ossl_typ.EVP_ENCODE_CTX* ctx, ubyte* out_, int* outl, const (ubyte)* in_, int inl);
void EVP_EncodeFinal(libressl_d.openssl.ossl_typ.EVP_ENCODE_CTX* ctx, ubyte* out_, int* outl);
int EVP_EncodeBlock(ubyte* t, const (ubyte)* f, int n);

void EVP_DecodeInit(libressl_d.openssl.ossl_typ.EVP_ENCODE_CTX* ctx);
int EVP_DecodeUpdate(libressl_d.openssl.ossl_typ.EVP_ENCODE_CTX* ctx, ubyte* out_, int* outl, const (ubyte)* in_, int inl);
int EVP_DecodeFinal(libressl_d.openssl.ossl_typ.EVP_ENCODE_CTX* ctx, ubyte* out_, int* outl);
int EVP_DecodeBlock(ubyte* t, const (ubyte)* f, int n);

void EVP_CIPHER_CTX_init(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* a);
int EVP_CIPHER_CTX_cleanup(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* a);
libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* EVP_CIPHER_CTX_new();
void EVP_CIPHER_CTX_free(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* a);
int EVP_CIPHER_CTX_reset(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* a);
int EVP_CIPHER_CTX_set_key_length(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* x, int keylen);
int EVP_CIPHER_CTX_set_padding(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* c, int pad);
int EVP_CIPHER_CTX_ctrl(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr_);
int EVP_CIPHER_CTX_rand_key(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, ubyte* key);

version (OPENSSL_NO_BIO) {
} else {
	const (.BIO_METHOD)* BIO_f_md();
	const (.BIO_METHOD)* BIO_f_base64();
	const (.BIO_METHOD)* BIO_f_cipher();
	int BIO_set_cipher(libressl_d.openssl.ossl_typ.BIO* b, const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* c, const (ubyte)* k, const (ubyte)* i, int enc);
}

const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_md_null();

version (OPENSSL_NO_MD4) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_md4();
}

version (OPENSSL_NO_MD5) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_md5();
	const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_md5_sha1();
}

version (OPENSSL_NO_SHA) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_sha1();
}

version (OPENSSL_NO_SHA256) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_sha224();
	const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_sha256();
}

version (OPENSSL_NO_SHA512) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_sha384();
	const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_sha512();
}

version (OPENSSL_NO_SM3) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_sm3();
}

version (OPENSSL_NO_RIPEMD) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_ripemd160();
}

version (OPENSSL_NO_WHIRLPOOL) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_whirlpool();
}

version (OPENSSL_NO_GOST) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_gostr341194();
	const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_gost2814789imit();
	const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_streebog256();
	const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_streebog512();
}

/**
 * does nothing :-\)
 */
const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_enc_null();

version (OPENSSL_NO_DES) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_ecb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_ede();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_ede3();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_ede_ecb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_ede3_ecb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_cfb64();
	alias EVP_des_cfb = .EVP_des_cfb64;
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_cfb1();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_cfb8();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_ede_cfb64();
	alias EVP_des_ede_cfb = .EVP_des_ede_cfb64;
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_ede3_cfb64();
	alias EVP_des_ede3_cfb = .EVP_des_ede3_cfb64;
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_ede3_cfb1();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_ede3_cfb8();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_ofb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_ede_ofb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_ede3_ofb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_cbc();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_ede_cbc();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_des_ede3_cbc();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_desx_cbc();
}

version (OPENSSL_NO_RC4) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_rc4();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_rc4_40();

	version (OPENSSL_NO_MD5) {
	} else {
		const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_rc4_hmac_md5();
	}
}

version (OPENSSL_NO_IDEA) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_idea_ecb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_idea_cfb64();
	alias EVP_idea_cfb = .EVP_idea_cfb64;
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_idea_ofb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_idea_cbc();
}

version (OPENSSL_NO_RC2) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_rc2_ecb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_rc2_cbc();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_rc2_40_cbc();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_rc2_64_cbc();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_rc2_cfb64();
	alias EVP_rc2_cfb = .EVP_rc2_cfb64;
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_rc2_ofb();
}

version (OPENSSL_NO_BF) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_bf_ecb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_bf_cbc();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_bf_cfb64();
	alias EVP_bf_cfb = .EVP_bf_cfb64;
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_bf_ofb();
}

version (OPENSSL_NO_CAST) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_cast5_ecb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_cast5_cbc();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_cast5_cfb64();
	alias EVP_cast5_cfb = .EVP_cast5_cfb64;
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_cast5_ofb();
}

version (OPENSSL_NO_AES) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_128_ecb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_128_cbc();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_128_cfb1();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_128_cfb8();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_128_cfb128();
	alias EVP_aes_128_cfb = .EVP_aes_128_cfb128;
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_128_ofb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_128_ctr();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_128_ccm();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_128_gcm();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_128_wrap();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_128_xts();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_192_ecb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_192_cbc();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_192_cfb1();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_192_cfb8();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_192_cfb128();
	alias EVP_aes_192_cfb = .EVP_aes_192_cfb128;
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_192_ofb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_192_ctr();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_192_ccm();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_192_gcm();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_192_wrap();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_256_ecb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_256_cbc();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_256_cfb1();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_256_cfb8();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_256_cfb128();
	alias EVP_aes_256_cfb = .EVP_aes_256_cfb128;
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_256_ofb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_256_ctr();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_256_ccm();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_256_gcm();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_256_wrap();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_256_xts();

	version (OPENSSL_NO_CHACHA) {
	} else {
		version (OPENSSL_NO_POLY1305) {
		} else {
			const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_chacha20_poly1305();
		}
	}

	version (OPENSSL_NO_SHA) {
	} else {
		version (OPENSSL_NO_SHA1) {
		} else {
			const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_128_cbc_hmac_sha1();
			const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_aes_256_cbc_hmac_sha1();
		}
	}
}

version (OPENSSL_NO_CAMELLIA) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_128_ecb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_128_cbc();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_128_cfb1();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_128_cfb8();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_128_cfb128();
	alias EVP_camellia_128_cfb = .EVP_camellia_128_cfb128;
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_128_ofb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_192_ecb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_192_cbc();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_192_cfb1();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_192_cfb8();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_192_cfb128();
	alias EVP_camellia_192_cfb = .EVP_camellia_192_cfb128;
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_192_ofb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_256_ecb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_256_cbc();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_256_cfb1();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_256_cfb8();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_256_cfb128();
	alias EVP_camellia_256_cfb = .EVP_camellia_256_cfb128;
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_camellia_256_ofb();
}

version (OPENSSL_NO_CHACHA) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_chacha20();
}

version (OPENSSL_NO_GOST) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_gost2814789_ecb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_gost2814789_cfb64();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_gost2814789_cnt();
}

version (OPENSSL_NO_SM4) {
} else {
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_sm4_ecb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_sm4_cbc();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_sm4_cfb128();
	alias EVP_sm4_cfb = .EVP_sm4_cfb128;
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_sm4_ofb();
	const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_sm4_ctr();
}

void OPENSSL_add_all_algorithms_noconf();
void OPENSSL_add_all_algorithms_conf();

version (OPENSSL_LOAD_CONF) {
	alias OpenSSL_add_all_algorithms = .OPENSSL_add_all_algorithms_conf;
} else {
	alias OpenSSL_add_all_algorithms = .OPENSSL_add_all_algorithms_noconf;
}

void OpenSSL_add_all_ciphers();
void OpenSSL_add_all_digests();

alias SSLeay_add_all_algorithms = .OpenSSL_add_all_algorithms;
alias SSLeay_add_all_ciphers = .OpenSSL_add_all_ciphers;
alias SSLeay_add_all_digests = .OpenSSL_add_all_digests;

int EVP_add_cipher(const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher);
int EVP_add_digest(const (libressl_d.openssl.ossl_typ.EVP_MD)* digest);

const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* EVP_get_cipherbyname(const (char)* name);
const (libressl_d.openssl.ossl_typ.EVP_MD)* EVP_get_digestbyname(const (char)* name);
void EVP_cleanup();

private alias EVP_CIPHER_do_all_func = /* Temporary type */ extern (C) nothrow @nogc void function(const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* ciph, const (char)* from, const (char)* to, void* x);
void EVP_CIPHER_do_all(.EVP_CIPHER_do_all_func fn, void* arg);

private alias EVP_CIPHER_do_all_sorted_func = /* Temporary type */ extern (C) nothrow @nogc void function(const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* ciph, const (char)* from, const (char)* to, void* x);
void EVP_CIPHER_do_all_sorted(.EVP_CIPHER_do_all_sorted_func fn, void* arg);

private alias EVP_MD_do_all_func = /* Temporary type */ extern (C) nothrow @nogc void function(const (libressl_d.openssl.ossl_typ.EVP_MD)* ciph, const (char)* from, const (char)* to, void* x);
void EVP_MD_do_all(.EVP_MD_do_all_func fn, void* arg);

private alias EVP_MD_do_all_sorted_func = /* Temporary type */ extern (C) nothrow @nogc void function(const (libressl_d.openssl.ossl_typ.EVP_MD)* ciph, const (char)* from, const (char)* to, void* x);
void EVP_MD_do_all_sorted(.EVP_MD_do_all_sorted_func fn, void* arg);

int EVP_PKEY_decrypt_old(ubyte* dec_key, const (ubyte)* enc_key, int enc_key_len, libressl_d.openssl.ossl_typ.EVP_PKEY* private_key);
int EVP_PKEY_encrypt_old(ubyte* enc_key, const (ubyte)* key, int key_len, libressl_d.openssl.ossl_typ.EVP_PKEY* pub_key);
int EVP_PKEY_type(int type);
int EVP_PKEY_id(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey);
int EVP_PKEY_base_id(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey);
int EVP_PKEY_bits(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey);
int EVP_PKEY_security_bits(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey);
int EVP_PKEY_size(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey);
int EVP_PKEY_set_type(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, int type);
int EVP_PKEY_set_type_str(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, const (char)* str, int len);
int EVP_PKEY_assign(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, int type, void* key);
void* EVP_PKEY_get0(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey);
const (ubyte)* EVP_PKEY_get0_hmac(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey, size_t* len);

version (OPENSSL_NO_RSA) {
} else {
	version (none) {
		struct rsa_st;
	}

	libressl_d.openssl.ossl_typ.rsa_st* EVP_PKEY_get0_RSA(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
	libressl_d.openssl.ossl_typ.rsa_st* EVP_PKEY_get1_RSA(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
	int EVP_PKEY_set1_RSA(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, libressl_d.openssl.ossl_typ.rsa_st* key);
}

version (OPENSSL_NO_DSA) {
} else {
	version (none) {
		struct dsa_st;
	}

	libressl_d.openssl.ossl_typ.dsa_st* EVP_PKEY_get0_DSA(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
	libressl_d.openssl.ossl_typ.dsa_st* EVP_PKEY_get1_DSA(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
	int EVP_PKEY_set1_DSA(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, libressl_d.openssl.ossl_typ.dsa_st* key);
}

version (OPENSSL_NO_DH) {
} else {
	version (none) {
		struct dh_st;
	}

	libressl_d.openssl.ossl_typ.dh_st* EVP_PKEY_get0_DH(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
	libressl_d.openssl.ossl_typ.dh_st* EVP_PKEY_get1_DH(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
	int EVP_PKEY_set1_DH(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, libressl_d.openssl.ossl_typ.dh_st* key);
}

version (OPENSSL_NO_EC) {
} else {
	libressl_d.openssl.ec.ec_key_st* EVP_PKEY_get0_EC_KEY(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
	libressl_d.openssl.ec.ec_key_st* EVP_PKEY_get1_EC_KEY(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
	int EVP_PKEY_set1_EC_KEY(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, libressl_d.openssl.ec.ec_key_st* key);
}

libressl_d.openssl.ossl_typ.EVP_PKEY* EVP_PKEY_new();
void EVP_PKEY_free(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
int EVP_PKEY_up_ref(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);

libressl_d.openssl.ossl_typ.EVP_PKEY* d2i_PublicKey(int type, libressl_d.openssl.ossl_typ.EVP_PKEY** a, const (ubyte)** pp, core.stdc.config.c_long length_);
int i2d_PublicKey(libressl_d.openssl.ossl_typ.EVP_PKEY* a, ubyte** pp);

libressl_d.openssl.ossl_typ.EVP_PKEY* d2i_PrivateKey(int type, libressl_d.openssl.ossl_typ.EVP_PKEY** a, const (ubyte)** pp, core.stdc.config.c_long length_);
libressl_d.openssl.ossl_typ.EVP_PKEY* d2i_AutoPrivateKey(libressl_d.openssl.ossl_typ.EVP_PKEY** a, const (ubyte)** pp, core.stdc.config.c_long length_);
int i2d_PrivateKey(libressl_d.openssl.ossl_typ.EVP_PKEY* a, ubyte** pp);

int EVP_PKEY_copy_parameters(libressl_d.openssl.ossl_typ.EVP_PKEY* to, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* from);
int EVP_PKEY_missing_parameters(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey);
int EVP_PKEY_save_parameters(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, int mode);
int EVP_PKEY_cmp_parameters(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* a, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* b);

int EVP_PKEY_cmp(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* a, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* b);

int EVP_PKEY_print_public(libressl_d.openssl.ossl_typ.BIO* out_, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey, int indent, libressl_d.openssl.ossl_typ.ASN1_PCTX* pctx);
int EVP_PKEY_print_private(libressl_d.openssl.ossl_typ.BIO* out_, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey, int indent, libressl_d.openssl.ossl_typ.ASN1_PCTX* pctx);
int EVP_PKEY_print_params(libressl_d.openssl.ossl_typ.BIO* out_, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey, int indent, libressl_d.openssl.ossl_typ.ASN1_PCTX* pctx);

int EVP_PKEY_get_default_digest_nid(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, int* pnid);

int EVP_CIPHER_type(const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* ctx);

/* calls methods */
int EVP_CIPHER_param_to_asn1(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* c, libressl_d.openssl.asn1.ASN1_TYPE* type);
int EVP_CIPHER_asn1_to_param(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* c, libressl_d.openssl.asn1.ASN1_TYPE* type);

/* These are used by EVP_CIPHER methods */
int EVP_CIPHER_set_asn1_iv(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* c, libressl_d.openssl.asn1.ASN1_TYPE* type);
int EVP_CIPHER_get_asn1_iv(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* c, libressl_d.openssl.asn1.ASN1_TYPE* type);

/* PKCS5 password based encryption */
int PKCS5_PBE_keyivgen(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, const (char)* pass, int passlen, libressl_d.openssl.asn1.ASN1_TYPE* param, const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher, const (libressl_d.openssl.ossl_typ.EVP_MD)* md, int en_de);
int PKCS5_PBKDF2_HMAC_SHA1(const (char)* pass, int passlen, const (ubyte)* salt, int saltlen, int iter, int keylen, ubyte* out_);
int PKCS5_PBKDF2_HMAC(const (char)* pass, int passlen, const (ubyte)* salt, int saltlen, int iter, const (libressl_d.openssl.ossl_typ.EVP_MD)* digest, int keylen, ubyte* out_);
int PKCS5_v2_PBE_keyivgen(libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, const (char)* pass, int passlen, libressl_d.openssl.asn1.ASN1_TYPE* param, const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher, const (libressl_d.openssl.ossl_typ.EVP_MD)* md, int en_de);

void PKCS5_PBE_add();

int EVP_PBE_CipherInit(libressl_d.openssl.ossl_typ.ASN1_OBJECT* pbe_obj, const (char)* pass, int passlen, libressl_d.openssl.asn1.ASN1_TYPE* param, libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, int en_de);

/* PBE type */

/**
 * Can appear as the outermost AlgorithmIdentifier
 */
enum EVP_PBE_TYPE_OUTER = 0x00;

/**
 * Is an PRF type OID
 */
enum EVP_PBE_TYPE_PRF = 0x01;

int EVP_PBE_alg_add_type(int pbe_type, int pbe_nid, int cipher_nid, int md_nid, .EVP_PBE_KEYGEN keygen);
int EVP_PBE_alg_add(int nid, const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher, const (libressl_d.openssl.ossl_typ.EVP_MD)* md, .EVP_PBE_KEYGEN keygen);
int EVP_PBE_find(int type, int pbe_nid, int* pcnid, int* pmnid, .EVP_PBE_KEYGEN* pkeygen);
void EVP_PBE_cleanup();

enum ASN1_PKEY_ALIAS = 0x01;
enum ASN1_PKEY_DYNAMIC = 0x02;
enum ASN1_PKEY_SIGPARAM_NULL = 0x04;

enum ASN1_PKEY_CTRL_PKCS7_SIGN = 0x01;
enum ASN1_PKEY_CTRL_PKCS7_ENCRYPT = 0x02;
enum ASN1_PKEY_CTRL_DEFAULT_MD_NID = 0x03;
enum ASN1_PKEY_CTRL_CMS_SIGN = 0x05;
enum ASN1_PKEY_CTRL_CMS_ENVELOPE = 0x07;
enum ASN1_PKEY_CTRL_CMS_RI_TYPE = 0x08;

int EVP_PKEY_asn1_get_count();
const (libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD)* EVP_PKEY_asn1_get0(int idx);
const (libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD)* EVP_PKEY_asn1_find(libressl_d.openssl.ossl_typ.ENGINE** pe, int type);
const (libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD)* EVP_PKEY_asn1_find_str(libressl_d.openssl.ossl_typ.ENGINE** pe, const (char)* str, int len);
int EVP_PKEY_asn1_add0(const (libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD)* ameth);
int EVP_PKEY_asn1_add_alias(int to, int from);
int EVP_PKEY_asn1_get0_info(int* ppkey_id, int* pkey_base_id, int* ppkey_flags, const (char)** pinfo, const (char)** ppem_str, const (libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD)* ameth);

const (libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD)* EVP_PKEY_get0_asn1(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey);
libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD* EVP_PKEY_asn1_new(int id, int flags, const (char)* pem_str, const (char)* info);
void EVP_PKEY_asn1_copy(libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD* dst, const (libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD)* src);
void EVP_PKEY_asn1_free(libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD* ameth);

private alias EVP_PKEY_asn1_set_public_pub_decode_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY* pk, libressl_d.openssl.ossl_typ.X509_PUBKEY* pub);
private alias EVP_PKEY_asn1_set_public_pub_encode_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.X509_PUBKEY* pub, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pk);
private alias EVP_PKEY_asn1_set_public_pub_cmp_func = /* Temporary type */ extern (C) nothrow @nogc int function(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* a, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* b);
private alias EVP_PKEY_asn1_set_public_pub_print_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.BIO* out_, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey, int indent, libressl_d.openssl.ossl_typ.ASN1_PCTX* pctx);
private alias EVP_PKEY_asn1_set_public_pkey_size_func = /* Temporary type */ extern (C) nothrow @nogc int function(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pk);
private alias EVP_PKEY_asn1_set_public_pkey_bits_func = /* Temporary type */ extern (C) nothrow @nogc int function(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pk);
void EVP_PKEY_asn1_set_public(libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD* ameth, .EVP_PKEY_asn1_set_public_pub_decode_func pub_decode, .EVP_PKEY_asn1_set_public_pub_encode_func pub_encode, .EVP_PKEY_asn1_set_public_pub_cmp_func pub_cmp, .EVP_PKEY_asn1_set_public_pub_print_func pub_print, .EVP_PKEY_asn1_set_public_pkey_size_func pkey_size, .EVP_PKEY_asn1_set_public_pkey_bits_func pkey_bits);

private alias EVP_PKEY_asn1_set_private_func1 = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY* pk, const (libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO)* p8inf);
private alias EVP_PKEY_asn1_set_private_func2 = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* p8, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pk);
private alias EVP_PKEY_asn1_set_private_func3 = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.BIO* out_, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey, int indent, libressl_d.openssl.ossl_typ.ASN1_PCTX* pctx);
void EVP_PKEY_asn1_set_private(libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD* ameth, .EVP_PKEY_asn1_set_private_func1 priv_decode, .EVP_PKEY_asn1_set_private_func2 priv_encode, .EVP_PKEY_asn1_set_private_func3 priv_print);

private alias EVP_PKEY_asn1_set_param_decode_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, const (ubyte)** pder, int derlen);
private alias EVP_PKEY_asn1_set_param_encode_func = /* Temporary type */ extern (C) nothrow @nogc int function(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey, ubyte** pder);
private alias EVP_PKEY_asn1_set_param_missing_func = /* Temporary type */ extern (C) nothrow @nogc int function(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pk);
private alias EVP_PKEY_asn1_set_param_copy_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY* to, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* from);
private alias EVP_PKEY_asn1_set_param_cmp_func = /* Temporary type */ extern (C) nothrow @nogc int function(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* a, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* b);
private alias EVP_PKEY_asn1_set_param_print_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.BIO* out_, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey, int indent, libressl_d.openssl.ossl_typ.ASN1_PCTX* pctx);
void EVP_PKEY_asn1_set_param(libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD* ameth, .EVP_PKEY_asn1_set_param_decode_func param_decode, .EVP_PKEY_asn1_set_param_encode_func param_encode, .EVP_PKEY_asn1_set_param_missing_func param_missing, .EVP_PKEY_asn1_set_param_copy_func param_copy, .EVP_PKEY_asn1_set_param_cmp_func param_cmp, .EVP_PKEY_asn1_set_param_print_func param_print);

private alias EVP_PKEY_asn1_set_free_func = /* Temporary type */ extern (C) nothrow @nogc void function(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
void EVP_PKEY_asn1_set_free(libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD* ameth, .EVP_PKEY_asn1_set_free_func pkey_free);

private alias EVP_PKEY_asn1_set_ctrl_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, int op, core.stdc.config.c_long arg1, void* arg2);
void EVP_PKEY_asn1_set_ctrl(libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD* ameth, .EVP_PKEY_asn1_set_ctrl_func pkey_ctrl);

private alias EVP_PKEY_asn1_set_security_bits_func = /* Temporary type */ extern (C) nothrow @nogc int function(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey);
void EVP_PKEY_asn1_set_security_bits(libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD* ameth, .EVP_PKEY_asn1_set_security_bits_func pkey_security_bits);

private alias EVP_PKEY_asn1_set_check_func = /* Temporary type */ extern (C) nothrow @nogc int function(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pk);
void EVP_PKEY_asn1_set_check(libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD* ameth, .EVP_PKEY_asn1_set_check_func pkey_check);

private alias EVP_PKEY_asn1_set_public_check_func = /* Temporary type */ extern (C) nothrow @nogc int function(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pk);
void EVP_PKEY_asn1_set_public_check(libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD* ameth, .EVP_PKEY_asn1_set_public_check_func pkey_public_check);

private alias EVP_PKEY_asn1_set_param_check_func = /* Temporary type */ extern (C) nothrow @nogc int function(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pk);
void EVP_PKEY_asn1_set_param_check(libressl_d.openssl.ossl_typ.EVP_PKEY_ASN1_METHOD* ameth, .EVP_PKEY_asn1_set_param_check_func pkey_check);

enum EVP_PKEY_OP_UNDEFINED = 0;
enum EVP_PKEY_OP_PARAMGEN = 1 << 1;
enum EVP_PKEY_OP_KEYGEN = 1 << 2;
enum EVP_PKEY_OP_SIGN = 1 << 3;
enum EVP_PKEY_OP_VERIFY = 1 << 4;
enum EVP_PKEY_OP_VERIFYRECOVER = 1 << 5;
enum EVP_PKEY_OP_SIGNCTX = 1 << 6;
enum EVP_PKEY_OP_VERIFYCTX = 1 << 7;
enum EVP_PKEY_OP_ENCRYPT = 1 << 8;
enum EVP_PKEY_OP_DECRYPT = 1 << 9;
enum EVP_PKEY_OP_DERIVE = 1 << 10;

enum EVP_PKEY_OP_TYPE_SIG = .EVP_PKEY_OP_SIGN | .EVP_PKEY_OP_VERIFY | .EVP_PKEY_OP_VERIFYRECOVER | .EVP_PKEY_OP_SIGNCTX | .EVP_PKEY_OP_VERIFYCTX;

enum EVP_PKEY_OP_TYPE_CRYPT = .EVP_PKEY_OP_ENCRYPT | .EVP_PKEY_OP_DECRYPT;

//enum EVP_PKEY_OP_TYPE_NOGEN = EVP_PKEY_OP_SIG | EVP_PKEY_OP_CRYPT | .EVP_PKEY_OP_DERIVE;

enum EVP_PKEY_OP_TYPE_GEN = .EVP_PKEY_OP_PARAMGEN | .EVP_PKEY_OP_KEYGEN;

pragma(inline, true)
int EVP_PKEY_CTX_set_signature_md(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* md)

	do
	{
		return .EVP_PKEY_CTX_ctrl(ctx, -1, .EVP_PKEY_OP_TYPE_SIG, .EVP_PKEY_CTRL_MD, 0, md);
	}

pragma(inline, true)
int EVP_PKEY_CTX_get_signature_md(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* pmd)

	do
	{
		return .EVP_PKEY_CTX_ctrl(ctx, -1, .EVP_PKEY_OP_TYPE_SIG, .EVP_PKEY_CTRL_GET_MD, 0, pmd);
	}

enum EVP_PKEY_CTRL_MD = 1;
enum EVP_PKEY_CTRL_PEER_KEY = 2;

enum EVP_PKEY_CTRL_PKCS7_ENCRYPT = 3;
enum EVP_PKEY_CTRL_PKCS7_DECRYPT = 4;

enum EVP_PKEY_CTRL_PKCS7_SIGN = 5;

enum EVP_PKEY_CTRL_SET_MAC_KEY = 6;

enum EVP_PKEY_CTRL_DIGESTINIT = 7;

/**
 * Used by GOST key encryption in TLS
 */
enum EVP_PKEY_CTRL_SET_IV = 8;

enum EVP_PKEY_CTRL_CMS_ENCRYPT = 9;
enum EVP_PKEY_CTRL_CMS_DECRYPT = 10;
enum EVP_PKEY_CTRL_CMS_SIGN = 11;

enum EVP_PKEY_CTRL_CIPHER = 12;

enum EVP_PKEY_CTRL_GET_MD = 13;

enum EVP_PKEY_ALG_CTRL = 0x1000;

enum EVP_PKEY_FLAG_AUTOARGLEN = 2;

/**
 * Method handles all operations: don't assume any digest related
 * defaults.
 */
enum EVP_PKEY_FLAG_SIGCTX_CUSTOM = 4;

const (libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD)* EVP_PKEY_meth_find(int type);
libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* EVP_PKEY_meth_new(int id, int flags);
void EVP_PKEY_meth_get0_info(int* ppkey_id, int* pflags, const (libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD)* meth);
void EVP_PKEY_meth_copy(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* dst, const (libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD)* src);
void EVP_PKEY_meth_free(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth);
int EVP_PKEY_meth_add0(const (libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD)* pmeth);

libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* EVP_PKEY_CTX_new(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, libressl_d.openssl.ossl_typ.ENGINE* e);
libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* EVP_PKEY_CTX_new_id(int id, libressl_d.openssl.ossl_typ.ENGINE* e);
libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* EVP_PKEY_CTX_dup(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
void EVP_PKEY_CTX_free(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);

int EVP_PKEY_CTX_ctrl(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int keytype, int optype, int cmd, int p1, void* p2);
int EVP_PKEY_CTX_ctrl_str(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, const (char)* type, const (char)* value);

int EVP_PKEY_CTX_get_operation(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
void EVP_PKEY_CTX_set0_keygen_info(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int* dat, int datlen);

libressl_d.openssl.ossl_typ.EVP_PKEY* EVP_PKEY_new_mac_key(int type, libressl_d.openssl.ossl_typ.ENGINE* e, const (ubyte)* key, int keylen);
libressl_d.openssl.ossl_typ.EVP_PKEY* EVP_PKEY_new_CMAC_key(libressl_d.openssl.ossl_typ.ENGINE* e, const (ubyte)* priv, size_t len, const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher);

void EVP_PKEY_CTX_set_data(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* data);
void* EVP_PKEY_CTX_get_data(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
libressl_d.openssl.ossl_typ.EVP_PKEY* EVP_PKEY_CTX_get0_pkey(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);

libressl_d.openssl.ossl_typ.EVP_PKEY* EVP_PKEY_CTX_get0_peerkey(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);

void EVP_PKEY_CTX_set_app_data(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* data);
void* EVP_PKEY_CTX_get_app_data(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);

int EVP_PKEY_sign_init(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
int EVP_PKEY_sign(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, ubyte* sig, size_t* siglen, const (ubyte)* tbs, size_t tbslen);
int EVP_PKEY_verify_init(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
int EVP_PKEY_verify(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, const (ubyte)* sig, size_t siglen, const (ubyte)* tbs, size_t tbslen);
int EVP_PKEY_verify_recover_init(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
int EVP_PKEY_verify_recover(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, ubyte* rout, size_t* routlen, const (ubyte)* sig, size_t siglen);
int EVP_PKEY_encrypt_init(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
int EVP_PKEY_encrypt(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, ubyte* out_, size_t* outlen, const (ubyte)* in_, size_t inlen);
int EVP_PKEY_decrypt_init(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
int EVP_PKEY_decrypt(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, ubyte* out_, size_t* outlen, const (ubyte)* in_, size_t inlen);

int EVP_PKEY_derive_init(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
int EVP_PKEY_derive_set_peer(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, libressl_d.openssl.ossl_typ.EVP_PKEY* peer);
int EVP_PKEY_derive(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, ubyte* key, size_t* keylen);

private alias EVP_PKEY_gen_cb = /* Not a function pointer type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);

int EVP_PKEY_paramgen_init(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
int EVP_PKEY_paramgen(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, libressl_d.openssl.ossl_typ.EVP_PKEY** ppkey);
int EVP_PKEY_keygen_init(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
int EVP_PKEY_keygen(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, libressl_d.openssl.ossl_typ.EVP_PKEY** ppkey);
int EVP_PKEY_check(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
int EVP_PKEY_public_check(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
int EVP_PKEY_param_check(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);

void EVP_PKEY_CTX_set_cb(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, .EVP_PKEY_gen_cb cb);
.EVP_PKEY_gen_cb EVP_PKEY_CTX_get_cb(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);

int EVP_PKEY_CTX_get_keygen_info(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int idx);

private alias EVP_PKEY_meth_set_init_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
void EVP_PKEY_meth_set_init(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_init_func init);

private alias EVP_PKEY_meth_set_copy_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* dst, libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* src);
void EVP_PKEY_meth_set_copy(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_copy_func copy);

private alias EVP_PKEY_meth_set_cleanup_func = /* Temporary type */ extern (C) nothrow @nogc void function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
void EVP_PKEY_meth_set_cleanup(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_cleanup_func cleanup);

private alias EVP_PKEY_meth_set_paramgen_func1 = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
private alias EVP_PKEY_meth_set_paramgen_func2 = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
void EVP_PKEY_meth_set_paramgen(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_paramgen_func1 paramgen_init, .EVP_PKEY_meth_set_paramgen_func2 paramgen);

private alias EVP_PKEY_meth_set_keygen_func1 = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
private alias EVP_PKEY_meth_set_keygen_func2 = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
void EVP_PKEY_meth_set_keygen(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_keygen_func1 keygen_init, .EVP_PKEY_meth_set_keygen_func2 keygen);

private alias EVP_PKEY_meth_set_sign_init_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
private alias EVP_PKEY_meth_set_sign_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, ubyte* sig, size_t* siglen, const (ubyte)* tbs, size_t tbslen);
void EVP_PKEY_meth_set_sign(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_sign_init_func sign_init, .EVP_PKEY_meth_set_sign_func sign);

private alias EVP_PKEY_meth_set_verify_init_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
private alias EVP_PKEY_meth_set_verify_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, const (ubyte)* sig, size_t siglen, const (ubyte)* tbs, size_t tbslen);
void EVP_PKEY_meth_set_verify(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_verify_init_func verify_init, .EVP_PKEY_meth_set_verify_func verify);

private alias EVP_PKEY_meth_set_verify_recover_init_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
private alias EVP_PKEY_meth_set_verify_recover_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, ubyte* sig, size_t* siglen, const (ubyte)* tbs, size_t tbslen);
void EVP_PKEY_meth_set_verify_recover(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_verify_recover_init_func verify_recover_init, .EVP_PKEY_meth_set_verify_recover_func verify_recover);

private alias EVP_PKEY_meth_set_signctx_init_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, libressl_d.openssl.ossl_typ.EVP_MD_CTX* mctx);
private alias EVP_PKEY_meth_set_signctx_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, ubyte* sig, size_t* siglen, libressl_d.openssl.ossl_typ.EVP_MD_CTX* mctx);
void EVP_PKEY_meth_set_signctx(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_signctx_init_func signctx_init, .EVP_PKEY_meth_set_signctx_func signctx);

private alias EVP_PKEY_meth_set_verifyctx_init_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, libressl_d.openssl.ossl_typ.EVP_MD_CTX* mctx);
private alias EVP_PKEY_meth_set_verifyctx_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, const (ubyte)* sig, int siglen, libressl_d.openssl.ossl_typ.EVP_MD_CTX* mctx);
void EVP_PKEY_meth_set_verifyctx(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_verifyctx_init_func verifyctx_init, .EVP_PKEY_meth_set_verifyctx_func verifyctx);

private alias EVP_PKEY_meth_set_encrypt_init_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
private alias EVP_PKEY_meth_set_encrypt_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, ubyte* out_, size_t* outlen, const (ubyte)* in_, size_t inlen);
void EVP_PKEY_meth_set_encrypt(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_encrypt_init_func encrypt_init, .EVP_PKEY_meth_set_encrypt_func encryptfn);

private alias EVP_PKEY_meth_set_decrypt_init_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
private alias EVP_PKEY_meth_set_decrypt_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, ubyte* out_, size_t* outlen, const (ubyte)* in_, size_t inlen);
void EVP_PKEY_meth_set_decrypt(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_decrypt_init_func decrypt_init, .EVP_PKEY_meth_set_decrypt_func decrypt);

private alias EVP_PKEY_meth_set_derive_init_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx);
private alias EVP_PKEY_meth_set_derive_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, ubyte* key, size_t* keylen);
void EVP_PKEY_meth_set_derive(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_derive_init_func derive_init, .EVP_PKEY_meth_set_derive_func derive);

private alias EVP_PKEY_meth_set_ctrl_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int type, int p1, void* p2);
private alias EVP_PKEY_meth_set_ctrl_str_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, const (char)* type, const (char)* value);
void EVP_PKEY_meth_set_ctrl(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_ctrl_func ctrl, .EVP_PKEY_meth_set_ctrl_str_func ctrl_str);
 
private alias EVP_PKEY_meth_set_check_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
void EVP_PKEY_meth_set_check(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_check_func check);

private alias EVP_PKEY_meth_set_public_check_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
void EVP_PKEY_meth_set_public_check(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_public_check_func public_check);

private alias EVP_PKEY_meth_set_param_check_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
void EVP_PKEY_meth_set_param_check(libressl_d.openssl.ossl_typ.EVP_PKEY_METHOD* pmeth, .EVP_PKEY_meth_set_param_check_func param_check);

/*
 * Authenticated Encryption with Additional Data.
 *
 * AEAD couples confidentiality and integrity in a single primtive. AEAD
 * algorithms take a key and then can seal and open individual messages. Each
 * message has a unique, per-message nonce and, optionally, additional data
 * which is authenticated but not included in the output.
 */

struct evp_aead_st;
alias EVP_AEAD = .evp_aead_st;

version (OPENSSL_NO_AES) {
} else {
	/**
	 * EVP_aes_128_gcm is AES-128 in Galois Counter Mode.
	 */
	const (.EVP_AEAD)* EVP_aead_aes_128_gcm();

	/**
	 * EVP_aes_256_gcm is AES-256 in Galois Counter Mode.
	 */
	const (.EVP_AEAD)* EVP_aead_aes_256_gcm();
}

version (OPENSSL_NO_CHACHA) {
} else {
	version (OPENSSL_NO_POLY1305) {
	} else {
		/**
		 * EVP_aead_chacha20_poly1305 is ChaCha20 with a Poly1305 authenticator.
		 */
		const (.EVP_AEAD)* EVP_aead_chacha20_poly1305();

		/**
		 * EVP_aead_xchacha20_poly1305 is XChaCha20 with a Poly1305 authenticator.
		 */
		const (.EVP_AEAD)* EVP_aead_xchacha20_poly1305();
	}
}

/**
 * EVP_AEAD_key_length returns the length of the keys used.
 */
size_t EVP_AEAD_key_length(const (.EVP_AEAD)* aead);

/**
 * EVP_AEAD_nonce_length returns the length of the per-message nonce.
 */
size_t EVP_AEAD_nonce_length(const (.EVP_AEAD)* aead);

/**
 * EVP_AEAD_max_overhead returns the maximum number of additional bytes added
 * by the act of sealing data with the AEAD.
 */
size_t EVP_AEAD_max_overhead(const (.EVP_AEAD)* aead);

/**
 * EVP_AEAD_max_tag_len returns the maximum tag length when using this AEAD.
 * This * is the largest value that can be passed as a tag length to
 * EVP_AEAD_CTX_init.
 */
size_t EVP_AEAD_max_tag_len(const (.EVP_AEAD)* aead);

/**
 * An EVP_AEAD_CTX represents an AEAD algorithm configured with a specific key
 * and message-independent IV.
 */
struct evp_aead_ctx_st;
alias EVP_AEAD_CTX = .evp_aead_ctx_st;

/**
 * EVP_AEAD_MAX_TAG_LENGTH is the maximum tag length used by any AEAD
 * defined in this header.
 */
enum EVP_AEAD_MAX_TAG_LENGTH = 16;

/**
 * EVP_AEAD_DEFAULT_TAG_LENGTH is a magic value that can be passed to
 * EVP_AEAD_CTX_init to indicate that the default tag length for an AEAD
 * should be used.
 */
enum EVP_AEAD_DEFAULT_TAG_LENGTH = 0;

/**
 * EVP_AEAD_CTX_new allocates a new context for use with EVP_AEAD_CTX_init.
 * It can be cleaned up for reuse with EVP_AEAD_CTX_cleanup and must be freed
 * with EVP_AEAD_CTX_free.
 */
.EVP_AEAD_CTX* EVP_AEAD_CTX_new();

/**
 * EVP_AEAD_CTX_free releases all memory owned by the context.
 */
void EVP_AEAD_CTX_free(.EVP_AEAD_CTX* ctx);

/**
 * EVP_AEAD_CTX_init initializes the context for the given AEAD algorithm.
 * The implementation argument may be null to choose the default implementation.
 * Authentication tags may be truncated by passing a tag length. A tag length
 * of zero indicates the default tag length should be used.
 */
int EVP_AEAD_CTX_init(.EVP_AEAD_CTX* ctx, const (.EVP_AEAD)* aead, const (ubyte)* key, size_t key_len, size_t tag_len, libressl_d.openssl.ossl_typ.ENGINE* impl);

/**
 * EVP_AEAD_CTX_cleanup frees any data allocated for this context.
 */
void EVP_AEAD_CTX_cleanup(.EVP_AEAD_CTX* ctx);

/**
 * EVP_AEAD_CTX_seal encrypts and authenticates the input and authenticates
 * any additional data (AD), the result being written as output. One is
 * returned on success, otherwise zero.
 *
 * This function may be called (with the same EVP_AEAD_CTX) concurrently with
 * itself or EVP_AEAD_CTX_open.
 *
 * At most max_out_len bytes are written as output and, in order to ensure
 * success, this value should be the length of the input plus the result of
 * EVP_AEAD_overhead. On successful return, out_len is set to the actual
 * number of bytes written.
 *
 * The length of the nonce is must be equal to the result of
 * EVP_AEAD_nonce_length for this AEAD.
 *
 * EVP_AEAD_CTX_seal never results in a partial output. If max_out_len is
 * insufficient, zero will be returned and out_len will be set to zero.
 *
 * If the input and output are aliased then out must be <= in.
 */
int EVP_AEAD_CTX_seal(const (.EVP_AEAD_CTX)* ctx, ubyte* out_, size_t* out_len, size_t max_out_len, const (ubyte)* nonce, size_t nonce_len, const (ubyte)* in_, size_t in_len, const (ubyte)* ad, size_t ad_len);

/**
 * EVP_AEAD_CTX_open authenticates the input and additional data, decrypting
 * the input and writing it as output. One is returned on success, otherwise
 * zero.
 *
 * This function may be called (with the same EVP_AEAD_CTX) concurrently with
 * itself or EVP_AEAD_CTX_seal.
 *
 * At most the number of input bytes are written as output. In order to ensure
 * success, max_out_len should be at least the same as the input length. On
 * successful return out_len is set to the actual number of bytes written.
 *
 * The length of nonce must be equal to the result of EVP_AEAD_nonce_length
 * for this AEAD.
 *
 * EVP_AEAD_CTX_open never results in a partial output. If max_out_len is
 * insufficient, zero will be returned and out_len will be set to zero.
 *
 * If the input and output are aliased then out must be <= in.
 */
int EVP_AEAD_CTX_open(const (.EVP_AEAD_CTX)* ctx, ubyte* out_, size_t* out_len, size_t max_out_len, const (ubyte)* nonce, size_t nonce_len, const (ubyte)* in_, size_t in_len, const (ubyte)* ad, size_t ad_len);

void EVP_add_alg_module();

void ERR_load_EVP_strings();

/* Error codes for the EVP functions. */

/* Function codes. */
enum EVP_F_AEAD_AES_GCM_INIT = 187;
enum EVP_F_AEAD_AES_GCM_OPEN = 188;
enum EVP_F_AEAD_AES_GCM_SEAL = 189;
enum EVP_F_AEAD_CHACHA20_POLY1305_INIT = 192;
enum EVP_F_AEAD_CHACHA20_POLY1305_OPEN = 193;
enum EVP_F_AEAD_CHACHA20_POLY1305_SEAL = 194;
enum EVP_F_AEAD_CTX_OPEN = 185;
enum EVP_F_AEAD_CTX_SEAL = 186;
enum EVP_F_AESNI_INIT_KEY = 165;
enum EVP_F_AESNI_XTS_CIPHER = 176;
enum EVP_F_AES_INIT_KEY = 133;
enum EVP_F_AES_XTS = 172;
enum EVP_F_AES_XTS_CIPHER = 175;
enum EVP_F_ALG_MODULE_INIT = 177;
enum EVP_F_CAMELLIA_INIT_KEY = 159;
enum EVP_F_CMAC_INIT = 173;
enum EVP_F_D2I_PKEY = 100;
enum EVP_F_DO_SIGVER_INIT = 161;
enum EVP_F_DSAPKEY2PKCS8 = 134;
enum EVP_F_DSA_PKEY2PKCS8 = 135;
enum EVP_F_ECDSA_PKEY2PKCS8 = 129;
enum EVP_F_ECKEY_PKEY2PKCS8 = 132;
enum EVP_F_EVP_AEAD_CTX_INIT = 180;
enum EVP_F_EVP_AEAD_CTX_OPEN = 190;
enum EVP_F_EVP_AEAD_CTX_SEAL = 191;
enum EVP_F_EVP_BYTESTOKEY = 200;
enum EVP_F_EVP_CIPHERINIT_EX = 123;
enum EVP_F_EVP_CIPHER_CTX_COPY = 163;
enum EVP_F_EVP_CIPHER_CTX_CTRL = 124;
enum EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH = 122;
enum EVP_F_EVP_CIPHER_GET_ASN1_IV = 201;
enum EVP_F_EVP_CIPHER_SET_ASN1_IV = 202;
enum EVP_F_EVP_DECRYPTFINAL_EX = 101;
enum EVP_F_EVP_DECRYPTUPDATE = 199;
enum EVP_F_EVP_DIGESTFINAL_EX = 196;
enum EVP_F_EVP_DIGESTINIT_EX = 128;
enum EVP_F_EVP_ENCRYPTFINAL_EX = 127;
enum EVP_F_EVP_ENCRYPTUPDATE = 198;
enum EVP_F_EVP_MD_CTX_COPY_EX = 110;
enum EVP_F_EVP_MD_CTX_CTRL = 195;
enum EVP_F_EVP_MD_SIZE = 162;
enum EVP_F_EVP_OPENINIT = 102;
enum EVP_F_EVP_PBE_ALG_ADD = 115;
enum EVP_F_EVP_PBE_ALG_ADD_TYPE = 160;
enum EVP_F_EVP_PBE_CIPHERINIT = 116;
enum EVP_F_EVP_PKCS82PKEY = 111;
enum EVP_F_EVP_PKCS82PKEY_BROKEN = 136;
enum EVP_F_EVP_PKEY2PKCS8_BROKEN = 113;
enum EVP_F_EVP_PKEY_COPY_PARAMETERS = 103;
enum EVP_F_EVP_PKEY_CTX_CTRL = 137;
enum EVP_F_EVP_PKEY_CTX_CTRL_STR = 150;
enum EVP_F_EVP_PKEY_CTX_DUP = 156;
enum EVP_F_EVP_PKEY_DECRYPT = 104;
enum EVP_F_EVP_PKEY_DECRYPT_INIT = 138;
enum EVP_F_EVP_PKEY_DECRYPT_OLD = 151;
enum EVP_F_EVP_PKEY_DERIVE = 153;
enum EVP_F_EVP_PKEY_DERIVE_INIT = 154;
enum EVP_F_EVP_PKEY_DERIVE_SET_PEER = 155;
enum EVP_F_EVP_PKEY_ENCRYPT = 105;
enum EVP_F_EVP_PKEY_ENCRYPT_INIT = 139;
enum EVP_F_EVP_PKEY_ENCRYPT_OLD = 152;
enum EVP_F_EVP_PKEY_GET1_DH = 119;
enum EVP_F_EVP_PKEY_GET1_DSA = 120;
enum EVP_F_EVP_PKEY_GET1_ECDSA = 130;
enum EVP_F_EVP_PKEY_GET1_EC_KEY = 131;
enum EVP_F_EVP_PKEY_GET1_RSA = 121;
enum EVP_F_EVP_PKEY_KEYGEN = 146;
enum EVP_F_EVP_PKEY_KEYGEN_INIT = 147;
enum EVP_F_EVP_PKEY_NEW = 106;
enum EVP_F_EVP_PKEY_PARAMGEN = 148;
enum EVP_F_EVP_PKEY_PARAMGEN_INIT = 149;
enum EVP_F_EVP_PKEY_SIGN = 140;
enum EVP_F_EVP_PKEY_SIGN_INIT = 141;
enum EVP_F_EVP_PKEY_VERIFY = 142;
enum EVP_F_EVP_PKEY_VERIFY_INIT = 143;
enum EVP_F_EVP_PKEY_VERIFY_RECOVER = 144;
enum EVP_F_EVP_PKEY_VERIFY_RECOVER_INIT = 145;
enum EVP_F_EVP_RIJNDAEL = 126;
enum EVP_F_EVP_SIGNFINAL = 107;
enum EVP_F_EVP_VERIFYFINAL = 108;
enum EVP_F_FIPS_CIPHERINIT = 166;
enum EVP_F_FIPS_CIPHER_CTX_COPY = 170;
enum EVP_F_FIPS_CIPHER_CTX_CTRL = 167;
enum EVP_F_FIPS_CIPHER_CTX_SET_KEY_LENGTH = 171;
enum EVP_F_FIPS_DIGESTINIT = 168;
enum EVP_F_FIPS_MD_CTX_COPY = 169;
enum EVP_F_HMAC_INIT_EX = 174;
enum EVP_F_INT_CTX_NEW = 157;
enum EVP_F_PKCS5_PBE_KEYIVGEN = 117;
enum EVP_F_PKCS5_V2_PBE_KEYIVGEN = 118;
enum EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN = 164;
enum EVP_F_PKCS8_SET_BROKEN = 112;
enum EVP_F_PKEY_SET_TYPE = 158;
enum EVP_F_RC2_GET_ASN1_TYPE_AND_IV = 197;
enum EVP_F_RC2_MAGIC_TO_METH = 109;
enum EVP_F_RC5_CTRL = 125;

/* Reason codes. */
enum EVP_R_AES_IV_SETUP_FAILED = 162;
enum EVP_R_AES_KEY_SETUP_FAILED = 143;
enum EVP_R_ASN1_LIB = 140;
enum EVP_R_BAD_BLOCK_LENGTH = 136;
enum EVP_R_BAD_DECRYPT = 100;
enum EVP_R_BAD_KEY_LENGTH = 137;
enum EVP_R_BN_DECODE_ERROR = 112;
enum EVP_R_BN_PUBKEY_ERROR = 113;
enum EVP_R_BUFFER_TOO_SMALL = 155;
enum EVP_R_CAMELLIA_KEY_SETUP_FAILED = 157;
enum EVP_R_CIPHER_PARAMETER_ERROR = 122;
enum EVP_R_COMMAND_NOT_SUPPORTED = 147;
enum EVP_R_CTRL_NOT_IMPLEMENTED = 132;
enum EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED = 133;
enum EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH = 138;
enum EVP_R_DECODE_ERROR = 114;
enum EVP_R_DIFFERENT_KEY_TYPES = 101;
enum EVP_R_DIFFERENT_PARAMETERS = 153;
enum EVP_R_DISABLED_FOR_FIPS = 163;
enum EVP_R_ENCODE_ERROR = 115;
enum EVP_R_ERROR_LOADING_SECTION = 165;
enum EVP_R_ERROR_SETTING_FIPS_MODE = 166;
enum EVP_R_EVP_PBE_CIPHERINIT_ERROR = 119;
enum EVP_R_EXPECTING_AN_HMAC_KEY = 174;
enum EVP_R_EXPECTING_AN_RSA_KEY = 127;
enum EVP_R_EXPECTING_A_DH_KEY = 128;
enum EVP_R_EXPECTING_A_DSA_KEY = 129;
enum EVP_R_EXPECTING_A_ECDSA_KEY = 141;
enum EVP_R_EXPECTING_A_EC_KEY = 142;
enum EVP_R_FIPS_MODE_NOT_SUPPORTED = 167;
enum EVP_R_GET_RAW_KEY_FAILED = 182;
enum EVP_R_INITIALIZATION_ERROR = 134;
enum EVP_R_INPUT_NOT_INITIALIZED = 111;
enum EVP_R_INVALID_DIGEST = 152;
enum EVP_R_INVALID_FIPS_MODE = 168;
enum EVP_R_INVALID_IV_LENGTH = 194;
enum EVP_R_INVALID_KEY_LENGTH = 130;
enum EVP_R_INVALID_OPERATION = 148;
enum EVP_R_IV_TOO_LARGE = 102;
enum EVP_R_KEYGEN_FAILURE = 120;
enum EVP_R_KEY_SETUP_FAILED = 180;
enum EVP_R_MESSAGE_DIGEST_IS_NULL = 159;
enum EVP_R_METHOD_NOT_SUPPORTED = 144;
enum EVP_R_MISSING_PARAMETERS = 103;
enum EVP_R_NO_CIPHER_SET = 131;
enum EVP_R_NO_DEFAULT_DIGEST = 158;
enum EVP_R_NO_DIGEST_SET = 139;
enum EVP_R_NO_DSA_PARAMETERS = 116;
enum EVP_R_NO_KEY_SET = 154;
enum EVP_R_NO_OPERATION_SET = 149;
enum EVP_R_NO_SIGN_FUNCTION_CONFIGURED = 104;
enum EVP_R_NO_VERIFY_FUNCTION_CONFIGURED = 105;
enum EVP_R_ONLY_ONESHOT_SUPPORTED = 177;
enum EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE = 150;
enum EVP_R_OPERATON_NOT_INITIALIZED = 151;
enum EVP_R_OUTPUT_ALIASES_INPUT = 172;
enum EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE = 117;
enum EVP_R_PRIVATE_KEY_DECODE_ERROR = 145;
enum EVP_R_PRIVATE_KEY_ENCODE_ERROR = 146;
enum EVP_R_PUBLIC_KEY_NOT_RSA = 106;
enum EVP_R_TAG_TOO_LARGE = 171;
enum EVP_R_TOO_LARGE = 164;
enum EVP_R_UNKNOWN_CIPHER = 160;
enum EVP_R_UNKNOWN_DIGEST = 161;
enum EVP_R_UNKNOWN_OPTION = 169;
enum EVP_R_UNKNOWN_PBE_ALGORITHM = 121;
enum EVP_R_UNSUPORTED_NUMBER_OF_ROUNDS = 135;
enum EVP_R_UNSUPPORTED_ALGORITHM = 156;
enum EVP_R_UNSUPPORTED_CIPHER = 107;
enum EVP_R_UNSUPPORTED_KEYLENGTH = 123;
enum EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION = 124;
enum EVP_R_UNSUPPORTED_KEY_SIZE = 108;
enum EVP_R_UNSUPPORTED_PRF = 125;
enum EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM = 118;
enum EVP_R_WRAP_MODE_NOT_ALLOWED = 170;
enum EVP_R_UNSUPPORTED_SALT_TYPE = 126;
enum EVP_R_WRONG_FINAL_BLOCK_LENGTH = 109;
enum EVP_R_WRONG_PUBLIC_KEY_TYPE = 110;
