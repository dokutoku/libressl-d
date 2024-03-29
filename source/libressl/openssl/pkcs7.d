/* $OpenBSD: pkcs7.h,v 1.19 2022/07/12 14:42:50 kn Exp $ */
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
module libressl.openssl.pkcs7;


private static import core.stdc.config;
private static import libressl.compat.stdio;
private static import libressl.openssl.objects;
private static import libressl.openssl.stack;
private static import libressl.openssl.x509;
public import libressl.openssl.asn1;
public import libressl.openssl.bio;
public import libressl.openssl.opensslconf;
public import libressl.openssl.ossl_typ;

extern (C):
nothrow @nogc:

//#if defined(_WIN32) && defined(__WINCRYPT_H__)
	version (LIBRESSL_INTERNAL) {
	} else {
		//pragma(msg, "Warning, overriding WinCrypt defines");
	}

	//#undef PKCS7_ISSUER_AND_SERIAL
	//#undef PKCS7_SIGNER_INFO
//#endif

/*
 * ncryption_ID		DES-CBC
Digest_ID		MD5
Digest_Encryption_ID	rsaEncryption
Key_Encryption_ID	rsaEncryption
 */

struct pkcs7_issuer_and_serial_st
{
	libressl.openssl.ossl_typ.X509_NAME* issuer;
	libressl.openssl.ossl_typ.ASN1_INTEGER* serial;
}

alias PKCS7_ISSUER_AND_SERIAL = .pkcs7_issuer_and_serial_st;

struct pkcs7_signer_info_st
{
	/**
	 * version 1
	 */
	libressl.openssl.ossl_typ.ASN1_INTEGER* version_;

	.PKCS7_ISSUER_AND_SERIAL* issuer_and_serial;
	libressl.openssl.ossl_typ.X509_ALGOR* digest_alg;

	/**
	 * [ 0 ]
	 */
	libressl.openssl.x509.stack_st_X509_ATTRIBUTE* auth_attr;

	libressl.openssl.ossl_typ.X509_ALGOR* digest_enc_alg;
	libressl.openssl.ossl_typ.ASN1_OCTET_STRING* enc_digest;

	/**
	 * [ 1 ]
	 */
	libressl.openssl.x509.stack_st_X509_ATTRIBUTE* unauth_attr;

	/* The private key to sign with */
	libressl.openssl.ossl_typ.EVP_PKEY* pkey;
}

alias PKCS7_SIGNER_INFO = .pkcs7_signer_info_st;

//DECLARE_STACK_OF(PKCS7_SIGNER_INFO)
struct stack_st_PKCS7_SIGNER_INFO
{
	libressl.openssl.stack._STACK stack;
}

struct pkcs7_recip_info_st
{
	/**
	 * version 0
	 */
	libressl.openssl.ossl_typ.ASN1_INTEGER* version_;

	.PKCS7_ISSUER_AND_SERIAL* issuer_and_serial;
	libressl.openssl.ossl_typ.X509_ALGOR* key_enc_algor;
	libressl.openssl.ossl_typ.ASN1_OCTET_STRING* enc_key;

	/**
	 * get the pub-key from this
	 */
	libressl.openssl.ossl_typ.X509* cert;
}

alias PKCS7_RECIP_INFO = .pkcs7_recip_info_st;

//DECLARE_STACK_OF(PKCS7_RECIP_INFO)
struct stack_st_PKCS7_RECIP_INFO
{
	libressl.openssl.stack._STACK stack;
}

struct pkcs7_signed_st
{
	/**
	 * version 1
	 */
	libressl.openssl.ossl_typ.ASN1_INTEGER* version_;

	/**
	 * md used
	 */
	libressl.openssl.asn1.stack_st_X509_ALGOR* md_algs;

	/**
	 * [ 0 ]
	 */
	libressl.openssl.x509.stack_st_X509* cert;

	/**
	 * [ 1 ]
	 */
	libressl.openssl.x509.stack_st_X509_CRL* crl;

	.stack_st_PKCS7_SIGNER_INFO* signer_info;

	.pkcs7_st* contents;
}

alias PKCS7_SIGNED = .pkcs7_signed_st;
/*
 * The above structure is very very similar to PKCS7_SIGN_ENVELOPE.
 * How about merging the two
 */

struct pkcs7_enc_content_st
{
	libressl.openssl.ossl_typ.ASN1_OBJECT* content_type;
	libressl.openssl.ossl_typ.X509_ALGOR* algorithm;

	/**
	 * [ 0 ]
	 */
	libressl.openssl.ossl_typ.ASN1_OCTET_STRING* enc_data;

	const (libressl.openssl.ossl_typ.EVP_CIPHER)* cipher;
}

alias PKCS7_ENC_CONTENT = .pkcs7_enc_content_st;

struct pkcs7_enveloped_st
{
	/**
	 * version 0
	 */
	libressl.openssl.ossl_typ.ASN1_INTEGER* version_;

	.stack_st_PKCS7_RECIP_INFO* recipientinfo;
	.PKCS7_ENC_CONTENT* enc_data;
}

alias PKCS7_ENVELOPE = .pkcs7_enveloped_st;

struct pkcs7_signedandenveloped_st
{
	/**
	 * version 1
	 */
	libressl.openssl.ossl_typ.ASN1_INTEGER* version_;

	/**
	 * md used
	 */
	libressl.openssl.asn1.stack_st_X509_ALGOR* md_algs;

	/**
	 * [ 0 ]
	 */
	libressl.openssl.x509.stack_st_X509* cert;

	/**
	 * [ 1 ]
	 */
	libressl.openssl.x509.stack_st_X509_CRL* crl;

	.stack_st_PKCS7_SIGNER_INFO* signer_info;

	.PKCS7_ENC_CONTENT* enc_data;
	.stack_st_PKCS7_RECIP_INFO* recipientinfo;
}

alias PKCS7_SIGN_ENVELOPE = .pkcs7_signedandenveloped_st;

struct pkcs7_digest_st
{
	/**
	 * version 0
	 */
	libressl.openssl.ossl_typ.ASN1_INTEGER* version_;

	/**
	 * md used
	 */
	libressl.openssl.ossl_typ.X509_ALGOR* md;

	.pkcs7_st* contents;
	libressl.openssl.ossl_typ.ASN1_OCTET_STRING* digest;
}

alias PKCS7_DIGEST = .pkcs7_digest_st;

struct pkcs7_encrypted_st
{
	/**
	 * version 0
	 */
	libressl.openssl.ossl_typ.ASN1_INTEGER* version_;

	.PKCS7_ENC_CONTENT* enc_data;
}

alias PKCS7_ENCRYPT = .pkcs7_encrypted_st;

struct pkcs7_st
{
	/*
	 * The following is non null if it contains ASN1 encoding of
	 * this structure
	 */
	ubyte* asn1;
	core.stdc.config.c_long length_;

	enum PKCS7_S_HEADER = 0;
	enum PKCS7_S_BODY = 1;
	enum PKCS7_S_TAIL = 2;

	/**
	 * used during processing
	 */
	int state;

	int detached;

	/**
	 * content as defined by the type
	 */
	libressl.openssl.ossl_typ.ASN1_OBJECT* type;

	/**
	 * all encryption/message digests are applied to the 'contents',
	 * leaving out the 'type' field.
	 */
	union d_
	{
		char* ptr_;

		/**
		 * NID_pkcs7_data
		 */
		libressl.openssl.ossl_typ.ASN1_OCTET_STRING* data;

		/**
		 * NID_pkcs7_signed
		 */
		.PKCS7_SIGNED* sign;

		/**
		 * NID_pkcs7_enveloped
		 */
		.PKCS7_ENVELOPE* enveloped;

		/**
		 * NID_pkcs7_signedAndEnveloped
		 */
		.PKCS7_SIGN_ENVELOPE* signed_and_enveloped;

		/**
		 * NID_pkcs7_digest
		 */
		.PKCS7_DIGEST* digest;

		/**
		 * NID_pkcs7_encrypted
		 */
		.PKCS7_ENCRYPT* encrypted;

		/**
		 * Anything else
		 */
		libressl.openssl.asn1.ASN1_TYPE* other;
	}

	d_ d;
}

alias PKCS7 = .pkcs7_st;

//DECLARE_STACK_OF(PKCS7)
struct stack_st_PKCS7
{
	libressl.openssl.stack._STACK stack;
}

mixin (libressl.openssl.ossl_typ.DECLARE_PKCS12_STACK_OF!("PKCS7"));

enum PKCS7_OP_SET_DETACHED_SIGNATURE = 1;
enum PKCS7_OP_GET_DETACHED_SIGNATURE = 2;

pragma(inline, true)
pure nothrow @trusted @nogc @live
libressl.openssl.x509.stack_st_X509_ATTRIBUTE* PKCS7_get_signed_attributes(return scope .PKCS7_SIGNER_INFO* si)

	in
	{
		assert(si != null);
	}

	do
	{
		return si.auth_attr;
	}

pragma(inline, true)
pure nothrow @trusted @nogc @live
libressl.openssl.x509.stack_st_X509_ATTRIBUTE* PKCS7_get_attributes(return scope .PKCS7_SIGNER_INFO* si)

	in
	{
		assert(si != null);
	}

	do
	{
		return si.unauth_attr;
	}

pragma(inline, true)
bool PKCS7_type_is_signed(A)(const (A)* a)

	in
	{
		assert(a != null);
	}

	do
	{
		return libressl.openssl.objects.OBJ_obj2nid(a.type) == libressl.openssl.objects.NID_pkcs7_signed;
	}

pragma(inline, true)
bool PKCS7_type_is_encrypted(A)(const (A)* a)

	in
	{
		assert(a != null);
	}

	do
	{
		return libressl.openssl.objects.OBJ_obj2nid(a.type) == libressl.openssl.objects.NID_pkcs7_encrypted;
	}

pragma(inline, true)
bool PKCS7_type_is_enveloped(A)(const (A)* a)

	in
	{
		assert(a != null);
	}

	do
	{
		return libressl.openssl.objects.OBJ_obj2nid(a.type) == libressl.openssl.objects.NID_pkcs7_enveloped;
	}

pragma(inline, true)
bool PKCS7_type_is_signedAndEnveloped(A)(const (A)* a)

	in
	{
		assert(a != null);
	}

	do
	{
		return libressl.openssl.objects.OBJ_obj2nid(a.type) == libressl.openssl.objects.NID_pkcs7_signedAndEnveloped;
	}

pragma(inline, true)
bool PKCS7_type_is_data(A)(const (A)* a)

	in
	{
		assert(a != null);
	}

	do
	{
		return libressl.openssl.objects.OBJ_obj2nid(a.type) == libressl.openssl.objects.NID_pkcs7_data;
	}

pragma(inline, true)
bool PKCS7_type_is_digest(A)(const (A)* a)

	in
	{
		assert(a != null);
	}

	do
	{
		return libressl.openssl.objects.OBJ_obj2nid(a.type) == libressl.openssl.objects.NID_pkcs7_digest;
	}

pragma(inline, true)
bool PKCS7_type_is_encrypted(A)(const (A)* a)

	in
	{
		assert(a != null);
	}

	do
	{
		return libressl.openssl.objects.OBJ_obj2nid(a.type) == libressl.openssl.objects.NID_pkcs7_encrypted;
	}

pragma(inline, true)
bool PKCS7_type_is_digest(A)(const (A)* a)

	in
	{
		assert(a != null);
	}

	do
	{
		return libressl.openssl.objects.OBJ_obj2nid(a.type) == libressl.openssl.objects.NID_pkcs7_digest;
	}

pragma(inline, true)
core.stdc.config.c_long PKCS7_set_detached(.PKCS7* p, core.stdc.config.c_long v)

	do
	{
		return .PKCS7_ctrl(p, .PKCS7_OP_SET_DETACHED_SIGNATURE, v, null);
	}

pragma(inline, true)
core.stdc.config.c_long PKCS7_get_detached(.PKCS7* p)

	do
	{
		return .PKCS7_ctrl(p, .PKCS7_OP_GET_DETACHED_SIGNATURE, 0, null);
	}

pragma(inline, true)
bool PKCS7_is_detached(P7)(P7 p7)

	do
	{
		return (.PKCS7_type_is_signed(p7)) && (.PKCS7_get_detached(p7));
	}

/* S/MIME related flags */

enum PKCS7_TEXT = 0x01;
enum PKCS7_NOCERTS = 0x02;
enum PKCS7_NOSIGS = 0x04;
enum PKCS7_NOCHAIN = 0x08;
enum PKCS7_NOINTERN = 0x10;
enum PKCS7_NOVERIFY = 0x20;
enum PKCS7_DETACHED = 0x40;
enum PKCS7_BINARY = 0x80;
enum PKCS7_NOATTR = 0x0100;
enum PKCS7_NOSMIMECAP = 0x0200;
enum PKCS7_NOOLDMIMETYPE = 0x0400;
enum PKCS7_CRLFEOL = 0x0800;
enum PKCS7_STREAM = 0x1000;
enum PKCS7_NOCRL = 0x2000;
enum PKCS7_PARTIAL = 0x4000;
enum PKCS7_REUSE_DIGEST = 0x8000;

/* Flags: for compatibility with older code */

enum SMIME_TEXT = .PKCS7_TEXT;
enum SMIME_NOCERTS = .PKCS7_NOCERTS;
enum SMIME_NOSIGS = .PKCS7_NOSIGS;
enum SMIME_NOCHAIN = .PKCS7_NOCHAIN;
enum SMIME_NOINTERN = .PKCS7_NOINTERN;
enum SMIME_NOVERIFY = .PKCS7_NOVERIFY;
enum SMIME_DETACHED = .PKCS7_DETACHED;
enum SMIME_BINARY = .PKCS7_BINARY;
enum SMIME_NOATTR = .PKCS7_NOATTR;

.PKCS7_ISSUER_AND_SERIAL* PKCS7_ISSUER_AND_SERIAL_new();
void PKCS7_ISSUER_AND_SERIAL_free(.PKCS7_ISSUER_AND_SERIAL* a);
.PKCS7_ISSUER_AND_SERIAL* d2i_PKCS7_ISSUER_AND_SERIAL(.PKCS7_ISSUER_AND_SERIAL** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKCS7_ISSUER_AND_SERIAL(.PKCS7_ISSUER_AND_SERIAL* a, ubyte** out_);
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS7_ISSUER_AND_SERIAL_it;

int PKCS7_ISSUER_AND_SERIAL_digest(.PKCS7_ISSUER_AND_SERIAL* data, const (libressl.openssl.ossl_typ.EVP_MD)* type, ubyte* md, uint* len);
.PKCS7* d2i_PKCS7_fp(libressl.compat.stdio.FILE* fp, .PKCS7** p7);
int i2d_PKCS7_fp(libressl.compat.stdio.FILE* fp, .PKCS7* p7);
.PKCS7* PKCS7_dup(.PKCS7* p7);
.PKCS7* d2i_PKCS7_bio(libressl.openssl.ossl_typ.BIO* bp, .PKCS7** p7);
int i2d_PKCS7_bio(libressl.openssl.ossl_typ.BIO* bp, .PKCS7* p7);
int i2d_PKCS7_bio_stream(libressl.openssl.ossl_typ.BIO* out_, .PKCS7* p7, libressl.openssl.ossl_typ.BIO* in_, int flags);
int PEM_write_bio_PKCS7_stream(libressl.openssl.ossl_typ.BIO* out_, .PKCS7* p7, libressl.openssl.ossl_typ.BIO* in_, int flags);

.PKCS7_SIGNER_INFO* PKCS7_SIGNER_INFO_new();
void PKCS7_SIGNER_INFO_free(.PKCS7_SIGNER_INFO* a);
.PKCS7_SIGNER_INFO* d2i_PKCS7_SIGNER_INFO(.PKCS7_SIGNER_INFO** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKCS7_SIGNER_INFO(.PKCS7_SIGNER_INFO* a, ubyte** out_);
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS7_SIGNER_INFO_it;
.PKCS7_RECIP_INFO* PKCS7_RECIP_INFO_new();
void PKCS7_RECIP_INFO_free(.PKCS7_RECIP_INFO* a);
.PKCS7_RECIP_INFO* d2i_PKCS7_RECIP_INFO(.PKCS7_RECIP_INFO** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKCS7_RECIP_INFO(.PKCS7_RECIP_INFO* a, ubyte** out_);
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS7_RECIP_INFO_it;
.PKCS7_SIGNED* PKCS7_SIGNED_new();
void PKCS7_SIGNED_free(.PKCS7_SIGNED* a);
.PKCS7_SIGNED* d2i_PKCS7_SIGNED(.PKCS7_SIGNED** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKCS7_SIGNED(.PKCS7_SIGNED* a, ubyte** out_);
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS7_SIGNED_it;
.PKCS7_ENC_CONTENT* PKCS7_ENC_CONTENT_new();
void PKCS7_ENC_CONTENT_free(.PKCS7_ENC_CONTENT* a);
.PKCS7_ENC_CONTENT* d2i_PKCS7_ENC_CONTENT(.PKCS7_ENC_CONTENT** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKCS7_ENC_CONTENT(.PKCS7_ENC_CONTENT* a, ubyte** out_);
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS7_ENC_CONTENT_it;
.PKCS7_ENVELOPE* PKCS7_ENVELOPE_new();
void PKCS7_ENVELOPE_free(.PKCS7_ENVELOPE* a);
.PKCS7_ENVELOPE* d2i_PKCS7_ENVELOPE(.PKCS7_ENVELOPE** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKCS7_ENVELOPE(.PKCS7_ENVELOPE* a, ubyte** out_);
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS7_ENVELOPE_it;
.PKCS7_SIGN_ENVELOPE* PKCS7_SIGN_ENVELOPE_new();
void PKCS7_SIGN_ENVELOPE_free(.PKCS7_SIGN_ENVELOPE* a);
.PKCS7_SIGN_ENVELOPE* d2i_PKCS7_SIGN_ENVELOPE(.PKCS7_SIGN_ENVELOPE** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKCS7_SIGN_ENVELOPE(.PKCS7_SIGN_ENVELOPE* a, ubyte** out_);
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS7_SIGN_ENVELOPE_it;
.PKCS7_DIGEST* PKCS7_DIGEST_new();
void PKCS7_DIGEST_free(.PKCS7_DIGEST* a);
.PKCS7_DIGEST* d2i_PKCS7_DIGEST(.PKCS7_DIGEST** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKCS7_DIGEST(.PKCS7_DIGEST* a, ubyte** out_);
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS7_DIGEST_it;
.PKCS7_ENCRYPT* PKCS7_ENCRYPT_new();
void PKCS7_ENCRYPT_free(.PKCS7_ENCRYPT* a);
.PKCS7_ENCRYPT* d2i_PKCS7_ENCRYPT(.PKCS7_ENCRYPT** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKCS7_ENCRYPT(.PKCS7_ENCRYPT* a, ubyte** out_);
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS7_ENCRYPT_it;
.PKCS7* PKCS7_new();
void PKCS7_free(.PKCS7* a);
.PKCS7* d2i_PKCS7(.PKCS7** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKCS7(.PKCS7* a, ubyte** out_);
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS7_it;

extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS7_ATTR_SIGN_it;
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS7_ATTR_VERIFY_it;

int i2d_PKCS7_NDEF(.PKCS7* a, ubyte** out_);
int PKCS7_print_ctx(libressl.openssl.ossl_typ.BIO* out_, .PKCS7* x, int indent, const (libressl.openssl.ossl_typ.ASN1_PCTX)* pctx);

core.stdc.config.c_long PKCS7_ctrl(.PKCS7* p7, int cmd, core.stdc.config.c_long larg, char* parg);

int PKCS7_set_type(.PKCS7* p7, int type);
int PKCS7_set0_type_other(.PKCS7* p7, int type, libressl.openssl.asn1.ASN1_TYPE* other);
int PKCS7_set_content(.PKCS7* p7, .PKCS7* p7_data);
int PKCS7_SIGNER_INFO_set(.PKCS7_SIGNER_INFO* p7i, libressl.openssl.ossl_typ.X509* x509, libressl.openssl.ossl_typ.EVP_PKEY* pkey, const (libressl.openssl.ossl_typ.EVP_MD)* dgst);
int PKCS7_SIGNER_INFO_sign(.PKCS7_SIGNER_INFO* si);
int PKCS7_add_signer(.PKCS7* p7, .PKCS7_SIGNER_INFO* p7i);
int PKCS7_add_certificate(.PKCS7* p7, libressl.openssl.ossl_typ.X509* x509);
int PKCS7_add_crl(.PKCS7* p7, libressl.openssl.ossl_typ.X509_CRL* x509);
int PKCS7_content_new(.PKCS7* p7, int nid);
int PKCS7_dataVerify(libressl.openssl.ossl_typ.X509_STORE* cert_store, libressl.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl.openssl.ossl_typ.BIO* bio, .PKCS7* p7, .PKCS7_SIGNER_INFO* si);
int PKCS7_signatureVerify(libressl.openssl.ossl_typ.BIO* bio, .PKCS7* p7, .PKCS7_SIGNER_INFO* si, libressl.openssl.ossl_typ.X509* x509);

libressl.openssl.ossl_typ.BIO* PKCS7_dataInit(.PKCS7* p7, libressl.openssl.ossl_typ.BIO* bio);
int PKCS7_dataFinal(.PKCS7* p7, libressl.openssl.ossl_typ.BIO* bio);
libressl.openssl.ossl_typ.BIO* PKCS7_dataDecode(.PKCS7* p7, libressl.openssl.ossl_typ.EVP_PKEY* pkey, libressl.openssl.ossl_typ.BIO* in_bio, libressl.openssl.ossl_typ.X509* pcert);

.PKCS7_SIGNER_INFO* PKCS7_add_signature(.PKCS7* p7, libressl.openssl.ossl_typ.X509* x509, libressl.openssl.ossl_typ.EVP_PKEY* pkey, const (libressl.openssl.ossl_typ.EVP_MD)* dgst);
libressl.openssl.ossl_typ.X509* PKCS7_cert_from_signer_info(.PKCS7* p7, .PKCS7_SIGNER_INFO* si);
int PKCS7_set_digest(.PKCS7* p7, const (libressl.openssl.ossl_typ.EVP_MD)* md);
.stack_st_PKCS7_SIGNER_INFO* PKCS7_get_signer_info(.PKCS7* p7);

.PKCS7_RECIP_INFO* PKCS7_add_recipient(.PKCS7* p7, libressl.openssl.ossl_typ.X509* x509);
void PKCS7_SIGNER_INFO_get0_algs(.PKCS7_SIGNER_INFO* si, libressl.openssl.ossl_typ.EVP_PKEY** pk, libressl.openssl.ossl_typ.X509_ALGOR** pdig, libressl.openssl.ossl_typ.X509_ALGOR** psig);
void PKCS7_RECIP_INFO_get0_alg(.PKCS7_RECIP_INFO* ri, libressl.openssl.ossl_typ.X509_ALGOR** penc);
int PKCS7_add_recipient_info(.PKCS7* p7, .PKCS7_RECIP_INFO* ri);
int PKCS7_RECIP_INFO_set(.PKCS7_RECIP_INFO* p7i, libressl.openssl.ossl_typ.X509* x509);
int PKCS7_set_cipher(.PKCS7* p7, const (libressl.openssl.ossl_typ.EVP_CIPHER)* cipher);
int PKCS7_stream(ubyte*** boundary, .PKCS7* p7);

.PKCS7_ISSUER_AND_SERIAL* PKCS7_get_issuer_and_serial(.PKCS7* p7, int idx);
libressl.openssl.ossl_typ.ASN1_OCTET_STRING* PKCS7_digest_from_attributes(libressl.openssl.x509.stack_st_X509_ATTRIBUTE* sk);
int PKCS7_add_signed_attribute(.PKCS7_SIGNER_INFO* p7si, int nid, int type, void* data);
int PKCS7_add_attribute(.PKCS7_SIGNER_INFO* p7si, int nid, int atrtype, void* value);
libressl.openssl.asn1.ASN1_TYPE* PKCS7_get_attribute(.PKCS7_SIGNER_INFO* si, int nid);
libressl.openssl.asn1.ASN1_TYPE* PKCS7_get_signed_attribute(.PKCS7_SIGNER_INFO* si, int nid);
int PKCS7_set_signed_attributes(.PKCS7_SIGNER_INFO* p7si, libressl.openssl.x509.stack_st_X509_ATTRIBUTE* sk);
int PKCS7_set_attributes(.PKCS7_SIGNER_INFO* p7si, libressl.openssl.x509.stack_st_X509_ATTRIBUTE* sk);

.PKCS7* PKCS7_sign(libressl.openssl.ossl_typ.X509* signcert, libressl.openssl.ossl_typ.EVP_PKEY* pkey, libressl.openssl.x509.stack_st_X509* certs, libressl.openssl.ossl_typ.BIO* data, int flags);

.PKCS7_SIGNER_INFO* PKCS7_sign_add_signer(.PKCS7* p7, libressl.openssl.ossl_typ.X509* signcert, libressl.openssl.ossl_typ.EVP_PKEY* pkey, const (libressl.openssl.ossl_typ.EVP_MD)* md, int flags);

int PKCS7_final(.PKCS7* p7, libressl.openssl.ossl_typ.BIO* data, int flags);
int PKCS7_verify(.PKCS7* p7, libressl.openssl.x509.stack_st_X509* certs, libressl.openssl.ossl_typ.X509_STORE* store, libressl.openssl.ossl_typ.BIO* indata, libressl.openssl.ossl_typ.BIO* out_, int flags);
libressl.openssl.x509.stack_st_X509* PKCS7_get0_signers(.PKCS7* p7, libressl.openssl.x509.stack_st_X509* certs, int flags);
.PKCS7* PKCS7_encrypt(libressl.openssl.x509.stack_st_X509* certs, libressl.openssl.ossl_typ.BIO* in_, const (libressl.openssl.ossl_typ.EVP_CIPHER)* cipher, int flags);
int PKCS7_decrypt(.PKCS7* p7, libressl.openssl.ossl_typ.EVP_PKEY* pkey, libressl.openssl.ossl_typ.X509* cert, libressl.openssl.ossl_typ.BIO* data, int flags);

int PKCS7_add_attrib_smimecap(.PKCS7_SIGNER_INFO* si, libressl.openssl.asn1.stack_st_X509_ALGOR* cap);
libressl.openssl.asn1.stack_st_X509_ALGOR* PKCS7_get_smimecap(.PKCS7_SIGNER_INFO* si);
int PKCS7_simple_smimecap(libressl.openssl.asn1.stack_st_X509_ALGOR* sk, int nid, int arg);

int PKCS7_add_attrib_content_type(.PKCS7_SIGNER_INFO* si, libressl.openssl.ossl_typ.ASN1_OBJECT* coid);
int PKCS7_add0_attrib_signing_time(.PKCS7_SIGNER_INFO* si, libressl.openssl.ossl_typ.ASN1_TIME* t);
int PKCS7_add1_attrib_digest(.PKCS7_SIGNER_INFO* si, const (ubyte)* md, int mdlen);

int SMIME_write_PKCS7(libressl.openssl.ossl_typ.BIO* bio, .PKCS7* p7, libressl.openssl.ossl_typ.BIO* data, int flags);
.PKCS7* SMIME_read_PKCS7(libressl.openssl.ossl_typ.BIO* bio, libressl.openssl.ossl_typ.BIO** bcont);

libressl.openssl.ossl_typ.BIO* BIO_new_PKCS7(libressl.openssl.ossl_typ.BIO* out_, .PKCS7* p7);

void ERR_load_PKCS7_strings();

/* Error codes for the PKCS7 functions. */

/* Function codes. */
enum PKCS7_F_B64_READ_PKCS7 = 120;
enum PKCS7_F_B64_WRITE_PKCS7 = 121;
enum PKCS7_F_DO_PKCS7_SIGNED_ATTRIB = 136;
enum PKCS7_F_I2D_PKCS7_BIO_STREAM = 140;
enum PKCS7_F_PKCS7_ADD0_ATTRIB_SIGNING_TIME = 135;
enum PKCS7_F_PKCS7_ADD_ATTRIB_SMIMECAP = 118;
enum PKCS7_F_PKCS7_ADD_CERTIFICATE = 100;
enum PKCS7_F_PKCS7_ADD_CRL = 101;
enum PKCS7_F_PKCS7_ADD_RECIPIENT_INFO = 102;
enum PKCS7_F_PKCS7_ADD_SIGNATURE = 131;
enum PKCS7_F_PKCS7_ADD_SIGNER = 103;
enum PKCS7_F_PKCS7_BIO_ADD_DIGEST = 125;
enum PKCS7_F_PKCS7_COPY_EXISTING_DIGEST = 138;
enum PKCS7_F_PKCS7_CTRL = 104;
enum PKCS7_F_PKCS7_DATADECODE = 112;
enum PKCS7_F_PKCS7_DATAFINAL = 128;
enum PKCS7_F_PKCS7_DATAINIT = 105;
enum PKCS7_F_PKCS7_DATASIGN = 106;
enum PKCS7_F_PKCS7_DATAVERIFY = 107;
enum PKCS7_F_PKCS7_DECRYPT = 114;
enum PKCS7_F_PKCS7_DECRYPT_RINFO = 133;
enum PKCS7_F_PKCS7_ENCODE_RINFO = 132;
enum PKCS7_F_PKCS7_ENCRYPT = 115;
enum PKCS7_F_PKCS7_FINAL = 134;
enum PKCS7_F_PKCS7_FIND_DIGEST = 127;
enum PKCS7_F_PKCS7_GET0_SIGNERS = 124;
enum PKCS7_F_PKCS7_RECIP_INFO_SET = 130;
enum PKCS7_F_PKCS7_SET_CIPHER = 108;
enum PKCS7_F_PKCS7_SET_CONTENT = 109;
enum PKCS7_F_PKCS7_SET_DIGEST = 126;
enum PKCS7_F_PKCS7_SET_TYPE = 110;
enum PKCS7_F_PKCS7_SIGN = 116;
enum PKCS7_F_PKCS7_SIGNATUREVERIFY = 113;
enum PKCS7_F_PKCS7_SIGNER_INFO_SET = 129;
enum PKCS7_F_PKCS7_SIGNER_INFO_SIGN = 139;
enum PKCS7_F_PKCS7_SIGN_ADD_SIGNER = 137;
enum PKCS7_F_PKCS7_SIMPLE_SMIMECAP = 119;
enum PKCS7_F_PKCS7_VERIFY = 117;
enum PKCS7_F_SMIME_READ_PKCS7 = 122;
enum PKCS7_F_SMIME_TEXT = 123;

/* Reason codes. */
enum PKCS7_R_CERTIFICATE_VERIFY_ERROR = 117;
enum PKCS7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER = 144;
enum PKCS7_R_CIPHER_NOT_INITIALIZED = 116;
enum PKCS7_R_CONTENT_AND_DATA_PRESENT = 118;
enum PKCS7_R_CTRL_ERROR = 152;
enum PKCS7_R_DECODE_ERROR = 130;
enum PKCS7_R_DECRYPTED_KEY_IS_WRONG_LENGTH = 100;
enum PKCS7_R_DECRYPT_ERROR = 119;
enum PKCS7_R_DIGEST_FAILURE = 101;
enum PKCS7_R_ENCRYPTION_CTRL_FAILURE = 149;
enum PKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE = 150;
enum PKCS7_R_ERROR_ADDING_RECIPIENT = 120;
enum PKCS7_R_ERROR_SETTING_CIPHER = 121;
enum PKCS7_R_INVALID_MIME_TYPE = 131;
enum PKCS7_R_INVALID_NULL_POINTER = 143;
enum PKCS7_R_MIME_NO_CONTENT_TYPE = 132;
enum PKCS7_R_MIME_PARSE_ERROR = 133;
enum PKCS7_R_MIME_SIG_PARSE_ERROR = 134;
enum PKCS7_R_MISSING_CERIPEND_INFO = 103;
enum PKCS7_R_NO_CONTENT = 122;
enum PKCS7_R_NO_CONTENT_TYPE = 135;
enum PKCS7_R_NO_DEFAULT_DIGEST = 151;
enum PKCS7_R_NO_MATCHING_DIGEST_TYPE_FOUND = 154;
enum PKCS7_R_NO_MULTIPART_BODY_FAILURE = 136;
enum PKCS7_R_NO_MULTIPART_BOUNDARY = 137;
enum PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE = 115;
enum PKCS7_R_NO_RECIPIENT_MATCHES_KEY = 146;
enum PKCS7_R_NO_SIGNATURES_ON_DATA = 123;
enum PKCS7_R_NO_SIGNERS = 142;
enum PKCS7_R_NO_SIG_CONTENT_TYPE = 138;
enum PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE = 104;
enum PKCS7_R_PKCS7_ADD_SIGNATURE_ERROR = 124;
enum PKCS7_R_PKCS7_ADD_SIGNER_ERROR = 153;
enum PKCS7_R_PKCS7_DATAFINAL = 126;
enum PKCS7_R_PKCS7_DATAFINAL_ERROR = 125;
enum PKCS7_R_PKCS7_DATASIGN = 145;
enum PKCS7_R_PKCS7_PARSE_ERROR = 139;
enum PKCS7_R_PKCS7_SIG_PARSE_ERROR = 140;
enum PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 127;
enum PKCS7_R_SIGNATURE_FAILURE = 105;
enum PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND = 128;
enum PKCS7_R_SIGNING_CTRL_FAILURE = 147;
enum PKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE = 148;
enum PKCS7_R_SIG_INVALID_MIME_TYPE = 141;
enum PKCS7_R_SMIME_TEXT_ERROR = 129;
enum PKCS7_R_UNABLE_TO_FIND_CERTIFICATE = 106;
enum PKCS7_R_UNABLE_TO_FIND_MEM_BIO = 107;
enum PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST = 108;
enum PKCS7_R_UNKNOWN_DIGEST_TYPE = 109;
enum PKCS7_R_UNKNOWN_OPERATION = 110;
enum PKCS7_R_UNSUPPORTED_CIPHER_TYPE = 111;
enum PKCS7_R_UNSUPPORTED_CONTENT_TYPE = 112;
enum PKCS7_R_WRONG_CONTENT_TYPE = 113;
enum PKCS7_R_WRONG_PKCS7_TYPE = 114;
