/* $OpenBSD: x509.h,v 1.74 2018/08/24 20:26:03 tb Exp $ */
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECDH support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */
module libressl_d.openssl.x509;


private static import core.stdc.config;
private static import libressl_d.compat.stdio;
private static import libressl_d.compat.time;
private static import libressl_d.openssl.x509v3;
public import libressl_d.openssl.asn1;
public import libressl_d.openssl.bio;
public import libressl_d.openssl.buffer;
public import libressl_d.openssl.dh;
public import libressl_d.openssl.dsa;
public import libressl_d.openssl.ec;
public import libressl_d.openssl.ecdh;
public import libressl_d.openssl.ecdsa;
public import libressl_d.openssl.evp;
public import libressl_d.openssl.opensslconf;
public import libressl_d.openssl.ossl_typ;
public import libressl_d.openssl.pkcs7;
public import libressl_d.openssl.rsa;
public import libressl_d.openssl.safestack;
public import libressl_d.openssl.sha;
public import libressl_d.openssl.stack;
public import libressl_d.openssl.x509_vfy;

//version = HEADER_X509_H;

//#if !defined(OPENSSL_NO_BUFFER)
	//public import libressl_d.openssl.buffer;
//#endif

//#if !defined(OPENSSL_NO_EVP)
	//public import libressl_d.openssl.evp;
//#endif

//#if !defined(OPENSSL_NO_BIO)
	//public import libressl_d.openssl.bio;
//#endif

//#if !defined(OPENSSL_NO_EC)
	//public import libressl_d.openssl.ec;
//#endif

//#if !defined(OPENSSL_NO_ECDSA)
	//public import libressl_d.openssl.ecdsa;
//#endif

//#if !defined(OPENSSL_NO_ECDH)
	//public import libressl_d.openssl.ecdh;
//#endif

//#if !defined(OPENSSL_NO_DEPRECATED)
	//#if !defined(OPENSSL_NO_RSA)
		//public import libressl_d.openssl.rsa;
	//#endif

	//#if !defined(OPENSSL_NO_DSA)
		//public import libressl_d.openssl.dsa;
	//#endif

	//#if !defined(OPENSSL_NO_DH)
		//public import libressl_d.openssl.dh;
	//#endif
//#endif

//#if !defined(OPENSSL_NO_SHA)
	//public import libressl_d.openssl.sha;
//#endif

extern (C):
nothrow @nogc:

//#if defined(_WIN32) && defined(__WINCRYPT_H__)
//#if !defined(LIBRESSL_INTERNAL)
//	pragma(msg, "Warning, overriding WinCrypt defines");
//#endif

//#undef libressl_d.openssl.ossl_typ.X509_NAME
//#undef X509_CERT_PAIR
//#undef X509_EXTENSIONS
//#endif

enum X509_FILETYPE_PEM = 1;
enum X509_FILETYPE_ASN1 = 2;
enum X509_FILETYPE_DEFAULT = 3;

enum X509v3_KU_DIGITAL_SIGNATURE = 0x0080;
enum X509v3_KU_NON_REPUDIATION = 0x0040;
enum X509v3_KU_KEY_ENCIPHERMENT = 0x0020;
enum X509v3_KU_DATA_ENCIPHERMENT = 0x0010;
enum X509v3_KU_KEY_AGREEMENT = 0x0008;
enum X509v3_KU_KEY_CERT_SIGN = 0x0004;
enum X509v3_KU_CRL_SIGN = 0x0002;
enum X509v3_KU_ENCIPHER_ONLY = 0x0001;
enum X509v3_KU_DECIPHER_ONLY = 0x8000;
enum X509v3_KU_UNDEF = 0xFFFF;

struct X509_objects_st
{
	int nid;
	int function() a2i;
	int function() i2a;
}

alias X509_OBJECTS = .X509_objects_st;

struct X509_algor_st
{
	libressl_d.openssl.asn1.ASN1_OBJECT* algorithm;
	libressl_d.openssl.asn1.ASN1_TYPE* parameter;
}

alias X509_ALGORS = libressl_d.openssl.asn1.stack_st_X509_ALGOR;

struct X509_val_st
{
	libressl_d.openssl.ossl_typ.ASN1_TIME* notBefore;
	libressl_d.openssl.ossl_typ.ASN1_TIME* notAfter;
}

alias X509_VAL = .X509_val_st;

struct X509_pubkey_st
{
	libressl_d.openssl.ossl_typ.X509_ALGOR* algor;
	libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* public_key;
	libressl_d.openssl.ossl_typ.EVP_PKEY* pkey;
}

struct X509_sig_st
{
	libressl_d.openssl.ossl_typ.X509_ALGOR* algor;
	libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* digest;
}

alias X509_SIG = .X509_sig_st;

struct X509_name_entry_st
{
	libressl_d.openssl.asn1.ASN1_OBJECT* object;
	libressl_d.openssl.ossl_typ.ASN1_STRING* value;
	int set;

	/**
	 * temp variable
	 */
	int size;
}

alias X509_NAME_ENTRY = .X509_name_entry_st;

//DECLARE_STACK_OF(X509_NAME_ENTRY)
struct stack_st_X509_NAME_ENTRY
{
	libressl_d.openssl.stack._STACK stack;
}

/**
 * we always keep X509_NAMEs in 2 forms.
 */
struct X509_name_st
{
	.stack_st_X509_NAME_ENTRY* entries;

	/**
	 * true if 'bytes' needs to be built
	 */
	int modified;

	//#if !defined(OPENSSL_NO_BUFFER)
		libressl_d.openssl.ossl_typ.BUF_MEM* bytes;
	//#else
		//char* bytes;
	//#endif

	/*	core.stdc.config.c_ulong hash; Keep the hash around for lookups */
	ubyte* canon_enc;
	int canon_enclen;
}

//DECLARE_STACK_OF(X509_NAME)
struct stack_st_X509_NAME
{
	libressl_d.openssl.stack._STACK stack;
}

enum X509_EX_V_NETSCAPE_HACK = 0x8000;
enum X509_EX_V_INIT = 0x0001;

struct X509_extension_st
{
	libressl_d.openssl.asn1.ASN1_OBJECT* object;
	libressl_d.openssl.ossl_typ.ASN1_BOOLEAN critical;
	libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* value;
}

alias X509_EXTENSION = .X509_extension_st;

alias X509_EXTENSIONS = .stack_st_X509_EXTENSION;

//DECLARE_STACK_OF(X509_EXTENSION)
struct stack_st_X509_EXTENSION
{
	libressl_d.openssl.stack._STACK stack;
}

/**
 * a sequence of these are used
 */
struct x509_attributes_st
{
	libressl_d.openssl.asn1.ASN1_OBJECT* object;

	/**
	 * 0 for a set, 1 for a single item (which is wrong)
	 */
	int single;

	union value_
	{
		char* ptr_;

		/**
		 * 0
		 */
		libressl_d.openssl.asn1.stack_st_ASN1_TYPE* set;

		/**
		 * 1
		 */
		libressl_d.openssl.asn1.ASN1_TYPE* single;
	}

	value_ value;
}

alias X509_ATTRIBUTE = .x509_attributes_st;

//DECLARE_STACK_OF(X509_ATTRIBUTE)
struct stack_st_X509_ATTRIBUTE
{
	libressl_d.openssl.stack._STACK stack;
}

struct X509_req_info_st
{
	libressl_d.openssl.asn1.ASN1_ENCODING enc;
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* version_;
	libressl_d.openssl.ossl_typ.X509_NAME* subject;
	libressl_d.openssl.ossl_typ.X509_PUBKEY* pubkey;
	/*  d=2 hl=2 l=  0 cons: cont: 00 */

	/**
	 * [ 0 ]
	 */
	.stack_st_X509_ATTRIBUTE* attributes;
}

alias X509_REQ_INFO = .X509_req_info_st;

struct X509_req_st
{
	.X509_REQ_INFO* req_info;
	libressl_d.openssl.ossl_typ.X509_ALGOR* sig_alg;
	libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* signature;
	int references;
}

alias X509_REQ = .X509_req_st;

struct x509_cinf_st
{
	/**
	 * [ 0 ] default of v1
	 */
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* version_;

	libressl_d.openssl.ossl_typ.ASN1_INTEGER* serialNumber;
	libressl_d.openssl.ossl_typ.X509_ALGOR* signature;
	libressl_d.openssl.ossl_typ.X509_NAME* issuer;
	.X509_VAL* validity;
	libressl_d.openssl.ossl_typ.X509_NAME* subject;
	libressl_d.openssl.ossl_typ.X509_PUBKEY* key;

	/**
	 * [ 1 ] optional in v2
	 */
	libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* issuerUID;

	/**
	 * [ 2 ] optional in v2
	 */
	libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* subjectUID;

	/**
	 * [ 3 ] optional in v3
	 */
	.stack_st_X509_EXTENSION* extensions;

	libressl_d.openssl.asn1.ASN1_ENCODING enc;
}

alias X509_CINF = .x509_cinf_st;

/*
 * This stuff is certificate "auxiliary info"
 * it contains details which are useful in certificate
 * stores and databases. When used this is tagged onto
 * the end of the certificate itself
 */

struct x509_cert_aux_st
{
	/**
	 * trusted uses
	 */
	libressl_d.openssl.asn1.stack_st_ASN1_OBJECT* trust;

	/**
	 * rejected uses
	 */
	libressl_d.openssl.asn1.stack_st_ASN1_OBJECT* reject;

	/**
	 * "friendly name"
	 */
	libressl_d.openssl.ossl_typ.ASN1_UTF8STRING* alias_;

	/**
	 * key id of private key
	 */
	libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* keyid;

	/**
	 * other unspecified info
	 */
	libressl_d.openssl.asn1.stack_st_X509_ALGOR* other;
}

alias X509_CERT_AUX = .x509_cert_aux_st;

struct x509_st
{
	.X509_CINF* cert_info;
	libressl_d.openssl.ossl_typ.X509_ALGOR* sig_alg;
	libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* signature;
	int valid;
	int references;
	char* name;
	libressl_d.openssl.ossl_typ.CRYPTO_EX_DATA ex_data;
	/* These contain copies of various extension values */
	core.stdc.config.c_long ex_pathlen;
	core.stdc.config.c_long ex_pcpathlen;
	core.stdc.config.c_ulong ex_flags;
	core.stdc.config.c_ulong ex_kusage;
	core.stdc.config.c_ulong ex_xkusage;
	core.stdc.config.c_ulong ex_nscert;
	libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* skid;
	libressl_d.openssl.ossl_typ.AUTHORITY_KEYID* akid;
	libressl_d.openssl.ossl_typ.X509_POLICY_CACHE* policy_cache;
	libressl_d.openssl.x509v3.stack_st_DIST_POINT* crldp;
	libressl_d.openssl.x509v3.stack_st_GENERAL_NAME* altname;
	libressl_d.openssl.ossl_typ.NAME_CONSTRAINTS* nc;

	//#if !defined(OPENSSL_NO_SHA)
	ubyte[libressl_d.openssl.sha.SHA_DIGEST_LENGTH] sha1_hash;
	//#endif

	.X509_CERT_AUX* aux;
}

//DECLARE_STACK_OF(X509)
struct stack_st_X509
{
	libressl_d.openssl.stack._STACK stack;
}

/* This is used for a table of trust checking functions */

struct x509_trust_st
{
	int trust;
	int flags;
	int function(.x509_trust_st*, libressl_d.openssl.ossl_typ.X509*, int) check_trust;
	char* name;
	int arg1;
	void* arg2;
}

alias X509_TRUST = .x509_trust_st;

//DECLARE_STACK_OF(X509_TRUST)
struct stack_st_X509_TRUST
{
	libressl_d.openssl.stack._STACK stack;
}

struct x509_cert_pair_st
{
	libressl_d.openssl.ossl_typ.X509* forward;
	libressl_d.openssl.ossl_typ.X509* reverse;
}

alias X509_CERT_PAIR = .x509_cert_pair_st;

/* standard trust ids */

/**
 *  Only valid in purpose settings
 */
enum X509_TRUST_DEFAULT = -1;

enum X509_TRUST_COMPAT = 1;
enum X509_TRUST_SSL_CLIENT = 2;
enum X509_TRUST_SSL_SERVER = 3;
enum X509_TRUST_EMAIL = 4;
enum X509_TRUST_OBJECT_SIGN = 5;
enum X509_TRUST_OCSP_SIGN = 6;
enum X509_TRUST_OCSP_REQUEST = 7;
enum X509_TRUST_TSA = 8;

/* Keep these up to date! */
enum X509_TRUST_MIN = 1;
enum X509_TRUST_MAX = 8;

/* trust_flags values */
enum X509_TRUST_DYNAMIC = 1;
enum X509_TRUST_DYNAMIC_NAME = 2;

/* check_trust return codes */

enum X509_TRUST_TRUSTED = 1;
enum X509_TRUST_REJECTED = 2;
enum X509_TRUST_UNTRUSTED = 3;

/* Flags for X509_print_ex() */

enum X509_FLAG_COMPAT = 0;
enum X509_FLAG_NO_HEADER = 1L;
enum X509_FLAG_NO_VERSION = 1L << 1;
enum X509_FLAG_NO_SERIAL = 1L << 2;
enum X509_FLAG_NO_SIGNAME = 1L << 3;
enum X509_FLAG_NO_ISSUER = 1L << 4;
enum X509_FLAG_NO_VALIDITY = 1L << 5;
enum X509_FLAG_NO_SUBJECT = 1L << 6;
enum X509_FLAG_NO_PUBKEY = 1L << 7;
enum X509_FLAG_NO_EXTENSIONS = 1L << 8;
enum X509_FLAG_NO_SIGDUMP = 1L << 9;
enum X509_FLAG_NO_AUX = 1L << 10;
enum X509_FLAG_NO_ATTRIBUTES = 1L << 11;

/* Flags specific to X509_NAME_print_ex() */

/* The field separator information */

enum XN_FLAG_SEP_MASK = 0x0F << 16;

/**
 *  Traditional SSLeay: use old X509_NAME_print
 */
enum XN_FLAG_COMPAT = 0;

/**
 * RFC2253 ,+
 */
enum XN_FLAG_SEP_COMMA_PLUS = 1 << 16;

/**
 * ,+ spaced: more readable
 */
enum XN_FLAG_SEP_CPLUS_SPC = 2 << 16;

/**
 * ;+ spaced
 */
enum XN_FLAG_SEP_SPLUS_SPC = 3 << 16;

/**
 * One line per field
 */
enum XN_FLAG_SEP_MULTILINE = 4 << 16;

/**
 * Reverse DN order
 */
enum XN_FLAG_DN_REV = 1 << 20;

/* How the field name is shown */

enum XN_FLAG_FN_MASK = 0x03 << 21;

/**
 *  Object short name
 */
enum XN_FLAG_FN_SN = 0;

/**
 * Object core.stdc.config.c_long name
 */
enum XN_FLAG_FN_LN = 1 << 21;

/**
 * Always use OIDs
 */
enum XN_FLAG_FN_OID = 2 << 21;

/**
 * No field names
 */
enum XN_FLAG_FN_NONE = 3 << 21;

/**
 * Put spaces round '='
 */
enum XN_FLAG_SPC_EQ = 1 << 23;

/*
 * This determines if we dump fields we don't recognise:
 * RFC2253 requires this.
 */

enum XN_FLAG_DUMP_UNKNOWN_FIELDS = 1 << 24;

/**
 * Align field names to 20 characters
 */
enum XN_FLAG_FN_ALIGN = 1 << 25;

/* Complete set of RFC2253 flags */

enum XN_FLAG_RFC2253 = libressl_d.openssl.asn1.ASN1_STRFLGS_RFC2253 | .XN_FLAG_SEP_COMMA_PLUS | .XN_FLAG_DN_REV | .XN_FLAG_FN_SN | .XN_FLAG_DUMP_UNKNOWN_FIELDS;

/* readable oneline form */

enum XN_FLAG_ONELINE = libressl_d.openssl.asn1.ASN1_STRFLGS_RFC2253 | libressl_d.openssl.asn1.ASN1_STRFLGS_ESC_QUOTE | .XN_FLAG_SEP_CPLUS_SPC | .XN_FLAG_SPC_EQ | .XN_FLAG_FN_SN;

/* readable multiline form */

enum XN_FLAG_MULTILINE = libressl_d.openssl.asn1.ASN1_STRFLGS_ESC_CTRL | libressl_d.openssl.asn1.ASN1_STRFLGS_ESC_MSB | .XN_FLAG_SEP_MULTILINE | .XN_FLAG_SPC_EQ | .XN_FLAG_FN_LN | .XN_FLAG_FN_ALIGN;

struct x509_revoked_st
{
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* serialNumber;
	libressl_d.openssl.ossl_typ.ASN1_TIME* revocationDate;
	.stack_st_X509_EXTENSION /* optional */ * extensions;
	/* Set up if indirect CRL */
	libressl_d.openssl.x509v3.stack_st_GENERAL_NAME* issuer;
	/* Revocation reason */
	int reason;

	/**
	 * load sequence
	 */
	int sequence;
}

//DECLARE_STACK_OF(X509_REVOKED)
struct stack_st_X509_REVOKED
{
	libressl_d.openssl.stack._STACK stack;
}

struct X509_crl_info_st
{
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* version_;
	libressl_d.openssl.ossl_typ.X509_ALGOR* sig_alg;
	libressl_d.openssl.ossl_typ.X509_NAME* issuer;
	libressl_d.openssl.ossl_typ.ASN1_TIME* lastUpdate;
	libressl_d.openssl.ossl_typ.ASN1_TIME* nextUpdate;
	.stack_st_X509_REVOKED* revoked;
	.stack_st_X509_EXTENSION /* [0] */ * extensions;
	libressl_d.openssl.asn1.ASN1_ENCODING enc;
}

alias X509_CRL_INFO = .X509_crl_info_st;
package alias stack_st_GENERAL_NAMES = void;

struct X509_crl_st
{
	/* actual signature */
	.X509_CRL_INFO* crl;
	libressl_d.openssl.ossl_typ.X509_ALGOR* sig_alg;
	libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* signature;
	int references;
	int flags;
	/* Copies of various extensions */
	libressl_d.openssl.ossl_typ.AUTHORITY_KEYID* akid;
	libressl_d.openssl.ossl_typ.ISSUING_DIST_POINT* idp;
	/* Convenient breakdown of IDP */
	int idp_flags;
	int idp_reasons;
	/* CRL and base CRL numbers for delta processing */
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* crl_number;
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* base_crl_number;

	//#if !defined(OPENSSL_NO_SHA)
	ubyte[libressl_d.openssl.sha.SHA_DIGEST_LENGTH] sha1_hash;
	//#endif

	stack_st_GENERAL_NAMES* issuers;
	const (libressl_d.openssl.ossl_typ.X509_CRL_METHOD)* meth;
	void* meth_data;
}

//DECLARE_STACK_OF(X509_CRL)
struct stack_st_X509_CRL
{
	libressl_d.openssl.stack._STACK stack;
}

struct private_key_st
{
	int version_;
	/* The PKCS#8 data types */
	libressl_d.openssl.ossl_typ.X509_ALGOR* enc_algor;

	/**
	 * encrypted pub key
	 */
	libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* enc_pkey;

	/* When decrypted, the following will not be null */
	libressl_d.openssl.ossl_typ.EVP_PKEY* dec_pkey;

	/* used to encrypt and decrypt */
	int key_length;
	char* key_data;

	/**
	 * true if we should auto free key_data
	 */
	int key_free;

	/* expanded version of 'enc_algor' */
	libressl_d.openssl.evp.EVP_CIPHER_INFO cipher;

	int references;
}

alias X509_PKEY = .private_key_st;

//#if !defined(OPENSSL_NO_EVP)
struct X509_info_st
{
	libressl_d.openssl.ossl_typ.X509* x509;
	libressl_d.openssl.ossl_typ.X509_CRL* crl;
	.X509_PKEY* x_pkey;

	libressl_d.openssl.evp.EVP_CIPHER_INFO enc_cipher;
	int enc_len;
	char* enc_data;

	int references;
}

alias X509_INFO = .X509_info_st;

//DECLARE_STACK_OF(X509_INFO)
struct stack_st_X509_INFO
{
	libressl_d.openssl.stack._STACK stack;
}
//#endif

/**
 * The next 2 structures and their 8 routines were sent to me by
 * Pat Richard <patr@x509.com> and are used to manipulate
 * Netscapes spki structures - useful if you are writing a CA web page
 */
struct Netscape_spkac_st
{
	libressl_d.openssl.ossl_typ.X509_PUBKEY* pubkey;

	/**
	 * challenge sent in atlas >= PR2
	 */
	libressl_d.openssl.ossl_typ.ASN1_IA5STRING* challenge;
}

alias NETSCAPE_SPKAC = .Netscape_spkac_st;

struct Netscape_spki_st
{
	/**
	 * signed public key and challenge
	 */
	.NETSCAPE_SPKAC* spkac;

	libressl_d.openssl.ossl_typ.X509_ALGOR* sig_algor;
	libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* signature;
}

alias NETSCAPE_SPKI = .Netscape_spki_st;

/**
 * Netscape certificate sequence structure
 */
struct Netscape_certificate_sequence
{
	libressl_d.openssl.asn1.ASN1_OBJECT* type;
	.stack_st_X509* certs;
}

alias NETSCAPE_CERT_SEQUENCE = .Netscape_certificate_sequence;

/*
 * nused (and iv length is wrong)
struct CBCParameter_st
{
ubyte[8] iv;
}

alias CBC_PARAM = .CBCParameter_st;
 */

/* Password based encryption structure */

struct PBEPARAM_st
{
	libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* salt;
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* iter;
}

alias PBEPARAM = .PBEPARAM_st;

/**
 * Password based encryption V2 structures
 */
struct PBE2PARAM_st
{
	libressl_d.openssl.ossl_typ.X509_ALGOR* keyfunc;
	libressl_d.openssl.ossl_typ.X509_ALGOR* encryption;
}

alias PBE2PARAM = .PBE2PARAM_st;

struct PBKDF2PARAM_st
{
	/**
	 * Usually OCTET STRING but could be anything
	 */
	libressl_d.openssl.asn1.ASN1_TYPE* salt;

	libressl_d.openssl.ossl_typ.ASN1_INTEGER* iter;
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* keylength;
	libressl_d.openssl.ossl_typ.X509_ALGOR* prf;
}

alias PBKDF2PARAM = .PBKDF2PARAM_st;

/**
 * PKCS#8 private key info structure
 */
struct pkcs8_priv_key_info_st
{
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* version_;
	libressl_d.openssl.ossl_typ.X509_ALGOR* pkeyalg;
	libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* pkey;
	.stack_st_X509_ATTRIBUTE* attributes;
}

enum X509_EXT_PACK_UNKNOWN = 1;
enum X509_EXT_PACK_STRING = 2;

/*****/
//#define X509_extract_key(x) X509_get_pubkey(x)

//#define X509_REQ_extract_key(a) .X509_REQ_get_pubkey(a)
//#define X509_name_cmp(a, b) .X509_NAME_cmp(a, b)

int X509_CRL_up_ref(libressl_d.openssl.ossl_typ.X509_CRL* x);
int X509_CRL_get_signature_nid(const (libressl_d.openssl.ossl_typ.X509_CRL)* crl);

const (.stack_st_X509_EXTENSION)* X509_CRL_get0_extensions(const (libressl_d.openssl.ossl_typ.X509_CRL)* crl);
core.stdc.config.c_long X509_CRL_get_version(const (libressl_d.openssl.ossl_typ.X509_CRL)* crl);
const (libressl_d.openssl.ossl_typ.ASN1_TIME)* X509_CRL_get0_lastUpdate(const (libressl_d.openssl.ossl_typ.X509_CRL)* crl);
const (libressl_d.openssl.ossl_typ.ASN1_TIME)* X509_CRL_get0_nextUpdate(const (libressl_d.openssl.ossl_typ.X509_CRL)* crl);
libressl_d.openssl.ossl_typ.ASN1_TIME* X509_CRL_get_lastUpdate(libressl_d.openssl.ossl_typ.X509_CRL* crl);
libressl_d.openssl.ossl_typ.ASN1_TIME* X509_CRL_get_nextUpdate(libressl_d.openssl.ossl_typ.X509_CRL* crl);
libressl_d.openssl.ossl_typ.X509_NAME* X509_CRL_get_issuer(const (libressl_d.openssl.ossl_typ.X509_CRL)* crl);
.stack_st_X509_REVOKED* X509_CRL_get_REVOKED(libressl_d.openssl.ossl_typ.X509_CRL* crl);
void X509_CRL_get0_signature(const (libressl_d.openssl.ossl_typ.X509_CRL)* crl, const (libressl_d.openssl.ossl_typ.ASN1_BIT_STRING)** psig, const (libressl_d.openssl.ossl_typ.X509_ALGOR)** palg);

int X509_REQ_get_signature_nid(const (.X509_REQ)* req);

void X509_REQ_get0_signature(const (.X509_REQ)* req, const (libressl_d.openssl.ossl_typ.ASN1_BIT_STRING)** psig, const (libressl_d.openssl.ossl_typ.X509_ALGOR)** palg);

void X509_CRL_set_default_method(const (libressl_d.openssl.ossl_typ.X509_CRL_METHOD)* meth);
libressl_d.openssl.ossl_typ.X509_CRL_METHOD* X509_CRL_METHOD_new(int function(libressl_d.openssl.ossl_typ.X509_CRL* crl) crl_init, int function(libressl_d.openssl.ossl_typ.X509_CRL* crl) crl_free, int function(libressl_d.openssl.ossl_typ.X509_CRL* crl, libressl_d.openssl.ossl_typ.X509_REVOKED** ret, libressl_d.openssl.ossl_typ.ASN1_INTEGER* ser, libressl_d.openssl.ossl_typ.X509_NAME* issuer) crl_lookup, int function(libressl_d.openssl.ossl_typ.X509_CRL* crl, libressl_d.openssl.ossl_typ.EVP_PKEY* pk) crl_verify);
void X509_CRL_METHOD_free(libressl_d.openssl.ossl_typ.X509_CRL_METHOD* m);

void X509_CRL_set_meth_data(libressl_d.openssl.ossl_typ.X509_CRL* crl, void* dat);
void* X509_CRL_get_meth_data(libressl_d.openssl.ossl_typ.X509_CRL* crl);

/*
 * This one is only used so that a binary form can output, as in
 * i2d_X509_NAME(X509_get_X509_PUBKEY(x),&buf)
 */
//#define X509_get_X509_PUBKEY(x) (x.cert_info.key)

const (char)* X509_verify_cert_error_string(core.stdc.config.c_long n);

//#if !defined(OPENSSL_NO_EVP)
int X509_verify(libressl_d.openssl.ossl_typ.X509* a, libressl_d.openssl.ossl_typ.EVP_PKEY* r);

int X509_REQ_verify(.X509_REQ* a, libressl_d.openssl.ossl_typ.EVP_PKEY* r);
int X509_CRL_verify(libressl_d.openssl.ossl_typ.X509_CRL* a, libressl_d.openssl.ossl_typ.EVP_PKEY* r);
int NETSCAPE_SPKI_verify(.NETSCAPE_SPKI* a, libressl_d.openssl.ossl_typ.EVP_PKEY* r);

.NETSCAPE_SPKI* NETSCAPE_SPKI_b64_decode(const (char)* str, int len);
char* NETSCAPE_SPKI_b64_encode(.NETSCAPE_SPKI* x);
libressl_d.openssl.ossl_typ.EVP_PKEY* NETSCAPE_SPKI_get_pubkey(.NETSCAPE_SPKI* x);
int NETSCAPE_SPKI_set_pubkey(.NETSCAPE_SPKI* x, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);

int NETSCAPE_SPKI_print(libressl_d.openssl.bio.BIO* out_, .NETSCAPE_SPKI* spki);

int X509_signature_dump(libressl_d.openssl.bio.BIO* bp, const (libressl_d.openssl.ossl_typ.ASN1_STRING)* sig, int indent);
int X509_signature_print(libressl_d.openssl.bio.BIO* bp, const (libressl_d.openssl.ossl_typ.X509_ALGOR)* alg, const (libressl_d.openssl.ossl_typ.ASN1_STRING)* sig);

int X509_sign(libressl_d.openssl.ossl_typ.X509* x, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, const (libressl_d.openssl.ossl_typ.EVP_MD)* md);
int X509_sign_ctx(libressl_d.openssl.ossl_typ.X509* x, libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx);
int X509_REQ_sign(.X509_REQ* x, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, const (libressl_d.openssl.ossl_typ.EVP_MD)* md);
int X509_REQ_sign_ctx(.X509_REQ* x, libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx);
int X509_CRL_sign(libressl_d.openssl.ossl_typ.X509_CRL* x, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, const (libressl_d.openssl.ossl_typ.EVP_MD)* md);
int X509_CRL_sign_ctx(libressl_d.openssl.ossl_typ.X509_CRL* x, libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx);
int NETSCAPE_SPKI_sign(.NETSCAPE_SPKI* x, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, const (libressl_d.openssl.ossl_typ.EVP_MD)* md);

int X509_pubkey_digest(const (libressl_d.openssl.ossl_typ.X509)* data, const (libressl_d.openssl.ossl_typ.EVP_MD)* type, ubyte* md, uint* len);
int X509_digest(const (libressl_d.openssl.ossl_typ.X509)* data, const (libressl_d.openssl.ossl_typ.EVP_MD)* type, ubyte* md, uint* len);
int X509_CRL_digest(const (libressl_d.openssl.ossl_typ.X509_CRL)* data, const (libressl_d.openssl.ossl_typ.EVP_MD)* type, ubyte* md, uint* len);
int X509_REQ_digest(const (.X509_REQ)* data, const (libressl_d.openssl.ossl_typ.EVP_MD)* type, ubyte* md, uint* len);
int X509_NAME_digest(const (libressl_d.openssl.ossl_typ.X509_NAME)* data, const (libressl_d.openssl.ossl_typ.EVP_MD)* type, ubyte* md, uint* len);
//#endif

libressl_d.openssl.ossl_typ.X509* d2i_X509_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.X509** x509);
int i2d_X509_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.X509* x509);
libressl_d.openssl.ossl_typ.X509_CRL* d2i_X509_CRL_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.X509_CRL** crl);
int i2d_X509_CRL_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.X509_CRL* crl);
.X509_REQ* d2i_X509_REQ_fp(libressl_d.compat.stdio.FILE* fp, .X509_REQ** req);
int i2d_X509_REQ_fp(libressl_d.compat.stdio.FILE* fp, .X509_REQ* req);

//#if !defined(OPENSSL_NO_RSA)
libressl_d.openssl.ossl_typ.RSA* d2i_RSAPrivateKey_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.RSA** rsa);
int i2d_RSAPrivateKey_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.RSA* rsa);
libressl_d.openssl.ossl_typ.RSA* d2i_RSAPublicKey_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.RSA** rsa);
int i2d_RSAPublicKey_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.RSA* rsa);
libressl_d.openssl.ossl_typ.RSA* d2i_RSA_PUBKEY_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.RSA** rsa);
int i2d_RSA_PUBKEY_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.RSA* rsa);
//#endif

//#if !defined(OPENSSL_NO_DSA)
libressl_d.openssl.ossl_typ.DSA* d2i_DSA_PUBKEY_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.DSA** dsa);
int i2d_DSA_PUBKEY_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.DSA* dsa);
int i2d_DSAPrivateKey_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.DSA* dsa);
//#endif

//#if !defined(OPENSSL_NO_EC)
libressl_d.openssl.ec.EC_KEY* d2i_EC_PUBKEY_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ec.EC_KEY** eckey);
int i2d_EC_PUBKEY_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ec.EC_KEY* eckey);
libressl_d.openssl.ec.EC_KEY* d2i_ECPrivateKey_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ec.EC_KEY** eckey);
int i2d_ECPrivateKey_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ec.EC_KEY* eckey);
//#endif

.X509_SIG* d2i_PKCS8_fp(libressl_d.compat.stdio.FILE* fp, .X509_SIG** p8);
int i2d_PKCS8_fp(libressl_d.compat.stdio.FILE* fp, .X509_SIG* p8);
libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* d2i_PKCS8_PRIV_KEY_INFO_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO** p8inf);
int i2d_PKCS8_PRIV_KEY_INFO_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* p8inf);
int i2d_PKCS8PrivateKeyInfo_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.EVP_PKEY* key);
int i2d_PrivateKey_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
libressl_d.openssl.ossl_typ.EVP_PKEY* d2i_PrivateKey_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.EVP_PKEY** a);
int i2d_PUBKEY_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
libressl_d.openssl.ossl_typ.EVP_PKEY* d2i_PUBKEY_fp(libressl_d.compat.stdio.FILE* fp, libressl_d.openssl.ossl_typ.EVP_PKEY** a);

//#if !defined(OPENSSL_NO_BIO)
libressl_d.openssl.ossl_typ.X509* d2i_X509_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.X509** x509);
int i2d_X509_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.X509* x509);
libressl_d.openssl.ossl_typ.X509_CRL* d2i_X509_CRL_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.X509_CRL** crl);
int i2d_X509_CRL_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.X509_CRL* crl);
.X509_REQ* d2i_X509_REQ_bio(libressl_d.openssl.bio.BIO* bp, .X509_REQ** req);
int i2d_X509_REQ_bio(libressl_d.openssl.bio.BIO* bp, .X509_REQ* req);

//#if !defined(OPENSSL_NO_RSA)
libressl_d.openssl.ossl_typ.RSA* d2i_RSAPrivateKey_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.RSA** rsa);
int i2d_RSAPrivateKey_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.RSA* rsa);
libressl_d.openssl.ossl_typ.RSA* d2i_RSAPublicKey_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.RSA** rsa);
int i2d_RSAPublicKey_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.RSA* rsa);
libressl_d.openssl.ossl_typ.RSA* d2i_RSA_PUBKEY_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.RSA** rsa);
int i2d_RSA_PUBKEY_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.RSA* rsa);
//#endif

//#if !defined(OPENSSL_NO_DSA)
libressl_d.openssl.ossl_typ.DSA* d2i_DSA_PUBKEY_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.DSA** dsa);
int i2d_DSA_PUBKEY_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.DSA* dsa);
libressl_d.openssl.ossl_typ.DSA* d2i_DSAPrivateKey_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.DSA** dsa);
int i2d_DSAPrivateKey_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.DSA* dsa);
//#endif

//#if !defined(OPENSSL_NO_EC)
libressl_d.openssl.ec.EC_KEY* d2i_EC_PUBKEY_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ec.EC_KEY** eckey);
int i2d_EC_PUBKEY_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ec.EC_KEY* eckey);
libressl_d.openssl.ec.EC_KEY* d2i_ECPrivateKey_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ec.EC_KEY** eckey);
int i2d_ECPrivateKey_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ec.EC_KEY* eckey);
//#endif

.X509_SIG* d2i_PKCS8_bio(libressl_d.openssl.bio.BIO* bp, .X509_SIG** p8);
int i2d_PKCS8_bio(libressl_d.openssl.bio.BIO* bp, .X509_SIG* p8);
libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* d2i_PKCS8_PRIV_KEY_INFO_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO** p8inf);
int i2d_PKCS8_PRIV_KEY_INFO_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* p8inf);
int i2d_PKCS8PrivateKeyInfo_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.EVP_PKEY* key);
int i2d_PrivateKey_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
libressl_d.openssl.ossl_typ.EVP_PKEY* d2i_PrivateKey_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.EVP_PKEY** a);
int i2d_PUBKEY_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
libressl_d.openssl.ossl_typ.EVP_PKEY* d2i_PUBKEY_bio(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.EVP_PKEY** a);
//#endif

libressl_d.openssl.ossl_typ.X509* X509_dup(libressl_d.openssl.ossl_typ.X509* x509);
.X509_ATTRIBUTE* X509_ATTRIBUTE_dup(.X509_ATTRIBUTE* xa);
.X509_EXTENSION* X509_EXTENSION_dup(.X509_EXTENSION* ex);
libressl_d.openssl.ossl_typ.X509_CRL* X509_CRL_dup(libressl_d.openssl.ossl_typ.X509_CRL* crl);
.X509_REQ* X509_REQ_dup(.X509_REQ* req);
libressl_d.openssl.ossl_typ.X509_ALGOR* X509_ALGOR_dup(libressl_d.openssl.ossl_typ.X509_ALGOR* xn);
int X509_ALGOR_set0(libressl_d.openssl.ossl_typ.X509_ALGOR* alg, libressl_d.openssl.asn1.ASN1_OBJECT* aobj, int ptype, void* pval);
void X509_ALGOR_get0(const (libressl_d.openssl.asn1.ASN1_OBJECT)** paobj, int* pptype, const (void)** ppval, const (libressl_d.openssl.ossl_typ.X509_ALGOR)* algor);
void X509_ALGOR_set_md(libressl_d.openssl.ossl_typ.X509_ALGOR* alg, const (libressl_d.openssl.ossl_typ.EVP_MD)* md);
int X509_ALGOR_cmp(const (libressl_d.openssl.ossl_typ.X509_ALGOR)* a, const (libressl_d.openssl.ossl_typ.X509_ALGOR)* b);

libressl_d.openssl.ossl_typ.X509_NAME* X509_NAME_dup(libressl_d.openssl.ossl_typ.X509_NAME* xn);
int X509_NAME_get0_der(libressl_d.openssl.ossl_typ.X509_NAME* nm, const (ubyte)** pder, size_t* pderlen);
.X509_NAME_ENTRY* X509_NAME_ENTRY_dup(.X509_NAME_ENTRY* ne);

int X509_cmp_time(const (libressl_d.openssl.ossl_typ.ASN1_TIME)* s, libressl_d.compat.time.time_t* t);
int X509_cmp_current_time(const (libressl_d.openssl.ossl_typ.ASN1_TIME)* s);
libressl_d.openssl.ossl_typ.ASN1_TIME* X509_time_adj(libressl_d.openssl.ossl_typ.ASN1_TIME* s, core.stdc.config.c_long adj, libressl_d.compat.time.time_t* t);
libressl_d.openssl.ossl_typ.ASN1_TIME* X509_time_adj_ex(libressl_d.openssl.ossl_typ.ASN1_TIME* s, int offset_day, core.stdc.config.c_long offset_sec, libressl_d.compat.time.time_t* t);
libressl_d.openssl.ossl_typ.ASN1_TIME* X509_gmtime_adj(libressl_d.openssl.ossl_typ.ASN1_TIME* s, core.stdc.config.c_long adj);

const (char)* X509_get_default_cert_area();
const (char)* X509_get_default_cert_dir();
const (char)* X509_get_default_cert_file();
const (char)* X509_get_default_cert_dir_env();
const (char)* X509_get_default_cert_file_env();
const (char)* X509_get_default_private_dir();

.X509_REQ* X509_to_X509_REQ(libressl_d.openssl.ossl_typ.X509* x, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, const (libressl_d.openssl.ossl_typ.EVP_MD)* md);
libressl_d.openssl.ossl_typ.X509* X509_REQ_to_X509(.X509_REQ* r, int days, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);

libressl_d.openssl.ossl_typ.X509_ALGOR* X509_ALGOR_new();
void X509_ALGOR_free(libressl_d.openssl.ossl_typ.X509_ALGOR* a);
libressl_d.openssl.ossl_typ.X509_ALGOR* d2i_X509_ALGOR(libressl_d.openssl.ossl_typ.X509_ALGOR** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_ALGOR(libressl_d.openssl.ossl_typ.X509_ALGOR* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_ALGOR_it;
.X509_ALGORS* d2i_X509_ALGORS(.X509_ALGORS** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_ALGORS(.X509_ALGORS* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_ALGORS_it;
.X509_VAL* X509_VAL_new();
void X509_VAL_free(.X509_VAL* a);
.X509_VAL* d2i_X509_VAL(.X509_VAL** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_VAL(.X509_VAL* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_VAL_it;

libressl_d.openssl.ossl_typ.X509_PUBKEY* X509_PUBKEY_new();
void X509_PUBKEY_free(libressl_d.openssl.ossl_typ.X509_PUBKEY* a);
libressl_d.openssl.ossl_typ.X509_PUBKEY* d2i_X509_PUBKEY(libressl_d.openssl.ossl_typ.X509_PUBKEY** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_PUBKEY(libressl_d.openssl.ossl_typ.X509_PUBKEY* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_PUBKEY_it;

int X509_PUBKEY_set(libressl_d.openssl.ossl_typ.X509_PUBKEY** x, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
libressl_d.openssl.ossl_typ.EVP_PKEY* X509_PUBKEY_get(libressl_d.openssl.ossl_typ.X509_PUBKEY* key);
libressl_d.openssl.ossl_typ.EVP_PKEY* X509_PUBKEY_get0(libressl_d.openssl.ossl_typ.X509_PUBKEY* key);
int X509_get_pubkey_parameters(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, .stack_st_X509 * chain);
int i2d_PUBKEY(libressl_d.openssl.ossl_typ.EVP_PKEY* a, ubyte** pp);
libressl_d.openssl.ossl_typ.EVP_PKEY* d2i_PUBKEY(libressl_d.openssl.ossl_typ.EVP_PKEY** a, const (ubyte)** pp, core.stdc.config.c_long length_);

//#if !defined(OPENSSL_NO_RSA)
int i2d_RSA_PUBKEY(libressl_d.openssl.ossl_typ.RSA* a, ubyte** pp);
libressl_d.openssl.ossl_typ.RSA* d2i_RSA_PUBKEY(libressl_d.openssl.ossl_typ.RSA** a, const (ubyte)** pp, core.stdc.config.c_long length_);
//#endif

//#if !defined(OPENSSL_NO_DSA)
int i2d_DSA_PUBKEY(libressl_d.openssl.ossl_typ.DSA* a, ubyte** pp);
libressl_d.openssl.ossl_typ.DSA* d2i_DSA_PUBKEY(libressl_d.openssl.ossl_typ.DSA** a, const (ubyte)** pp, core.stdc.config.c_long length_);
//#endif

//#if !defined(OPENSSL_NO_EC)
int i2d_EC_PUBKEY(libressl_d.openssl.ec.EC_KEY* a, ubyte** pp);
libressl_d.openssl.ec.EC_KEY* d2i_EC_PUBKEY(libressl_d.openssl.ec.EC_KEY** a, const (ubyte)** pp, core.stdc.config.c_long length_);
//#endif

.X509_SIG* X509_SIG_new();
void X509_SIG_free(.X509_SIG* a);
.X509_SIG* d2i_X509_SIG(.X509_SIG** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_SIG(.X509_SIG* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_SIG_it;
.X509_REQ_INFO* X509_REQ_INFO_new();
void X509_REQ_INFO_free(.X509_REQ_INFO* a);
.X509_REQ_INFO* d2i_X509_REQ_INFO(.X509_REQ_INFO** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_REQ_INFO(.X509_REQ_INFO* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_REQ_INFO_it;
.X509_REQ* X509_REQ_new();
void X509_REQ_free(.X509_REQ* a);
.X509_REQ* d2i_X509_REQ(.X509_REQ** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_REQ(.X509_REQ* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_REQ_it;

.X509_ATTRIBUTE* X509_ATTRIBUTE_new();
void X509_ATTRIBUTE_free(.X509_ATTRIBUTE* a);
.X509_ATTRIBUTE* d2i_X509_ATTRIBUTE(.X509_ATTRIBUTE** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_ATTRIBUTE(.X509_ATTRIBUTE* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_ATTRIBUTE_it;
.X509_ATTRIBUTE* X509_ATTRIBUTE_create(int nid, int atrtype, void* value);

.X509_EXTENSION* X509_EXTENSION_new();
void X509_EXTENSION_free(.X509_EXTENSION* a);
.X509_EXTENSION* d2i_X509_EXTENSION(.X509_EXTENSION** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_EXTENSION(.X509_EXTENSION* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_EXTENSION_it;
X509_EXTENSIONS* d2i_X509_EXTENSIONS(X509_EXTENSIONS** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_EXTENSIONS(X509_EXTENSIONS* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_EXTENSIONS_it;

.X509_NAME_ENTRY* X509_NAME_ENTRY_new();
void X509_NAME_ENTRY_free(.X509_NAME_ENTRY* a);
.X509_NAME_ENTRY* d2i_X509_NAME_ENTRY(.X509_NAME_ENTRY** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_NAME_ENTRY(.X509_NAME_ENTRY* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_NAME_ENTRY_it;

libressl_d.openssl.ossl_typ.X509_NAME* X509_NAME_new();
void X509_NAME_free(libressl_d.openssl.ossl_typ.X509_NAME* a);
libressl_d.openssl.ossl_typ.X509_NAME* d2i_X509_NAME(libressl_d.openssl.ossl_typ.X509_NAME** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_NAME(libressl_d.openssl.ossl_typ.X509_NAME* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_NAME_it;

int X509_NAME_set(libressl_d.openssl.ossl_typ.X509_NAME** xn, libressl_d.openssl.ossl_typ.X509_NAME* name);

.X509_CINF* X509_CINF_new();
void X509_CINF_free(.X509_CINF* a);
.X509_CINF* d2i_X509_CINF(.X509_CINF** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_CINF(.X509_CINF* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_CINF_it;

libressl_d.openssl.ossl_typ.X509* X509_new();
void X509_free(libressl_d.openssl.ossl_typ.X509* a);
libressl_d.openssl.ossl_typ.X509* d2i_X509(libressl_d.openssl.ossl_typ.X509** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509(libressl_d.openssl.ossl_typ.X509* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_it;
.X509_CERT_AUX* X509_CERT_AUX_new();
void X509_CERT_AUX_free(.X509_CERT_AUX* a);
.X509_CERT_AUX* d2i_X509_CERT_AUX(.X509_CERT_AUX** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_CERT_AUX(.X509_CERT_AUX* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_CERT_AUX_it;

.X509_CERT_PAIR* X509_CERT_PAIR_new();
void X509_CERT_PAIR_free(.X509_CERT_PAIR* a);
.X509_CERT_PAIR* d2i_X509_CERT_PAIR(.X509_CERT_PAIR** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_CERT_PAIR(.X509_CERT_PAIR* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_CERT_PAIR_it;

int X509_get_ex_new_index(core.stdc.config.c_long argl, void* argp, libressl_d.openssl.ossl_typ.CRYPTO_EX_new* new_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_dup* dup_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_free* free_func);
int X509_set_ex_data(libressl_d.openssl.ossl_typ.X509* r, int idx, void* arg);
void* X509_get_ex_data(libressl_d.openssl.ossl_typ.X509* r, int idx);
int i2d_X509_AUX(libressl_d.openssl.ossl_typ.X509* a, ubyte** pp);
libressl_d.openssl.ossl_typ.X509* d2i_X509_AUX(libressl_d.openssl.ossl_typ.X509** a, const (ubyte)** pp, core.stdc.config.c_long length_);
void X509_get0_signature(const (libressl_d.openssl.ossl_typ.ASN1_BIT_STRING)** psig, const (libressl_d.openssl.ossl_typ.X509_ALGOR)** palg, const (libressl_d.openssl.ossl_typ.X509)* x);
int X509_get_signature_nid(const (libressl_d.openssl.ossl_typ.X509)* x);

int X509_alias_set1(libressl_d.openssl.ossl_typ.X509* x, const (ubyte)* name, int len);
int X509_keyid_set1(libressl_d.openssl.ossl_typ.X509* x, const (ubyte)* id, int len);
ubyte* X509_alias_get0(libressl_d.openssl.ossl_typ.X509* x, int* len);
ubyte* X509_keyid_get0(libressl_d.openssl.ossl_typ.X509* x, int* len);
//int (*X509_TRUST_set_default(int function(int, libressl_d.openssl.ossl_typ.X509*, int) trust))(int, libressl_d.openssl.ossl_typ.X509*, int);
int X509_TRUST_set(int* t, int trust);
int X509_add1_trust_object(libressl_d.openssl.ossl_typ.X509* x, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj);
int X509_add1_reject_object(libressl_d.openssl.ossl_typ.X509* x, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj);
void X509_trust_clear(libressl_d.openssl.ossl_typ.X509* x);
void X509_reject_clear(libressl_d.openssl.ossl_typ.X509* x);

libressl_d.openssl.ossl_typ.X509_REVOKED* X509_REVOKED_new();
void X509_REVOKED_free(libressl_d.openssl.ossl_typ.X509_REVOKED* a);
libressl_d.openssl.ossl_typ.X509_REVOKED* X509_REVOKED_dup(libressl_d.openssl.ossl_typ.X509_REVOKED* a);
libressl_d.openssl.ossl_typ.X509_REVOKED* d2i_X509_REVOKED(libressl_d.openssl.ossl_typ.X509_REVOKED** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_REVOKED(libressl_d.openssl.ossl_typ.X509_REVOKED* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_REVOKED_it;

.X509_CRL_INFO* X509_CRL_INFO_new();
void X509_CRL_INFO_free(.X509_CRL_INFO* a);
.X509_CRL_INFO* d2i_X509_CRL_INFO(.X509_CRL_INFO** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_CRL_INFO(.X509_CRL_INFO* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_CRL_INFO_it;

libressl_d.openssl.ossl_typ.X509_CRL* X509_CRL_new();
void X509_CRL_free(libressl_d.openssl.ossl_typ.X509_CRL* a);
libressl_d.openssl.ossl_typ.X509_CRL* d2i_X509_CRL(libressl_d.openssl.ossl_typ.X509_CRL** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_X509_CRL(libressl_d.openssl.ossl_typ.X509_CRL* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM X509_CRL_it;

int X509_CRL_add0_revoked(libressl_d.openssl.ossl_typ.X509_CRL* crl, libressl_d.openssl.ossl_typ.X509_REVOKED* rev);
int X509_CRL_get0_by_serial(libressl_d.openssl.ossl_typ.X509_CRL* crl, libressl_d.openssl.ossl_typ.X509_REVOKED** ret, libressl_d.openssl.ossl_typ.ASN1_INTEGER* serial);
int X509_CRL_get0_by_cert(libressl_d.openssl.ossl_typ.X509_CRL* crl, libressl_d.openssl.ossl_typ.X509_REVOKED** ret, libressl_d.openssl.ossl_typ.X509* x);

.X509_PKEY* X509_PKEY_new();
void X509_PKEY_free(.X509_PKEY* a);

.NETSCAPE_SPKI* NETSCAPE_SPKI_new();
void NETSCAPE_SPKI_free(.NETSCAPE_SPKI* a);
.NETSCAPE_SPKI* d2i_NETSCAPE_SPKI(.NETSCAPE_SPKI** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_NETSCAPE_SPKI(.NETSCAPE_SPKI* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM NETSCAPE_SPKI_it;
.NETSCAPE_SPKAC* NETSCAPE_SPKAC_new();
void NETSCAPE_SPKAC_free(.NETSCAPE_SPKAC* a);
.NETSCAPE_SPKAC* d2i_NETSCAPE_SPKAC(.NETSCAPE_SPKAC** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_NETSCAPE_SPKAC(.NETSCAPE_SPKAC* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM NETSCAPE_SPKAC_it;
.NETSCAPE_CERT_SEQUENCE* NETSCAPE_CERT_SEQUENCE_new();
void NETSCAPE_CERT_SEQUENCE_free(.NETSCAPE_CERT_SEQUENCE* a);
.NETSCAPE_CERT_SEQUENCE* d2i_NETSCAPE_CERT_SEQUENCE(.NETSCAPE_CERT_SEQUENCE** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_NETSCAPE_CERT_SEQUENCE(.NETSCAPE_CERT_SEQUENCE* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM NETSCAPE_CERT_SEQUENCE_it;

//#if !defined(OPENSSL_NO_EVP)
.X509_INFO* X509_INFO_new();
void X509_INFO_free(.X509_INFO* a);
char* X509_NAME_oneline(const (libressl_d.openssl.ossl_typ.X509_NAME)* a, char* buf, int size);

int ASN1_item_digest(const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, const (libressl_d.openssl.ossl_typ.EVP_MD)* type, void* data, ubyte* md, uint* len);

int ASN1_item_verify(const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, libressl_d.openssl.ossl_typ.X509_ALGOR* algor1, libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* signature, void* data, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);

int ASN1_item_sign(const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, libressl_d.openssl.ossl_typ.X509_ALGOR* algor1, libressl_d.openssl.ossl_typ.X509_ALGOR* algor2, libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* signature, void* data, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey, const (libressl_d.openssl.ossl_typ.EVP_MD)* type);
int ASN1_item_sign_ctx(const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, libressl_d.openssl.ossl_typ.X509_ALGOR* algor1, libressl_d.openssl.ossl_typ.X509_ALGOR* algor2, libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* signature, void* asn, libressl_d.openssl.ossl_typ.EVP_MD_CTX* ctx);
//#endif

const (.stack_st_X509_EXTENSION)* X509_get0_extensions(const (libressl_d.openssl.ossl_typ.X509)* x);
const (libressl_d.openssl.ossl_typ.X509_ALGOR)* X509_get0_tbs_sigalg(const (libressl_d.openssl.ossl_typ.X509)* x);
int X509_set_version(libressl_d.openssl.ossl_typ.X509* x, core.stdc.config.c_long version_);
core.stdc.config.c_long X509_get_version(const (libressl_d.openssl.ossl_typ.X509)* x);
int X509_set_serialNumber(libressl_d.openssl.ossl_typ.X509* x, libressl_d.openssl.ossl_typ.ASN1_INTEGER* serial);
libressl_d.openssl.ossl_typ.ASN1_INTEGER* X509_get_serialNumber(libressl_d.openssl.ossl_typ.X509* x);
const (libressl_d.openssl.ossl_typ.ASN1_INTEGER)* X509_get0_serialNumber(const (libressl_d.openssl.ossl_typ.X509)* x);
int X509_set_issuer_name(libressl_d.openssl.ossl_typ.X509* x, libressl_d.openssl.ossl_typ.X509_NAME* name);
libressl_d.openssl.ossl_typ.X509_NAME* X509_get_issuer_name(const (libressl_d.openssl.ossl_typ.X509)* a);
int X509_set_subject_name(libressl_d.openssl.ossl_typ.X509* x, libressl_d.openssl.ossl_typ.X509_NAME* name);
libressl_d.openssl.ossl_typ.X509_NAME* X509_get_subject_name(const (libressl_d.openssl.ossl_typ.X509)* a);
int X509_set_notBefore(libressl_d.openssl.ossl_typ.X509* x, const (libressl_d.openssl.ossl_typ.ASN1_TIME)* tm);
int X509_set1_notBefore(libressl_d.openssl.ossl_typ.X509* x, const (libressl_d.openssl.ossl_typ.ASN1_TIME)* tm);
int X509_set_notAfter(libressl_d.openssl.ossl_typ.X509* x, const (libressl_d.openssl.ossl_typ.ASN1_TIME)* tm);
int X509_set1_notAfter(libressl_d.openssl.ossl_typ.X509* x, const (libressl_d.openssl.ossl_typ.ASN1_TIME)* tm);
const (libressl_d.openssl.ossl_typ.ASN1_TIME)* X509_get0_notBefore(const (libressl_d.openssl.ossl_typ.X509)* x);
libressl_d.openssl.ossl_typ.ASN1_TIME* X509_getm_notBefore(const (libressl_d.openssl.ossl_typ.X509)* x);
const (libressl_d.openssl.ossl_typ.ASN1_TIME)* X509_get0_notAfter(const (libressl_d.openssl.ossl_typ.X509)* x);
libressl_d.openssl.ossl_typ.ASN1_TIME* X509_getm_notAfter(const (libressl_d.openssl.ossl_typ.X509)* x);
int X509_set_pubkey(libressl_d.openssl.ossl_typ.X509* x, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
libressl_d.openssl.ossl_typ.EVP_PKEY* X509_get_pubkey(libressl_d.openssl.ossl_typ.X509* x);
libressl_d.openssl.ossl_typ.EVP_PKEY* X509_get0_pubkey(const (libressl_d.openssl.ossl_typ.X509)* x);
libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* X509_get0_pubkey_bitstr(const (libressl_d.openssl.ossl_typ.X509)* x);
int X509_certificate_type(const (libressl_d.openssl.ossl_typ.X509)* x, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pubkey);
int X509_get_signature_type(const (libressl_d.openssl.ossl_typ.X509)* x);

alias X509_get_notBefore = .X509_getm_notBefore;
alias X509_get_notAfter = .X509_getm_notAfter;

int X509_REQ_set_version(.X509_REQ* x, core.stdc.config.c_long version_);
core.stdc.config.c_long X509_REQ_get_version(const (.X509_REQ)* x);
int X509_REQ_set_subject_name(.X509_REQ* req, libressl_d.openssl.ossl_typ.X509_NAME* name);
libressl_d.openssl.ossl_typ.X509_NAME* X509_REQ_get_subject_name(const (.X509_REQ)* x);
int X509_REQ_set_pubkey(.X509_REQ* x, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
libressl_d.openssl.ossl_typ.EVP_PKEY* X509_REQ_get_pubkey(.X509_REQ* req);
int X509_REQ_extension_nid(int nid);
int* X509_REQ_get_extension_nids();
void X509_REQ_set_extension_nids(int* nids);
.stack_st_X509_EXTENSION* X509_REQ_get_extensions(.X509_REQ* req);
int X509_REQ_add_extensions_nid(.X509_REQ* req, .stack_st_X509_EXTENSION * exts, int nid);
int X509_REQ_add_extensions(.X509_REQ* req, .stack_st_X509_EXTENSION * exts);
int X509_REQ_get_attr_count(const (.X509_REQ)* req);
int X509_REQ_get_attr_by_NID(const (.X509_REQ)* req, int nid, int lastpos);
int X509_REQ_get_attr_by_OBJ(const (.X509_REQ)* req, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int lastpos);
.X509_ATTRIBUTE* X509_REQ_get_attr(const (.X509_REQ)* req, int loc);
.X509_ATTRIBUTE* X509_REQ_delete_attr(.X509_REQ* req, int loc);
int X509_REQ_add1_attr(.X509_REQ* req, .X509_ATTRIBUTE* attr);
int X509_REQ_add1_attr_by_OBJ(.X509_REQ* req, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int type, const (ubyte)* bytes, int len);
int X509_REQ_add1_attr_by_NID(.X509_REQ* req, int nid, int type, const (ubyte)* bytes, int len);
int X509_REQ_add1_attr_by_txt(.X509_REQ* req, const (char)* attrname, int type, const (ubyte)* bytes, int len);

int X509_CRL_set_version(libressl_d.openssl.ossl_typ.X509_CRL* x, core.stdc.config.c_long version_);
int X509_CRL_set_issuer_name(libressl_d.openssl.ossl_typ.X509_CRL* x, libressl_d.openssl.ossl_typ.X509_NAME* name);
int X509_CRL_set_lastUpdate(libressl_d.openssl.ossl_typ.X509_CRL* x, const (libressl_d.openssl.ossl_typ.ASN1_TIME)* tm);
int X509_CRL_set1_lastUpdate(libressl_d.openssl.ossl_typ.X509_CRL* x, const (libressl_d.openssl.ossl_typ.ASN1_TIME)* tm);
int X509_CRL_set_nextUpdate(libressl_d.openssl.ossl_typ.X509_CRL* x, const (libressl_d.openssl.ossl_typ.ASN1_TIME)* tm);
int X509_CRL_set1_nextUpdate(libressl_d.openssl.ossl_typ.X509_CRL* x, const (libressl_d.openssl.ossl_typ.ASN1_TIME)* tm);
int X509_CRL_sort(libressl_d.openssl.ossl_typ.X509_CRL* crl);

const (.stack_st_X509_EXTENSION)* X509_REVOKED_get0_extensions(const (libressl_d.openssl.ossl_typ.X509_REVOKED)* x);
const (libressl_d.openssl.ossl_typ.ASN1_TIME)* X509_REVOKED_get0_revocationDate(const (libressl_d.openssl.ossl_typ.X509_REVOKED)* x);
const (libressl_d.openssl.ossl_typ.ASN1_INTEGER)* X509_REVOKED_get0_serialNumber(const (libressl_d.openssl.ossl_typ.X509_REVOKED)* x);
int X509_REVOKED_set_revocationDate(libressl_d.openssl.ossl_typ.X509_REVOKED* r, libressl_d.openssl.ossl_typ.ASN1_TIME* tm);
int X509_REVOKED_set_serialNumber(libressl_d.openssl.ossl_typ.X509_REVOKED* x, libressl_d.openssl.ossl_typ.ASN1_INTEGER* serial);

int X509_REQ_check_private_key(.X509_REQ* x509, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);

int X509_check_private_key(const (libressl_d.openssl.ossl_typ.X509)* x509, const (libressl_d.openssl.ossl_typ.EVP_PKEY)* pkey);

int X509_issuer_and_serial_cmp(const (libressl_d.openssl.ossl_typ.X509)* a, const (libressl_d.openssl.ossl_typ.X509)* b);
core.stdc.config.c_ulong X509_issuer_and_serial_hash(libressl_d.openssl.ossl_typ.X509* a);

int X509_issuer_name_cmp(const (libressl_d.openssl.ossl_typ.X509)* a, const (libressl_d.openssl.ossl_typ.X509)* b);
core.stdc.config.c_ulong X509_issuer_name_hash(libressl_d.openssl.ossl_typ.X509* a);

int X509_subject_name_cmp(const (libressl_d.openssl.ossl_typ.X509)* a, const (libressl_d.openssl.ossl_typ.X509)* b);
core.stdc.config.c_ulong X509_subject_name_hash(libressl_d.openssl.ossl_typ.X509* x);

//#if !defined(OPENSSL_NO_MD5)
core.stdc.config.c_ulong X509_issuer_name_hash_old(libressl_d.openssl.ossl_typ.X509* a);
core.stdc.config.c_ulong X509_subject_name_hash_old(libressl_d.openssl.ossl_typ.X509* x);
//#endif

int X509_cmp(const (libressl_d.openssl.ossl_typ.X509)* a, const (libressl_d.openssl.ossl_typ.X509)* b);
int X509_NAME_cmp(const (libressl_d.openssl.ossl_typ.X509_NAME)* a, const (libressl_d.openssl.ossl_typ.X509_NAME)* b);
core.stdc.config.c_ulong X509_NAME_hash(libressl_d.openssl.ossl_typ.X509_NAME* x);
core.stdc.config.c_ulong X509_NAME_hash_old(libressl_d.openssl.ossl_typ.X509_NAME* x);

int X509_CRL_cmp(const (libressl_d.openssl.ossl_typ.X509_CRL)* a, const (libressl_d.openssl.ossl_typ.X509_CRL)* b);
int X509_CRL_match(const (libressl_d.openssl.ossl_typ.X509_CRL)* a, const (libressl_d.openssl.ossl_typ.X509_CRL)* b);
int X509_print_ex_fp(libressl_d.compat.stdio.FILE* bp, libressl_d.openssl.ossl_typ.X509* x, core.stdc.config.c_ulong nmflag, core.stdc.config.c_ulong cflag);
int X509_print_fp(libressl_d.compat.stdio.FILE* bp, libressl_d.openssl.ossl_typ.X509* x);
int X509_CRL_print_fp(libressl_d.compat.stdio.FILE* bp, libressl_d.openssl.ossl_typ.X509_CRL* x);
int X509_REQ_print_fp(libressl_d.compat.stdio.FILE* bp, .X509_REQ* req);
int X509_NAME_print_ex_fp(libressl_d.compat.stdio.FILE* fp, const (libressl_d.openssl.ossl_typ.X509_NAME)* nm, int indent, core.stdc.config.c_ulong flags);

//#if !defined(OPENSSL_NO_BIO)
int X509_NAME_print(libressl_d.openssl.bio.BIO* bp, const (libressl_d.openssl.ossl_typ.X509_NAME)* name, int obase);
int X509_NAME_print_ex(libressl_d.openssl.bio.BIO* out_, const (libressl_d.openssl.ossl_typ.X509_NAME)* nm, int indent, core.stdc.config.c_ulong flags);
int X509_print_ex(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.X509* x, core.stdc.config.c_ulong nmflag, core.stdc.config.c_ulong cflag);
int X509_print(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.X509* x);
int X509_ocspid_print(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.X509* x);
int X509_CERT_AUX_print(libressl_d.openssl.bio.BIO* bp, .X509_CERT_AUX* x, int indent);
int X509_CRL_print(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.X509_CRL* x);
int X509_REQ_print_ex(libressl_d.openssl.bio.BIO* bp, .X509_REQ* x, core.stdc.config.c_ulong nmflag, core.stdc.config.c_ulong cflag);
int X509_REQ_print(libressl_d.openssl.bio.BIO* bp, .X509_REQ* req);
//#endif

int X509_NAME_entry_count(const (libressl_d.openssl.ossl_typ.X509_NAME)* name);
int X509_NAME_get_text_by_NID(libressl_d.openssl.ossl_typ.X509_NAME* name, int nid, char* buf, int len);
int X509_NAME_get_text_by_OBJ(libressl_d.openssl.ossl_typ.X509_NAME* name, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, char* buf, int len);

/*
 * NOTE: you should be passsing -1, not 0 as lastpos.  The functions that use
 * lastpos, search after that position on.
 */
int X509_NAME_get_index_by_NID(const (libressl_d.openssl.ossl_typ.X509_NAME)* name, int nid, int lastpos);
int X509_NAME_get_index_by_OBJ(const (libressl_d.openssl.ossl_typ.X509_NAME)* name, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int lastpos);
.X509_NAME_ENTRY* X509_NAME_get_entry(const (libressl_d.openssl.ossl_typ.X509_NAME)* name, int loc);
.X509_NAME_ENTRY* X509_NAME_delete_entry(libressl_d.openssl.ossl_typ.X509_NAME* name, int loc);
int X509_NAME_add_entry(libressl_d.openssl.ossl_typ.X509_NAME* name, const (.X509_NAME_ENTRY)* ne, int loc, int set);
int X509_NAME_add_entry_by_OBJ(libressl_d.openssl.ossl_typ.X509_NAME* name, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int type, const (ubyte)* bytes, int len, int loc, int set);
int X509_NAME_add_entry_by_NID(libressl_d.openssl.ossl_typ.X509_NAME* name, int nid, int type, const (ubyte)* bytes, int len, int loc, int set);
.X509_NAME_ENTRY* X509_NAME_ENTRY_create_by_txt(.X509_NAME_ENTRY** ne, const (char)* field, int type, const (ubyte)* bytes, int len);
.X509_NAME_ENTRY* X509_NAME_ENTRY_create_by_NID(.X509_NAME_ENTRY** ne, int nid, int type, const (ubyte)* bytes, int len);
int X509_NAME_add_entry_by_txt(libressl_d.openssl.ossl_typ.X509_NAME* name, const (char)* field, int type, const (ubyte)* bytes, int len, int loc, int set);
.X509_NAME_ENTRY* X509_NAME_ENTRY_create_by_OBJ(.X509_NAME_ENTRY** ne, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int type, const (ubyte)* bytes, int len);
int X509_NAME_ENTRY_set_object(.X509_NAME_ENTRY* ne, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj);
int X509_NAME_ENTRY_set_data(.X509_NAME_ENTRY* ne, int type, const (ubyte)* bytes, int len);
libressl_d.openssl.asn1.ASN1_OBJECT* X509_NAME_ENTRY_get_object(const (.X509_NAME_ENTRY)* ne);
libressl_d.openssl.ossl_typ.ASN1_STRING* X509_NAME_ENTRY_get_data(const (.X509_NAME_ENTRY)* ne);
int X509_NAME_ENTRY_set(const (.X509_NAME_ENTRY)* ne);

int X509v3_get_ext_count(const (.stack_st_X509_EXTENSION)* x);
int X509v3_get_ext_by_NID(const (.stack_st_X509_EXTENSION)* x, int nid, int lastpos);
int X509v3_get_ext_by_OBJ(const (.stack_st_X509_EXTENSION)* x, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int lastpos);
int X509v3_get_ext_by_critical(const (.stack_st_X509_EXTENSION)* x, int crit, int lastpos);
.X509_EXTENSION* X509v3_get_ext(const (.stack_st_X509_EXTENSION)* x, int loc);
.X509_EXTENSION* X509v3_delete_ext(.stack_st_X509_EXTENSION * x, int loc);
.stack_st_X509_EXTENSION* X509v3_add_ext(.stack_st_X509_EXTENSION** x, .X509_EXTENSION* ex, int loc);

int X509_get_ext_count(const (libressl_d.openssl.ossl_typ.X509)* x);
int X509_get_ext_by_NID(const (libressl_d.openssl.ossl_typ.X509)* x, int nid, int lastpos);
int X509_get_ext_by_OBJ(const (libressl_d.openssl.ossl_typ.X509)* x, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int lastpos);
int X509_get_ext_by_critical(const (libressl_d.openssl.ossl_typ.X509)* x, int crit, int lastpos);
.X509_EXTENSION* X509_get_ext(const (libressl_d.openssl.ossl_typ.X509)* x, int loc);
.X509_EXTENSION* X509_delete_ext(libressl_d.openssl.ossl_typ.X509* x, int loc);
int X509_add_ext(libressl_d.openssl.ossl_typ.X509* x, .X509_EXTENSION* ex, int loc);
void* X509_get_ext_d2i(const (libressl_d.openssl.ossl_typ.X509)* x, int nid, int* crit, int* idx);
int X509_add1_ext_i2d(libressl_d.openssl.ossl_typ.X509* x, int nid, void* value, int crit, core.stdc.config.c_ulong flags);

int X509_CRL_get_ext_count(const (libressl_d.openssl.ossl_typ.X509_CRL)* x);
int X509_CRL_get_ext_by_NID(const (libressl_d.openssl.ossl_typ.X509_CRL)* x, int nid, int lastpos);
int X509_CRL_get_ext_by_OBJ(const (libressl_d.openssl.ossl_typ.X509_CRL)* x, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int lastpos);
int X509_CRL_get_ext_by_critical(const (libressl_d.openssl.ossl_typ.X509_CRL)* x, int crit, int lastpos);
.X509_EXTENSION* X509_CRL_get_ext(const (libressl_d.openssl.ossl_typ.X509_CRL)* x, int loc);
.X509_EXTENSION* X509_CRL_delete_ext(libressl_d.openssl.ossl_typ.X509_CRL* x, int loc);
int X509_CRL_add_ext(libressl_d.openssl.ossl_typ.X509_CRL* x, .X509_EXTENSION* ex, int loc);
void* X509_CRL_get_ext_d2i(const (libressl_d.openssl.ossl_typ.X509_CRL)* x, int nid, int* crit, int* idx);
int X509_CRL_add1_ext_i2d(libressl_d.openssl.ossl_typ.X509_CRL* x, int nid, void* value, int crit, core.stdc.config.c_ulong flags);

int X509_REVOKED_get_ext_count(const (libressl_d.openssl.ossl_typ.X509_REVOKED)* x);
int X509_REVOKED_get_ext_by_NID(const (libressl_d.openssl.ossl_typ.X509_REVOKED)* x, int nid, int lastpos);
int X509_REVOKED_get_ext_by_OBJ(const (libressl_d.openssl.ossl_typ.X509_REVOKED)* x, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int lastpos);
int X509_REVOKED_get_ext_by_critical(const (libressl_d.openssl.ossl_typ.X509_REVOKED)* x, int crit, int lastpos);
.X509_EXTENSION* X509_REVOKED_get_ext(const (libressl_d.openssl.ossl_typ.X509_REVOKED)* x, int loc);
.X509_EXTENSION* X509_REVOKED_delete_ext(libressl_d.openssl.ossl_typ.X509_REVOKED* x, int loc);
int X509_REVOKED_add_ext(libressl_d.openssl.ossl_typ.X509_REVOKED* x, .X509_EXTENSION* ex, int loc);
void* X509_REVOKED_get_ext_d2i(const (libressl_d.openssl.ossl_typ.X509_REVOKED)* x, int nid, int* crit, int* idx);
int X509_REVOKED_add1_ext_i2d(libressl_d.openssl.ossl_typ.X509_REVOKED* x, int nid, void* value, int crit, core.stdc.config.c_ulong flags);

.X509_EXTENSION* X509_EXTENSION_create_by_NID(.X509_EXTENSION** ex, int nid, int crit, libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* data);
.X509_EXTENSION* X509_EXTENSION_create_by_OBJ(.X509_EXTENSION** ex, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int crit, libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* data);
int X509_EXTENSION_set_object(.X509_EXTENSION* ex, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj);
int X509_EXTENSION_set_critical(.X509_EXTENSION* ex, int crit);
int X509_EXTENSION_set_data(.X509_EXTENSION* ex, libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* data);
libressl_d.openssl.asn1.ASN1_OBJECT* X509_EXTENSION_get_object(.X509_EXTENSION* ex);
libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* X509_EXTENSION_get_data(.X509_EXTENSION* ne);
int X509_EXTENSION_get_critical(const (.X509_EXTENSION)* ex);

int X509at_get_attr_count(const (.stack_st_X509_ATTRIBUTE)* x);
int X509at_get_attr_by_NID(const (.stack_st_X509_ATTRIBUTE)* x, int nid, int lastpos);
int X509at_get_attr_by_OBJ(const (.stack_st_X509_ATTRIBUTE)* sk, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int lastpos);
.X509_ATTRIBUTE* X509at_get_attr(const (.stack_st_X509_ATTRIBUTE)* x, int loc);
.X509_ATTRIBUTE* X509at_delete_attr(.stack_st_X509_ATTRIBUTE * x, int loc);
.stack_st_X509_ATTRIBUTE* X509at_add1_attr(.stack_st_X509_ATTRIBUTE** x, .X509_ATTRIBUTE* attr);
.stack_st_X509_ATTRIBUTE* X509at_add1_attr_by_OBJ(.stack_st_X509_ATTRIBUTE** x, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int type, const (ubyte)* bytes, int len);
.stack_st_X509_ATTRIBUTE* X509at_add1_attr_by_NID(.stack_st_X509_ATTRIBUTE** x, int nid, int type, const (ubyte)* bytes, int len);
.stack_st_X509_ATTRIBUTE* X509at_add1_attr_by_txt(.stack_st_X509_ATTRIBUTE** x, const (char)* attrname, int type, const (ubyte)* bytes, int len);
void* X509at_get0_data_by_OBJ(.stack_st_X509_ATTRIBUTE * x, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int lastpos, int type);
.X509_ATTRIBUTE* X509_ATTRIBUTE_create_by_NID(.X509_ATTRIBUTE** attr, int nid, int atrtype, const (void)* data, int len);
.X509_ATTRIBUTE* X509_ATTRIBUTE_create_by_OBJ(.X509_ATTRIBUTE** attr, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int atrtype, const (void)* data, int len);
.X509_ATTRIBUTE* X509_ATTRIBUTE_create_by_txt(.X509_ATTRIBUTE** attr, const (char)* atrname, int type, const (ubyte)* bytes, int len);
int X509_ATTRIBUTE_set1_object(.X509_ATTRIBUTE* attr, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj);
int X509_ATTRIBUTE_set1_data(.X509_ATTRIBUTE* attr, int attrtype, const (void)* data, int len);
void* X509_ATTRIBUTE_get0_data(.X509_ATTRIBUTE* attr, int idx, int atrtype, void* data);
int X509_ATTRIBUTE_count(const (.X509_ATTRIBUTE)* attr);
libressl_d.openssl.asn1.ASN1_OBJECT* X509_ATTRIBUTE_get0_object(.X509_ATTRIBUTE* attr);
libressl_d.openssl.asn1.ASN1_TYPE* X509_ATTRIBUTE_get0_type(.X509_ATTRIBUTE* attr, int idx);

int EVP_PKEY_get_attr_count(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* key);
int EVP_PKEY_get_attr_by_NID(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* key, int nid, int lastpos);
int EVP_PKEY_get_attr_by_OBJ(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* key, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int lastpos);
.X509_ATTRIBUTE* EVP_PKEY_get_attr(const (libressl_d.openssl.ossl_typ.EVP_PKEY)* key, int loc);
.X509_ATTRIBUTE* EVP_PKEY_delete_attr(libressl_d.openssl.ossl_typ.EVP_PKEY* key, int loc);
int EVP_PKEY_add1_attr(libressl_d.openssl.ossl_typ.EVP_PKEY* key, .X509_ATTRIBUTE* attr);
int EVP_PKEY_add1_attr_by_OBJ(libressl_d.openssl.ossl_typ.EVP_PKEY* key, const (libressl_d.openssl.asn1.ASN1_OBJECT)* obj, int type, const (ubyte)* bytes, int len);
int EVP_PKEY_add1_attr_by_NID(libressl_d.openssl.ossl_typ.EVP_PKEY* key, int nid, int type, const (ubyte)* bytes, int len);
int EVP_PKEY_add1_attr_by_txt(libressl_d.openssl.ossl_typ.EVP_PKEY* key, const (char)* attrname, int type, const (ubyte)* bytes, int len);

int X509_verify_cert(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);

/* lookup a cert from a X509 STACK */
libressl_d.openssl.ossl_typ.X509* X509_find_by_issuer_and_serial(.stack_st_X509* sk, libressl_d.openssl.ossl_typ.X509_NAME* name, libressl_d.openssl.ossl_typ.ASN1_INTEGER* serial);
libressl_d.openssl.ossl_typ.X509* X509_find_by_subject(.stack_st_X509* sk, libressl_d.openssl.ossl_typ.X509_NAME* name);

.PBEPARAM* PBEPARAM_new();
void PBEPARAM_free(.PBEPARAM* a);
.PBEPARAM* d2i_PBEPARAM(.PBEPARAM** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PBEPARAM(.PBEPARAM* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM PBEPARAM_it;
.PBE2PARAM* PBE2PARAM_new();
void PBE2PARAM_free(.PBE2PARAM* a);
.PBE2PARAM* d2i_PBE2PARAM(.PBE2PARAM** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PBE2PARAM(.PBE2PARAM* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM PBE2PARAM_it;
.PBKDF2PARAM* PBKDF2PARAM_new();
void PBKDF2PARAM_free(.PBKDF2PARAM* a);
.PBKDF2PARAM* d2i_PBKDF2PARAM(.PBKDF2PARAM** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PBKDF2PARAM(.PBKDF2PARAM* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM PBKDF2PARAM_it;

int PKCS5_pbe_set0_algor(libressl_d.openssl.ossl_typ.X509_ALGOR* algor, int alg, int iter, const (ubyte)* salt, int saltlen);

libressl_d.openssl.ossl_typ.X509_ALGOR* PKCS5_pbe_set(int alg, int iter, const (ubyte)* salt, int saltlen);
libressl_d.openssl.ossl_typ.X509_ALGOR* PKCS5_pbe2_set(const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher, int iter, ubyte* salt, int saltlen);
libressl_d.openssl.ossl_typ.X509_ALGOR* PKCS5_pbe2_set_iv(const (libressl_d.openssl.ossl_typ.EVP_CIPHER)* cipher, int iter, ubyte* salt, int saltlen, ubyte* aiv, int prf_nid);

libressl_d.openssl.ossl_typ.X509_ALGOR* PKCS5_pbkdf2_set(int iter, ubyte* salt, int saltlen, int prf_nid, int keylen);

/* PKCS#8 utilities */

libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* PKCS8_PRIV_KEY_INFO_new();
void PKCS8_PRIV_KEY_INFO_free(libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* a);
libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* d2i_PKCS8_PRIV_KEY_INFO(libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKCS8_PRIV_KEY_INFO(libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM PKCS8_PRIV_KEY_INFO_it;

libressl_d.openssl.ossl_typ.EVP_PKEY* EVP_PKCS82PKEY(const (libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO)* p8);
libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* EVP_PKEY2PKCS8(libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);

int PKCS8_pkey_set0(libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* priv, libressl_d.openssl.asn1.ASN1_OBJECT* aobj, int version_, int ptype, void* pval, ubyte* penc, int penclen);
int PKCS8_pkey_get0(const (libressl_d.openssl.asn1.ASN1_OBJECT)** ppkalg, const (ubyte)** pk, int* ppklen, const (libressl_d.openssl.ossl_typ.X509_ALGOR)** pa, const (libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO)* p8);

const (.stack_st_X509_ATTRIBUTE)* PKCS8_pkey_get0_attrs(const (libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO)* p8);
int PKCS8_pkey_add1_attr_by_NID(libressl_d.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* p8, int nid, int type, const (ubyte)* bytes, int len);

int X509_PUBKEY_set0_param(libressl_d.openssl.ossl_typ.X509_PUBKEY* pub, libressl_d.openssl.asn1.ASN1_OBJECT* aobj, int ptype, void* pval, ubyte* penc, int penclen);
int X509_PUBKEY_get0_param(libressl_d.openssl.asn1.ASN1_OBJECT** ppkalg, const (ubyte)** pk, int* ppklen, libressl_d.openssl.ossl_typ.X509_ALGOR** pa, libressl_d.openssl.ossl_typ.X509_PUBKEY* pub);

int X509_check_trust(libressl_d.openssl.ossl_typ.X509* x, int id, int flags);
int X509_TRUST_get_count();
.X509_TRUST* X509_TRUST_get0(int idx);
int X509_TRUST_get_by_id(int id);
int X509_TRUST_add(int id, int flags, int function(.X509_TRUST*, libressl_d.openssl.ossl_typ.X509*, int) ck, const (char)* name, int arg1, void* arg2);
void X509_TRUST_cleanup();
int X509_TRUST_get_flags(const (.X509_TRUST)* xp);
char* X509_TRUST_get0_name(const (.X509_TRUST)* xp);
int X509_TRUST_get_trust(const (.X509_TRUST)* xp);

int X509_up_ref(libressl_d.openssl.ossl_typ.X509* x);
.stack_st_X509* X509_chain_up_ref(.stack_st_X509 * chain);

/* BEGIN ERROR CODES */
/**
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_X509_strings();

/* Error codes for the X509 functions. */

/* Function codes. */
enum X509_F_ADD_CERT_DIR = 100;
enum X509_F_BY_FILE_CTRL = 101;
enum X509_F_CHECK_POLICY = 145;
enum X509_F_DIR_CTRL = 102;
enum X509_F_GET_CERT_BY_SUBJECT = 103;
enum X509_F_NETSCAPE_SPKI_B64_DECODE = 129;
enum X509_F_NETSCAPE_SPKI_B64_ENCODE = 130;
enum X509_F_X509AT_ADD1_ATTR = 135;
enum X509_F_X509V3_ADD_EXT = 104;
enum X509_F_X509_ATTRIBUTE_CREATE_BY_NID = 136;
enum X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ = 137;
enum X509_F_X509_ATTRIBUTE_CREATE_BY_TXT = 140;
enum X509_F_X509_ATTRIBUTE_GET0_DATA = 139;
enum X509_F_X509_ATTRIBUTE_SET1_DATA = 138;
enum X509_F_X509_CHECK_PRIVATE_KEY = 128;
enum X509_F_X509_CRL_PRINT_FP = 147;
enum X509_F_X509_EXTENSION_CREATE_BY_NID = 108;
enum X509_F_X509_EXTENSION_CREATE_BY_OBJ = 109;
enum X509_F_X509_GET_PUBKEY_PARAMETERS = 110;
enum X509_F_X509_LOAD_CERT_CRL_FILE = 132;
enum X509_F_X509_LOAD_CERT_FILE = 111;
enum X509_F_X509_LOAD_CRL_FILE = 112;
enum X509_F_X509_NAME_ADD_ENTRY = 113;
enum X509_F_X509_NAME_ENTRY_CREATE_BY_NID = 114;
enum X509_F_X509_NAME_ENTRY_CREATE_BY_TXT = 131;
enum X509_F_X509_NAME_ENTRY_SET_OBJECT = 115;
enum X509_F_X509_NAME_ONELINE = 116;
enum X509_F_X509_NAME_PRINT = 117;
enum X509_F_X509_PRINT_EX_FP = 118;
enum X509_F_X509_PUBKEY_GET = 119;
enum X509_F_X509_PUBKEY_SET = 120;
enum X509_F_X509_REQ_CHECK_PRIVATE_KEY = 144;
enum X509_F_X509_REQ_PRINT_EX = 121;
enum X509_F_X509_REQ_PRINT_FP = 122;
enum X509_F_X509_REQ_TO_X509 = 123;
enum X509_F_X509_STORE_ADD_CERT = 124;
enum X509_F_X509_STORE_ADD_CRL = 125;
enum X509_F_X509_STORE_CTX_GET1_ISSUER = 146;
enum X509_F_X509_STORE_CTX_INIT = 143;
enum X509_F_X509_STORE_CTX_NEW = 142;
enum X509_F_X509_STORE_CTX_PURPOSE_INHERIT = 134;
enum X509_F_X509_TO_X509_REQ = 126;
enum X509_F_X509_TRUST_ADD = 133;
enum X509_F_X509_TRUST_SET = 141;
enum X509_F_X509_VERIFY_CERT = 127;

/* Reason codes. */
enum X509_R_BAD_X509_FILETYPE = 100;
enum X509_R_BASE64_DECODE_ERROR = 118;
enum X509_R_CANT_CHECK_DH_KEY = 114;
enum X509_R_CERT_ALREADY_IN_HASH_TABLE = 101;
enum X509_R_ERR_ASN1_LIB = 102;
enum X509_R_INVALID_DIRECTORY = 113;
enum X509_R_INVALID_FIELD_NAME = 119;
enum X509_R_INVALID_TRUST = 123;
enum X509_R_KEY_TYPE_MISMATCH = 115;
enum X509_R_KEY_VALUES_MISMATCH = 116;
enum X509_R_LOADING_CERT_DIR = 103;
enum X509_R_LOADING_DEFAULTS = 104;
enum X509_R_METHOD_NOT_SUPPORTED = 124;
enum X509_R_NO_CERT_SET_FOR_US_TO_VERIFY = 105;
enum X509_R_PUBLIC_KEY_DECODE_ERROR = 125;
enum X509_R_PUBLIC_KEY_ENCODE_ERROR = 126;
enum X509_R_SHOULD_RETRY = 106;
enum X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN = 107;
enum X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY = 108;
enum X509_R_UNKNOWN_KEY_TYPE = 117;
enum X509_R_UNKNOWN_NID = 109;
enum X509_R_UNKNOWN_PURPOSE_ID = 121;
enum X509_R_UNKNOWN_TRUST_ID = 120;
enum X509_R_UNSUPPORTED_ALGORITHM = 111;
enum X509_R_WRONG_LOOKUP_TYPE = 112;
enum X509_R_WRONG_TYPE = 122;
