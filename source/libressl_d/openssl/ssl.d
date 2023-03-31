/* $OpenBSD: ssl.h,v 1.229 2022/09/11 17:39:46 tb Exp $ */
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
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */
module libressl_d.openssl.ssl;


private static import core.stdc.config;
private static import libressl_d.compat.stdio;
private static import libressl_d.openssl.asn1;
private static import libressl_d.openssl.crypto;
private static import libressl_d.openssl.ec;
private static import libressl_d.openssl.opensslfeatures;
private static import libressl_d.openssl.ossl_typ;
private static import libressl_d.openssl.stack;
private static import libressl_d.openssl.x509;
public import core.stdc.stdint;
public import libressl_d.openssl.bio;
public import libressl_d.openssl.dtls1;
public import libressl_d.openssl.hmac;
public import libressl_d.openssl.opensslconf;
public import libressl_d.openssl.pem;
public import libressl_d.openssl.safestack;
public import libressl_d.openssl.srtp;
public import libressl_d.openssl.ssl23;
public import libressl_d.openssl.ssl2;
public import libressl_d.openssl.ssl3;
public import libressl_d.openssl.tls1;

version (LIBRESSL_HAS_QUIC) {
	version = LIBRESSL_HAS_QUIC_OR_LIBRESSL_INTERNAL;
} else version (LIBRESSL_INTERNAL) {
	version = LIBRESSL_HAS_QUIC_OR_LIBRESSL_INTERNAL;
}

version (OPENSSL_NO_DEPRECATED) {
	private struct stack_st_X509_NAME;
	private struct stack_st_X509;
} else {
	public import libressl_d.openssl.buffer;
	public import libressl_d.openssl.crypto;
	public import libressl_d.openssl.lhash;

	version (OPENSSL_NO_X509) {
		private struct stack_st_X509_NAME;
		private struct stack_st_X509;
	} else {
		public import libressl_d.openssl.x509;

		private alias stack_st_X509_NAME = libressl_d.openssl.x509.stack_st_X509_NAME;
		private alias stack_st_X509 = libressl_d.openssl.x509.stack_st_X509;
	}
}

//public import libressl_d.openssl.dtls1; /* Datagram TLS */
//public import libressl_d.openssl.srtp; /* Support for the use_srtp extension */
//public import libressl_d.openssl.tls1; /* This is mostly sslv3 with a few tweaks */

extern (C):
nothrow @nogc:

/* SSLeay version number for ASN.1 encoding of the session information */
/*
 * Version 0 - initial version
 * Version 1 - added the optional peer certificate
 */
enum SSL_SESSION_ASN1_VERSION = 0x0001;

/* text strings for the ciphers */
enum SSL_TXT_NULL_WITH_MD5 = libressl_d.openssl.ssl2.SSL2_TXT_NULL_WITH_MD5;
enum SSL_TXT_RC4_128_WITH_MD5 = libressl_d.openssl.ssl2.SSL2_TXT_RC4_128_WITH_MD5;
enum SSL_TXT_RC4_128_EXPORT40_WITH_MD5 = libressl_d.openssl.ssl2.SSL2_TXT_RC4_128_EXPORT40_WITH_MD5;
enum SSL_TXT_RC2_128_CBC_WITH_MD5 = libressl_d.openssl.ssl2.SSL2_TXT_RC2_128_CBC_WITH_MD5;
enum SSL_TXT_RC2_128_CBC_EXPORT40_WITH_MD5 = libressl_d.openssl.ssl2.SSL2_TXT_RC2_128_CBC_EXPORT40_WITH_MD5;
enum SSL_TXT_IDEA_128_CBC_WITH_MD5 = libressl_d.openssl.ssl2.SSL2_TXT_IDEA_128_CBC_WITH_MD5;
enum SSL_TXT_DES_64_CBC_WITH_MD5 = libressl_d.openssl.ssl2.SSL2_TXT_DES_64_CBC_WITH_MD5;
enum SSL_TXT_DES_64_CBC_WITH_SHA = libressl_d.openssl.ssl2.SSL2_TXT_DES_64_CBC_WITH_SHA;
enum SSL_TXT_DES_192_EDE3_CBC_WITH_MD5 = libressl_d.openssl.ssl2.SSL2_TXT_DES_192_EDE3_CBC_WITH_MD5;
enum SSL_TXT_DES_192_EDE3_CBC_WITH_SHA = libressl_d.openssl.ssl2.SSL2_TXT_DES_192_EDE3_CBC_WITH_SHA;

/*
 * VRS Additional Kerberos5 entries
 */
enum SSL_TXT_KRB5_DES_64_CBC_SHA = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_DES_64_CBC_SHA;
enum SSL_TXT_KRB5_DES_192_CBC3_SHA = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_DES_192_CBC3_SHA;
enum SSL_TXT_KRB5_RC4_128_SHA = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_RC4_128_SHA;
enum SSL_TXT_KRB5_IDEA_128_CBC_SHA = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_IDEA_128_CBC_SHA;
enum SSL_TXT_KRB5_DES_64_CBC_MD5 = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_DES_64_CBC_MD5;
enum SSL_TXT_KRB5_DES_192_CBC3_MD5 = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_DES_192_CBC3_MD5;
enum SSL_TXT_KRB5_RC4_128_MD5 = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_RC4_128_MD5;
enum SSL_TXT_KRB5_IDEA_128_CBC_MD5 = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_IDEA_128_CBC_MD5;

enum SSL_TXT_KRB5_DES_40_CBC_SHA = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_DES_40_CBC_SHA;
enum SSL_TXT_KRB5_RC2_40_CBC_SHA = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_RC2_40_CBC_SHA;
enum SSL_TXT_KRB5_RC4_40_SHA = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_RC4_40_SHA;
enum SSL_TXT_KRB5_DES_40_CBC_MD5 = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_DES_40_CBC_MD5;
enum SSL_TXT_KRB5_RC2_40_CBC_MD5 = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_RC2_40_CBC_MD5;
enum SSL_TXT_KRB5_RC4_40_MD5 = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_RC4_40_MD5;

//enum SSL_TXT_KRB5_DES_40_CBC_SHA = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_DES_40_CBC_SHA;
//enum SSL_TXT_KRB5_DES_40_CBC_MD5 = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_DES_40_CBC_MD5;
//enum SSL_TXT_KRB5_DES_64_CBC_SHA = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_DES_64_CBC_SHA;
//enum SSL_TXT_KRB5_DES_64_CBC_MD5 = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_DES_64_CBC_MD5;
//enum SSL_TXT_KRB5_DES_192_CBC3_SHA = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_DES_192_CBC3_SHA;
//enum SSL_TXT_KRB5_DES_192_CBC3_MD5 = libressl_d.openssl.ssl3.SSL3_TXT_KRB5_DES_192_CBC3_MD5;
enum SSL_MAX_KRB5_PRINCIPAL_LENGTH = 256;

enum SSL_MAX_SSL_SESSION_ID_LENGTH = 32;
enum SSL_MAX_SID_CTX_LENGTH = 32;

enum SSL_MIN_RSA_MODULUS_LENGTH_IN_BYTES = 512 / 8;
enum SSL_MAX_KEY_ARG_LENGTH = 8;
enum SSL_MAX_MASTER_KEY_LENGTH = 48;

/* These are used to specify which ciphers to use and not to use */

enum SSL_TXT_LOW = "LOW";
enum SSL_TXT_MEDIUM = "MEDIUM";
enum SSL_TXT_HIGH = "HIGH";

/**
 * unused!
 */
enum SSL_TXT_kFZA = "kFZA";

///Ditto
enum SSL_TXT_aFZA = "aFZA";

///Ditto
enum SSL_TXT_eFZA = "eFZA";

///Ditto
enum SSL_TXT_FZA = "FZA";

enum SSL_TXT_aNULL = "aNULL";
enum SSL_TXT_eNULL = "eNULL";
enum SSL_TXT_NULL = "null";

enum SSL_TXT_kRSA = "kRSA";

/**
 * no such ciphersuites supported!
 */
enum SSL_TXT_kDHr = "kDHr";

///Ditto
enum SSL_TXT_kDHd = "kDHd";

///Ditto
enum SSL_TXT_kDH = "kDH";

enum SSL_TXT_kEDH = "kEDH";
enum SSL_TXT_kKRB5 = "kKRB5";
enum SSL_TXT_kECDHr = "kECDHr";
enum SSL_TXT_kECDHe = "kECDHe";
enum SSL_TXT_kECDH = "kECDH";
enum SSL_TXT_kEECDH = "kEECDH";
enum SSL_TXT_kPSK = "kPSK";
enum SSL_TXT_kGOST = "kGOST";
enum SSL_TXT_kSRP = "kSRP";

enum SSL_TXT_aRSA = "aRSA";
enum SSL_TXT_aDSS = "aDSS";

/**
 * no such ciphersuites supported!
 */
enum SSL_TXT_aDH = "aDH";

enum SSL_TXT_aECDH = "aECDH";
enum SSL_TXT_aKRB5 = "aKRB5";
enum SSL_TXT_aECDSA = "aECDSA";
enum SSL_TXT_aPSK = "aPSK";
enum SSL_TXT_aGOST94 = "aGOST94";
enum SSL_TXT_aGOST01 = "aGOST01";
enum SSL_TXT_aGOST = "aGOST";

enum SSL_TXT_DSS = "DSS";
enum SSL_TXT_DH = "DH";

/**
 * same as "kDHE:-ADH"
 */
enum SSL_TXT_DHE = "DHE";

/**
 * previous name for DHE
 */
enum SSL_TXT_EDH = "EDH";

enum SSL_TXT_ADH = "ADH";
enum SSL_TXT_RSA = "RSA";
enum SSL_TXT_ECDH = "ECDH";

/**
 * same as "kECDHE:-AECDH"
 */
enum SSL_TXT_ECDHE = "ECDHE";

/**
 * previous name for ECDHE
 */
enum SSL_TXT_EECDH = "EECDH";

enum SSL_TXT_AECDH = "AECDH";
enum SSL_TXT_ECDSA = "ECDSA";
enum SSL_TXT_KRB5 = "KRB5";
enum SSL_TXT_PSK = "PSK";
enum SSL_TXT_SRP = "SRP";

enum SSL_TXT_DES = "DES";
enum SSL_TXT_3DES = "3DES";
enum SSL_TXT_RC4 = "RC4";
enum SSL_TXT_RC2 = "RC2";
enum SSL_TXT_IDEA = "IDEA";
enum SSL_TXT_SEED = "SEED";
enum SSL_TXT_AES128 = "AES128";
enum SSL_TXT_AES256 = "AES256";
enum SSL_TXT_AES = "AES";
enum SSL_TXT_AES_GCM = "AESGCM";
enum SSL_TXT_CAMELLIA128 = "CAMELLIA128";
enum SSL_TXT_CAMELLIA256 = "CAMELLIA256";
enum SSL_TXT_CAMELLIA = "CAMELLIA";
enum SSL_TXT_CHACHA20 = "CHACHA20";

enum SSL_TXT_AEAD = "AEAD";
enum SSL_TXT_MD5 = "MD5";
enum SSL_TXT_SHA1 = "SHA1";

/**
 * same as "SHA1"
 */
enum SSL_TXT_SHA = "SHA";

enum SSL_TXT_GOST94 = "GOST94";
enum SSL_TXT_GOST89MAC = "GOST89MAC";
enum SSL_TXT_SHA256 = "SHA256";
enum SSL_TXT_SHA384 = "SHA384";
enum SSL_TXT_STREEBOG256 = "STREEBOG256";
enum SSL_TXT_STREEBOG512 = "STREEBOG512";

enum SSL_TXT_DTLS1 = "DTLSv1";
enum SSL_TXT_DTLS1_2 = "DTLSv1.2";
enum SSL_TXT_SSLV2 = "SSLv2";
enum SSL_TXT_SSLV3 = "SSLv3";
enum SSL_TXT_TLSV1 = "TLSv1";
enum SSL_TXT_TLSV1_1 = "TLSv1.1";
enum SSL_TXT_TLSV1_2 = "TLSv1.2";

static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	enum SSL_TXT_TLSV1_3 = "TLSv1.3";
}

enum SSL_TXT_EXP = "EXP";
enum SSL_TXT_EXPORT = "EXPORT";

enum SSL_TXT_ALL = "ALL";

/*
 * COMPLEMENTOF* definitions. These identifiers are used to (de-select)
 * ciphers normally not being used.
 * Example: "RC4" will activate all ciphers using RC4 including ciphers
 * without authentication, which would normally disabled by DEFAULT (due
 * the "!ADH" being part of default). Therefore "RC4:!COMPLEMENTOFDEFAULT"
 * will make sure that it is also disabled in the specific selection.
 * COMPLEMENTOF* identifiers are portable between version, as adjustments
 * to the default cipher setup will also be included here.
 *
 * COMPLEMENTOFDEFAULT does not experience the same special treatment that
 * DEFAULT gets, as only selection is being done and no sorting as needed
 * for DEFAULT.
 */
enum SSL_TXT_CMPALL = "COMPLEMENTOFALL";
enum SSL_TXT_CMPDEF = "COMPLEMENTOFDEFAULT";

/*
 * The following cipher list is used by default.
 * It also is substituted when an application-defined cipher list string
 * starts with 'DEFAULT'.
 */
enum SSL_DEFAULT_CIPHER_LIST = "ALL:!aNULL:!eNULL:!SSLv2";
/*
 * As of OpenSSL 1.0.0, ssl_create_cipher_list() in ssl/ssl_ciph.c always
 * starts with a reasonable order, and all we have to do for DEFAULT is
 * throwing out anonymous and unencrypted ciphersuites!
 * (The latter are not actually enabled by ALL, but "ALL:RSA" would enable
 * some of them.)
 */

/* Used in SSL_set_shutdown()/SSL_get_shutdown(); */
enum SSL_SENT_SHUTDOWN = 1;
enum SSL_RECEIVED_SHUTDOWN = 2;

enum SSL_FILETYPE_ASN1 = libressl_d.openssl.x509.X509_FILETYPE_ASN1;
enum SSL_FILETYPE_PEM = libressl_d.openssl.x509.X509_FILETYPE_PEM;

/*
 * This is needed to stop compilers complaining about the
 * 'struct ssl_st *' function parameters used to prototype callbacks
 * in SSL_CTX.
 */
alias ssl_crock_st = libressl_d.openssl.ossl_typ.ssl_st*;

version (all) {
	struct ssl_method_st;
	struct ssl_cipher_st;
	struct ssl_session_st;
}

alias SSL_METHOD = .ssl_method_st;
alias SSL_CIPHER = .ssl_cipher_st;
alias SSL_SESSION = .ssl_session_st;

//DECLARE_STACK_OF(SSL_CIPHER)
struct stack_st_SSL_CIPHER
{
	libressl_d.openssl.stack._STACK stack;
}

/**
 * SRTP protection profiles for use with the use_srtp extension (RFC 5764)
 */
struct srtp_protection_profile_st
{
	const (char)* name;
	core.stdc.config.c_ulong id;
}

alias SRTP_PROTECTION_PROFILE = .srtp_protection_profile_st;

//DECLARE_STACK_OF(SRTP_PROTECTION_PROFILE)
struct stack_st_SRTP_PROTECTION_PROFILE
{
	libressl_d.openssl.stack._STACK stack;
}

alias tls_session_ticket_ext_cb_fn = extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.SSL* s, const (ubyte)* data, int len, void* arg);
alias tls_session_secret_cb_fn = extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.SSL* s, void* secret, int* secret_len, .stack_st_SSL_CIPHER * peer_ciphers, .SSL_CIPHER** cipher, void* arg);

/**
 * Allow initial connection to servers that don't support RI
 */
enum SSL_OP_LEGACY_SERVER_CONNECT = 0x00000004L;

/**
 * Disable SSL 3.0/TLS 1.0 CBC vulnerability workaround that was added
 * in OpenSSL 0.9.6d.  Usually (depending on the application protocol)
 * the workaround is not needed.
 * Unfortunately some broken SSL/TLS implementations cannot handle it
 * at all, which is why it was previously included in SSL_OP_ALL.
 * Now it's not.
 */
enum SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = 0x00000800L;

/**
 * DTLS options
 */
enum SSL_OP_NO_QUERY_MTU = 0x00001000L;

/**
 * Turn on Cookie Exchange (on relevant for servers)
 */
enum SSL_OP_COOKIE_EXCHANGE = 0x00002000L;

/**
 * Don't use RFC4507 ticket extension
 */
enum SSL_OP_NO_TICKET = 0x00004000L;

/**
 * As server, disallow session resumption on renegotiation
 */
enum SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x00010000L;

/**
 * Disallow client initiated renegotiation.
 */
enum SSL_OP_NO_CLIENT_RENEGOTIATION = 0x00020000L;

/**
 * If set, always create a new key when using tmp_dh parameters
 */
enum SSL_OP_SINGLE_DH_USE = 0x00100000L;

/**
 * Set on servers to choose the cipher according to the server's
 * preferences
 */
enum SSL_OP_CIPHER_SERVER_PREFERENCE = 0x00400000L;

enum SSL_OP_NO_TLSv1 = 0x04000000L;
enum SSL_OP_NO_TLSv1_2 = 0x08000000L;
enum SSL_OP_NO_TLSv1_1 = 0x10000000L;

static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	enum SSL_OP_NO_TLSv1_3 = 0x20000000L;
}

enum SSL_OP_NO_DTLSv1 = 0x40000000L;
enum SSL_OP_NO_DTLSv1_2 = 0x80000000L;

/**
 * SSL_OP_ALL: various bug workarounds that should be rather harmless.
 */
enum SSL_OP_ALL = .SSL_OP_LEGACY_SERVER_CONNECT;

/* Obsolete flags kept for compatibility. No sane code should use them. */
enum SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION = 0x00;
enum SSL_OP_CISCO_ANYCONNECT = 0x00;
enum SSL_OP_CRYPTOPRO_TLSEXT_BUG = 0x00;
enum SSL_OP_EPHEMERAL_RSA = 0x00;
enum SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER = 0x00;
enum SSL_OP_MICROSOFT_SESS_ID_BUG = 0x00;
enum SSL_OP_MSIE_SSLV2_RSA_PADDING = 0x00;
enum SSL_OP_NETSCAPE_CA_DN_BUG = 0x00;
enum SSL_OP_NETSCAPE_CHALLENGE_BUG = 0x00;
enum SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG = 0x00;
enum SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG = 0x00;
enum SSL_OP_NO_COMPRESSION = 0x00;
enum SSL_OP_NO_SSLv2 = 0x00;
enum SSL_OP_NO_SSLv3 = 0x00;
enum SSL_OP_PKCS1_CHECK_1 = 0x00;
enum SSL_OP_PKCS1_CHECK_2 = 0x00;
enum SSL_OP_SAFARI_ECDHE_ECDSA_BUG = 0x00;
enum SSL_OP_SINGLE_ECDH_USE = 0x00;
enum SSL_OP_SSLEAY_080_CLIENT_DH_BUG = 0x00;
enum SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG = 0x00;
enum SSL_OP_TLSEXT_PADDING = 0x00;
enum SSL_OP_TLS_BLOCK_PADDING_BUG = 0x00;
enum SSL_OP_TLS_D5_BUG = 0x00;
enum SSL_OP_TLS_ROLLBACK_BUG = 0x00;

/**
 * Allow SSL_write(..., n) to return r with 0 < r < n (i.e. report success
 * when just a single record has been written):
 */
enum SSL_MODE_ENABLE_PARTIAL_WRITE = 0x00000001L;

/**
 * Make it possible to retry SSL_write() with changed buffer location
 * (buffer contents must stay the same!); this is not the default to avoid
 * the misconception that non-blocking SSL_write() behaves like
 * non-blocking write():
 */
enum SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 0x00000002L;

/**
 * Never bother the application with retries if the transport
 * is blocking:
 */
enum SSL_MODE_AUTO_RETRY = 0x00000004L;

/**
 * Don't attempt to automatically build certificate chain
 */
enum SSL_MODE_NO_AUTO_CHAIN = 0x00000008L;

/**
 * Save RAM by releasing read and write buffers when they're empty. (SSL3 and
 * TLS only.)  "Released" buffers are put onto a free-list in the context
 * or just freed (depending on the context's setting for freelist_max_len).
 */
enum SSL_MODE_RELEASE_BUFFERS = 0x00000010L;

/*
 * Note: SSL[_CTX]_set_{options,mode} use |= op on the previous value,
 * they cannot be used to clear bits.
 */

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_options(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.config.c_long op)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_OPTIONS, op, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_clear_options(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.config.c_long op)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_CLEAR_OPTIONS, op, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_get_options(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_OPTIONS, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_options(libressl_d.openssl.ossl_typ.SSL* ssl, core.stdc.config.c_long op)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_OPTIONS, op, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_clear_options(libressl_d.openssl.ossl_typ.SSL* ssl, core.stdc.config.c_long op)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_CLEAR_OPTIONS, op, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_get_options(libressl_d.openssl.ossl_typ.SSL* ssl)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_OPTIONS, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_mode(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.config.c_long op)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_MODE, op, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_clear_mode(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.config.c_long op)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_CLEAR_MODE, op, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_get_mode(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_MODE, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_clear_mode(libressl_d.openssl.ossl_typ.SSL* ssl, core.stdc.config.c_long op)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_CLEAR_MODE, op, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_mode(libressl_d.openssl.ossl_typ.SSL* ssl, core.stdc.config.c_long op)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_MODE, op, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_get_mode(libressl_d.openssl.ossl_typ.SSL* ssl)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_MODE, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_mtu(libressl_d.openssl.ossl_typ.SSL* ssl, core.stdc.config.c_long mtu)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_SET_MTU, mtu, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_get_secure_renegotiation_support(libressl_d.openssl.ossl_typ.SSL* ssl)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_GET_RI_SUPPORT, 0, null);
	}

private alias SSL_CTX_set_msg_callback_func = /* Temporary type */ extern (C) nothrow @nogc void function(int write_p, int version_, int content_type, const (void)* buf, size_t len, libressl_d.openssl.ossl_typ.SSL* ssl, void* arg);
void SSL_CTX_set_msg_callback(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .SSL_CTX_set_msg_callback_func cb);

private alias SSL_set_msg_callback_func = /* Temporary type */ extern (C) nothrow @nogc void function(int write_p, int version_, int content_type, const (void)* buf, size_t len, libressl_d.openssl.ossl_typ.SSL* ssl, void* arg);
void SSL_set_msg_callback(libressl_d.openssl.ossl_typ.SSL* ssl, .SSL_set_msg_callback_func cb);

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_msg_callback_arg(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, void* arg)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SET_MSG_CALLBACK_ARG, 0, arg);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_msg_callback_arg(libressl_d.openssl.ossl_typ.SSL* ssl, void* arg)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_SET_MSG_CALLBACK_ARG, 0, arg);
	}

alias SSL_CTX_keylog_cb_func = extern (C) nothrow @nogc void function(const (libressl_d.openssl.ossl_typ.SSL)* ssl, const (char)* line);
void SSL_CTX_set_keylog_callback(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .SSL_CTX_keylog_cb_func cb);
.SSL_CTX_keylog_cb_func SSL_CTX_get_keylog_callback(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx);
int SSL_set_num_tickets(libressl_d.openssl.ossl_typ.SSL* s, size_t num_tickets);
size_t SSL_get_num_tickets(const (libressl_d.openssl.ossl_typ.SSL)* s);
int SSL_CTX_set_num_tickets(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, size_t num_tickets);
size_t SSL_CTX_get_num_tickets(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx);

.stack_st_X509* SSL_get0_verified_chain(const (libressl_d.openssl.ossl_typ.SSL)* s);

version (LIBRESSL_INTERNAL) {
} else {
	struct ssl_aead_ctx_st;
	alias SSL_AEAD_CTX = .ssl_aead_ctx_st;
}

/**
 * 100k max cert list :-\)
 */
enum SSL_MAX_CERT_LIST_DEFAULT = 1024 * 100;

enum SSL_SESSION_CACHE_MAX_SIZE_DEFAULT = 1024 * 20;

/**
 * This callback type is used inside SSL_CTX, SSL, and in the functions that set
 * them. It is used to override the generation of SSL/TLS session IDs in a
 * server. Return value should be zero on an error, non-zero to proceed. Also,
 * callbacks should themselves check if the id they generate is unique otherwise
 * the SSL handshake will fail with an error - callbacks can do this using the
 * 'ssl' value they're passed by;
 *      SSL_has_matching_session_id(ssl, id, *id_len)
 * The length value passed in is set at the maximum size the session ID can be.
 * In SSLv2 this is 16 bytes, whereas SSLv3/TLSv1 it is 32 bytes. The callback
 * can alter this length to be less if desired, but under SSLv2 session IDs are
 * supposed to be fixed at 16 bytes so the id will be padded after the callback
 * returns in this case. It is also an error for the callback to set the size to
 * zero.
 */
alias GEN_SESSION_CB = extern (C) nothrow @nogc int function(const (libressl_d.openssl.ossl_typ.SSL)* ssl, ubyte* id, uint* id_len);

struct ssl_comp_st;
alias SSL_COMP = .ssl_comp_st;

version (LIBRESSL_INTERNAL) {
	//DECLARE_STACK_OF(SSL_COMP)
	struct stack_st_SSL_COMP
	{
		libressl_d.openssl.stack._STACK stack;
	}

	struct lhash_st_SSL_SESSION
	{
		int dummy;
	}
} else {
	struct lhash_st_SSL_SESSION;
}

enum SSL_SESS_CACHE_OFF = 0x0000;
enum SSL_SESS_CACHE_CLIENT = 0x0001;
enum SSL_SESS_CACHE_SERVER = 0x0002;
enum SSL_SESS_CACHE_BOTH = .SSL_SESS_CACHE_CLIENT | .SSL_SESS_CACHE_SERVER;
enum SSL_SESS_CACHE_NO_AUTO_CLEAR = 0x0080;
/* enough comments already ... see SSL_CTX_set_session_cache_mode(3) */
enum SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 0x0100;
enum SSL_SESS_CACHE_NO_INTERNAL_STORE = 0x0200;
enum SSL_SESS_CACHE_NO_INTERNAL = .SSL_SESS_CACHE_NO_INTERNAL_LOOKUP | .SSL_SESS_CACHE_NO_INTERNAL_STORE;

.lhash_st_SSL_SESSION* SSL_CTX_sessions(libressl_d.openssl.ossl_typ.SSL_CTX* ctx);

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_sess_number(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SESS_NUMBER, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_sess_connect(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SESS_CONNECT, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_sess_connect_good(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SESS_CONNECT_GOOD, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_sess_connect_renegotiate(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SESS_CONNECT_RENEGOTIATE, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_sess_accept(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SESS_ACCEPT, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_sess_accept_renegotiate(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SESS_ACCEPT_RENEGOTIATE, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_sess_accept_good(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SESS_ACCEPT_GOOD, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_sess_hits(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SESS_HIT, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_sess_cb_hits(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SESS_CB_HIT, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_sess_misses(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SESS_MISSES, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_sess_timeouts(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SESS_TIMEOUTS, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_sess_cache_full(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SESS_CACHE_FULL, 0, null);
	}

private alias SSL_CTX_sess_set_new_cb_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.ssl_st* ssl, .SSL_SESSION* sess);
void SSL_CTX_sess_set_new_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .SSL_CTX_sess_set_new_cb_func new_session_cb);
//int (*SSL_CTX_sess_get_new_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ctx))(libressl_d.openssl.ossl_typ.ssl_st* ssl, .SSL_SESSION* sess);

private alias SSL_CTX_sess_set_remove_cb_func = /* Temporary type */ extern (C) nothrow @nogc void function(libressl_d.openssl.ossl_typ.ssl_ctx_st* ctx, .SSL_SESSION* sess);
void SSL_CTX_sess_set_remove_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .SSL_CTX_sess_set_remove_cb_func remove_session_cb);
//void (*SSL_CTX_sess_get_remove_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ctx))(libressl_d.openssl.ossl_typ.ssl_ctx_st* ctx, .SSL_SESSION* sess);

private alias SSL_CTX_sess_set_get_cb_func = /* Temporary type */ extern (C) nothrow @nogc .SSL_SESSION* function(libressl_d.openssl.ossl_typ.ssl_st* ssl, const (ubyte)* data, int len, int* copy);
void SSL_CTX_sess_set_get_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .SSL_CTX_sess_set_get_cb_func get_session_cb);
//.SSL_SESSION* (*SSL_CTX_sess_get_get_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ctx))(libressl_d.openssl.ossl_typ.ssl_st* ssl, const (ubyte)* data, int len, int* copy);

private alias SSL_CTX_set_info_callback_func = /* Temporary type */ extern (C) nothrow @nogc void function(const (libressl_d.openssl.ossl_typ.SSL)* ssl, int type, int val);
void SSL_CTX_set_info_callback(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .SSL_CTX_set_info_callback_func cb);
//void (*SSL_CTX_get_info_callback(libressl_d.openssl.ossl_typ.SSL_CTX* ctx))(const (libressl_d.openssl.ossl_typ.SSL)* ssl, int type, int val);

private alias SSL_CTX_set_client_cert_cb_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.SSL* ssl, libressl_d.openssl.ossl_typ.X509** x509, libressl_d.openssl.ossl_typ.EVP_PKEY** pkey);
void SSL_CTX_set_client_cert_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .SSL_CTX_set_client_cert_cb_func client_cert_cb);
//int (*SSL_CTX_get_client_cert_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ctx))(libressl_d.openssl.ossl_typ.SSL* ssl, libressl_d.openssl.ossl_typ.X509** x509, libressl_d.openssl.ossl_typ.EVP_PKEY** pkey);

version (OPENSSL_NO_ENGINE) {
} else {
	int SSL_CTX_set_client_cert_engine(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, libressl_d.openssl.ossl_typ.ENGINE* e);
}


private alias SSL_CTX_set_cookie_generate_cb_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.SSL* ssl, ubyte* cookie, uint* cookie_len);
void SSL_CTX_set_cookie_generate_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .SSL_CTX_set_cookie_generate_cb_func app_gen_cookie_cb);

private alias SSL_CTX_set_cookie_verify_cb_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.SSL* ssl, const (ubyte)* cookie, uint cookie_len);
void SSL_CTX_set_cookie_verify_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .SSL_CTX_set_cookie_verify_cb_func app_verify_cookie_cb);

private alias SSL_CTX_set_next_protos_advertised_cb_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.SSL* ssl, const (ubyte)** out_, uint* outlen, void* arg);
void SSL_CTX_set_next_protos_advertised_cb(libressl_d.openssl.ossl_typ.SSL_CTX* s, .SSL_CTX_set_next_protos_advertised_cb_func cb, void* arg);

private alias SSL_CTX_set_next_proto_select_cb_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.SSL* ssl, ubyte** out_, ubyte* outlen, const (ubyte)* in_, uint inlen, void* arg);
void SSL_CTX_set_next_proto_select_cb(libressl_d.openssl.ossl_typ.SSL_CTX* s, .SSL_CTX_set_next_proto_select_cb_func cb, void* arg);

int SSL_select_next_proto(ubyte** out_, ubyte* outlen, const (ubyte)* in_, uint inlen, const (ubyte)* client, uint client_len);
void SSL_get0_next_proto_negotiated(const (libressl_d.openssl.ossl_typ.SSL)* s, const (ubyte)** data, uint* len);

enum OPENSSL_NPN_UNSUPPORTED = 0;
enum OPENSSL_NPN_NEGOTIATED = 1;
enum OPENSSL_NPN_NO_OVERLAP = 2;

int SSL_CTX_set_alpn_protos(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, const (ubyte)* protos, uint protos_len);
int SSL_set_alpn_protos(libressl_d.openssl.ossl_typ.SSL* ssl, const (ubyte)* protos, uint protos_len);

private alias SSL_CTX_set_alpn_select_cb_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.SSL* ssl, const (ubyte)** out_, ubyte* outlen, const (ubyte)* in_, uint inlen, void* arg);
void SSL_CTX_set_alpn_select_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .SSL_CTX_set_alpn_select_cb_func cb, void* arg);
void SSL_get0_alpn_selected(const (libressl_d.openssl.ossl_typ.SSL)* ssl, const (ubyte)** data, uint* len);

static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	alias SSL_psk_use_session_cb_func = extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.SSL* ssl, const (libressl_d.openssl.ossl_typ.EVP_MD)* md, const (ubyte)** id, size_t* idlen, .SSL_SESSION** sess);
	void SSL_set_psk_use_session_callback(libressl_d.openssl.ossl_typ.SSL* s, .SSL_psk_use_session_cb_func cb);
}

enum SSL_NOTHING = 1;
enum SSL_WRITING = 2;
enum SSL_READING = 3;
enum SSL_X509_LOOKUP = 4;

/* These will only be used when doing non-blocking IO */
pragma(inline, true)
bool SSL_want_nothing(const (libressl_d.openssl.ossl_typ.SSL)* s)

	do
	{
		return .SSL_want(s) == .SSL_NOTHING;
	}

pragma(inline, true)
bool SSL_want_read(const (libressl_d.openssl.ossl_typ.SSL)* s)

	do
	{
		return .SSL_want(s) == .SSL_READING;
	}

pragma(inline, true)
bool SSL_want_write(const (libressl_d.openssl.ossl_typ.SSL)* s)

	do
	{
		return .SSL_want(s) == .SSL_WRITING;
	}

pragma(inline, true)
bool SSL_want_x509_lookup(const (libressl_d.openssl.ossl_typ.SSL)* s)

	do
	{
		return .SSL_want(s) == .SSL_X509_LOOKUP;
	}

enum SSL_MAC_FLAG_READ_MAC_STREAM = 1;
enum SSL_MAC_FLAG_WRITE_MAC_STREAM = 2;

/* compatibility */

pragma(inline, true)
int SSL_set_app_data(libressl_d.openssl.ossl_typ.SSL* s, char* arg)

	do
	{
		return .SSL_set_ex_data(s, 0, arg);
	}

pragma(inline, true)
void* SSL_get_app_data(const (libressl_d.openssl.ossl_typ.SSL)* s)

	do
	{
		return .SSL_get_ex_data(s, 0);
	}

pragma(inline, true)
int SSL_SESSION_set_app_data(.SSL_SESSION* s, char* a)

	do
	{
		return .SSL_SESSION_set_ex_data(s, 0, a);
	}

pragma(inline, true)
void* SSL_SESSION_get_app_data(const (.SSL_SESSION)* s)

	do
	{
		return .SSL_SESSION_get_ex_data(s, 0);
	}

pragma(inline, true)
void* SSL_CTX_get_app_data(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx)

	do
	{
		return .SSL_CTX_get_ex_data(ctx, 0);
	}

pragma(inline, true)
int SSL_CTX_set_app_data(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, char* arg)

	do
	{
		return .SSL_CTX_set_ex_data(ctx, 0, arg);
	}

/*
 * The following are the possible values for ssl.state are are
 * used to indicate where we are up to in the SSL connection establishment.
 * The macros that follow are about the only things you should need to use
 * and even then, only when using non-blocking IO.
 * It can also be useful to work out where you were when the connection
 * failed
 */

enum SSL_ST_CONNECT = 0x1000;
enum SSL_ST_ACCEPT = 0x2000;
enum SSL_ST_MASK = 0x0FFF;
enum SSL_ST_INIT = .SSL_ST_CONNECT | .SSL_ST_ACCEPT;
enum SSL_ST_BEFORE = 0x4000;
enum SSL_ST_OK = 0x03;
enum SSL_ST_RENEGOTIATE = 0x04 | .SSL_ST_INIT;

enum SSL_CB_LOOP = 0x01;
enum SSL_CB_EXIT = 0x02;
enum SSL_CB_READ = 0x04;
enum SSL_CB_WRITE = 0x08;

/**
 * used in callback
 */
enum SSL_CB_ALERT = 0x4000;

enum SSL_CB_READ_ALERT = .SSL_CB_ALERT | .SSL_CB_READ;
enum SSL_CB_WRITE_ALERT = .SSL_CB_ALERT | .SSL_CB_WRITE;
enum SSL_CB_ACCEPT_LOOP = .SSL_ST_ACCEPT | .SSL_CB_LOOP;
enum SSL_CB_ACCEPT_EXIT = .SSL_ST_ACCEPT | .SSL_CB_EXIT;
enum SSL_CB_CONNECT_LOOP = .SSL_ST_CONNECT | .SSL_CB_LOOP;
enum SSL_CB_CONNECT_EXIT = .SSL_ST_CONNECT | .SSL_CB_EXIT;
enum SSL_CB_HANDSHAKE_START = 0x10;
enum SSL_CB_HANDSHAKE_DONE = 0x20;

/* Is the SSL_connection established? */
alias SSL_get_state = .SSL_state;

pragma(inline, true)
bool SSL_is_init_finished(const (libressl_d.openssl.ossl_typ.SSL)* a)

	do
	{
		return .SSL_state(a) == .SSL_ST_OK;
	}

pragma(inline, true)
int SSL_in_init(const (libressl_d.openssl.ossl_typ.SSL)* a)

	do
	{
		return .SSL_state(a) & .SSL_ST_INIT;
	}

pragma(inline, true)
int SSL_in_before(const (libressl_d.openssl.ossl_typ.SSL)* a)

	do
	{
		return .SSL_state(a) & .SSL_ST_BEFORE;
	}

pragma(inline, true)
int SSL_in_connect_init(const (libressl_d.openssl.ossl_typ.SSL)* a)

	do
	{
		return .SSL_state(a) & .SSL_ST_CONNECT;
	}

pragma(inline, true)
int SSL_in_accept_init(const (libressl_d.openssl.ossl_typ.SSL)* a)

	do
	{
		return .SSL_state(a) & .SSL_ST_ACCEPT;
	}

/*
 * The following 2 states are kept in ssl.rstate when reads fail,
 * you should not need these
 */
enum SSL_ST_READ_HEADER = 0xF0;
enum SSL_ST_READ_BODY = 0xF1;
enum SSL_ST_READ_DONE = 0xF2;

/*
 * Obtain latest Finished message
 *   -- that we sent (SSL_get_finished)
 *   -- that we expected from peer (SSL_get_peer_finished).
 * Returns length (0 == no Finished so far), copies up to 'count' bytes.
 */
size_t SSL_get_finished(const (libressl_d.openssl.ossl_typ.SSL)* s, void* buf, size_t count);
size_t SSL_get_peer_finished(const (libressl_d.openssl.ossl_typ.SSL)* s, void* buf, size_t count);

/*
 * use either SSL_VERIFY_NONE or SSL_VERIFY_PEER, the last 2 options
 * are 'ored' with SSL_VERIFY_PEER if they are desired
 */
enum SSL_VERIFY_NONE = 0x00;
enum SSL_VERIFY_PEER = 0x01;
enum SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
enum SSL_VERIFY_CLIENT_ONCE = 0x04;

static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	enum SSL_VERIFY_POST_HANDSHAKE = 0x08;

	int SSL_verify_client_post_handshake(libressl_d.openssl.ossl_typ.SSL* s);
	void SSL_CTX_set_post_handshake_auth(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, int val);
	void SSL_set_post_handshake_auth(libressl_d.openssl.ossl_typ.SSL* s, int val);
}

alias OpenSSL_add_ssl_algorithms = .SSL_library_init;
alias SSLeay_add_ssl_algorithms = .SSL_library_init;

/* More backward compatibility */
pragma(inline, true)
const (char)* SSL_get_cipher(const (libressl_d.openssl.ossl_typ.SSL)* s)

	do
	{
		return .SSL_CIPHER_get_name(.SSL_get_current_cipher(s));
	}

pragma(inline, true)
int SSL_get_cipher_bits(const (libressl_d.openssl.ossl_typ.SSL)* s, int* np)

	do
	{
		return .SSL_CIPHER_get_bits(.SSL_get_current_cipher(s), np);
	}

pragma(inline, true)
const (char)* SSL_get_cipher_version(const (libressl_d.openssl.ossl_typ.SSL)* s)

	do
	{
		return .SSL_CIPHER_get_version(.SSL_get_current_cipher(s));
	}

pragma(inline, true)
const (char)* SSL_get_cipher_name(const (libressl_d.openssl.ossl_typ.SSL)* s)

	do
	{
		return .SSL_CIPHER_get_name(.SSL_get_current_cipher(s));
	}

alias SSL_get_time = .SSL_SESSION_get_time;
alias SSL_set_time = .SSL_SESSION_set_time;
alias SSL_get_timeout = .SSL_SESSION_get_timeout;
alias SSL_set_timeout = .SSL_SESSION_set_timeout;

//#define d2i_SSL_SESSION_bio(bp, s_id) libressl_d.openssl.asn1.ASN1_d2i_bio_of(.SSL_SESSION, .SSL_SESSION_new, .d2i_SSL_SESSION, bp, s_id)
//#define i2d_SSL_SESSION_bio(bp, s_id) libressl_d.openssl.asn1.ASN1_i2d_bio_of(.SSL_SESSION, .i2d_SSL_SESSION, bp, s_id)

.SSL_SESSION* PEM_read_bio_SSL_SESSION(libressl_d.openssl.ossl_typ.BIO* bp, .SSL_SESSION** x, libressl_d.openssl.pem.pem_password_cb cb, void* u);
.SSL_SESSION* PEM_read_SSL_SESSION(libressl_d.compat.stdio.FILE* fp, .SSL_SESSION** x, libressl_d.openssl.pem.pem_password_cb cb, void* u);
int PEM_write_bio_SSL_SESSION(libressl_d.openssl.ossl_typ.BIO* bp, .SSL_SESSION* x);
int PEM_write_SSL_SESSION(libressl_d.compat.stdio.FILE* fp, .SSL_SESSION* x);

/*
 * TLS Alerts.
 *
 * https://www.iana.org/assignments/tls-parameters/#tls-parameters-6
 */

/* Obsolete alerts. */
version (LIBRESSL_INTERNAL) {
} else {
	/* Removed in TLSv1.1 */
	enum SSL_AD_DECRYPTION_FAILED = 21;

	/* Removed in TLSv1.0 */
	enum SSL_AD_NO_CERTIFICATE = 41;

	/* Removed in TLSv1.1 */
	enum SSL_AD_EXPORT_RESTRICTION = 60;
}

enum SSL_AD_CLOSE_NOTIFY = 0;
enum SSL_AD_UNEXPECTED_MESSAGE = 10;
enum SSL_AD_BAD_RECORD_MAC = 20;
enum SSL_AD_RECORD_OVERFLOW = 22;

/* Removed in TLSv1.3 */
enum SSL_AD_DECOMPRESSION_FAILURE = 30;

enum SSL_AD_HANDSHAKE_FAILURE = 40;
enum SSL_AD_BAD_CERTIFICATE = 42;
enum SSL_AD_UNSUPPORTED_CERTIFICATE = 43;
enum SSL_AD_CERTIFICATE_REVOKED = 44;
enum SSL_AD_CERTIFICATE_EXPIRED = 45;
enum SSL_AD_CERTIFICATE_UNKNOWN = 46;
enum SSL_AD_ILLEGAL_PARAMETER = 47;
enum SSL_AD_UNKNOWN_CA = 48;
enum SSL_AD_ACCESS_DENIED = 49;
enum SSL_AD_DECODE_ERROR = 50;
enum SSL_AD_DECRYPT_ERROR = 51;
enum SSL_AD_PROTOCOL_VERSION = 70;
enum SSL_AD_INSUFFICIENT_SECURITY = 71;
enum SSL_AD_INTERNAL_ERROR = 80;
enum SSL_AD_INAPPROPRIATE_FALLBACK = 86;
enum SSL_AD_USER_CANCELLED = 90;

/* Removed in TLSv1.3 */
enum SSL_AD_NO_RENEGOTIATION = 100;

/* Added in TLSv1.3. */
enum SSL_AD_MISSING_EXTENSION = 109;

enum SSL_AD_UNSUPPORTED_EXTENSION = 110;

/* Removed in TLSv1.3 */
enum SSL_AD_CERTIFICATE_UNOBTAINABLE = 111;

enum SSL_AD_UNRECOGNIZED_NAME = 112;
enum SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE = 113;

/* Removed in TLSv1.3 */
enum SSL_AD_BAD_CERTIFICATE_HASH_VALUE = 114;

enum SSL_AD_UNKNOWN_PSK_IDENTITY = 115;
enum SSL_AD_CERTIFICATE_REQUIRED = 116;
enum SSL_AD_NO_APPLICATION_PROTOCOL = 120;

/* Offset to get an SSL_R_... value from an SSL_AD_... value. */
enum SSL_AD_REASON_OFFSET = 1000;

enum SSL_ERROR_NONE = 0;
enum SSL_ERROR_SSL = 1;
enum SSL_ERROR_WANT_READ = 2;
enum SSL_ERROR_WANT_WRITE = 3;
enum SSL_ERROR_WANT_X509_LOOKUP = 4;
enum SSL_ERROR_SYSCALL = 5;
enum SSL_ERROR_ZERO_RETURN = 6;
enum SSL_ERROR_WANT_CONNECT = 7;
enum SSL_ERROR_WANT_ACCEPT = 8;
enum SSL_ERROR_WANT_ASYNC = 9;
enum SSL_ERROR_WANT_ASYNC_JOB = 10;
enum SSL_ERROR_WANT_CLIENT_HELLO_CB = 11;

enum SSL_CTRL_NEED_TMP_RSA = 1;
enum SSL_CTRL_SET_TMP_RSA = 2;
enum SSL_CTRL_SET_TMP_DH = 3;
enum SSL_CTRL_SET_TMP_ECDH = 4;
enum SSL_CTRL_SET_TMP_RSA_CB = 5;
enum SSL_CTRL_SET_TMP_DH_CB = 6;
enum SSL_CTRL_SET_TMP_ECDH_CB = 7;

enum SSL_CTRL_GET_SESSION_REUSED = 8;
enum SSL_CTRL_GET_CLIENT_CERT_REQUEST = 9;
enum SSL_CTRL_GET_NUM_RENEGOTIATIONS = 10;
enum SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS = 11;
enum SSL_CTRL_GET_TOTAL_RENEGOTIATIONS = 12;
enum SSL_CTRL_GET_FLAGS = 13;
enum SSL_CTRL_EXTRA_CHAIN_CERT = 14;

enum SSL_CTRL_SET_MSG_CALLBACK = 15;
enum SSL_CTRL_SET_MSG_CALLBACK_ARG = 16;

/* only applies to datagram connections */
enum SSL_CTRL_SET_MTU = 17;
/* Stats */
enum SSL_CTRL_SESS_NUMBER = 20;
enum SSL_CTRL_SESS_CONNECT = 21;
enum SSL_CTRL_SESS_CONNECT_GOOD = 22;
enum SSL_CTRL_SESS_CONNECT_RENEGOTIATE = 23;
enum SSL_CTRL_SESS_ACCEPT = 24;
enum SSL_CTRL_SESS_ACCEPT_GOOD = 25;
enum SSL_CTRL_SESS_ACCEPT_RENEGOTIATE = 26;
enum SSL_CTRL_SESS_HIT = 27;
enum SSL_CTRL_SESS_CB_HIT = 28;
enum SSL_CTRL_SESS_MISSES = 29;
enum SSL_CTRL_SESS_TIMEOUTS = 30;
enum SSL_CTRL_SESS_CACHE_FULL = 31;
enum SSL_CTRL_OPTIONS = 32;
enum SSL_CTRL_MODE = 33;

enum SSL_CTRL_GET_READ_AHEAD = 40;
enum SSL_CTRL_SET_READ_AHEAD = 41;
enum SSL_CTRL_SET_SESS_CACHE_SIZE = 42;
enum SSL_CTRL_GET_SESS_CACHE_SIZE = 43;
enum SSL_CTRL_SET_SESS_CACHE_MODE = 44;
enum SSL_CTRL_GET_SESS_CACHE_MODE = 45;

enum SSL_CTRL_GET_MAX_CERT_LIST = 50;
enum SSL_CTRL_SET_MAX_CERT_LIST = 51;

enum SSL_CTRL_SET_MAX_SEND_FRAGMENT = 52;

/* see tls1.h for macros based on these */
enum SSL_CTRL_SET_TLSEXT_SERVERNAME_CB = 53;
enum SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG = 54;
enum SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
enum SSL_CTRL_SET_TLSEXT_DEBUG_CB = 56;
enum SSL_CTRL_SET_TLSEXT_DEBUG_ARG = 57;
enum SSL_CTRL_GET_TLSEXT_TICKET_KEYS = 58;
enum SSL_CTRL_SET_TLSEXT_TICKET_KEYS = 59;
enum SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB = 128;
enum SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB = 63;
enum SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG = 129;
enum SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG = 64;
enum SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE = 127;
enum SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE = 65;
enum SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS = 66;
enum SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS = 67;
enum SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS = 68;
enum SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS = 69;
enum SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP = 70;
enum SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP = 71;

enum SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB = 72;

enum SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB = 75;
enum SSL_CTRL_SET_SRP_VERIFY_PARAM_CB = 76;
enum SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB = 77;

enum SSL_CTRL_SET_SRP_ARG = 78;
enum SSL_CTRL_SET_TLS_EXT_SRP_USERNAME = 79;
enum SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH = 80;
enum SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD = 81;

enum DTLS_CTRL_GET_TIMEOUT = 73;
enum DTLS_CTRL_HANDLE_TIMEOUT = 74;
enum DTLS_CTRL_LISTEN = 75;

enum SSL_CTRL_GET_RI_SUPPORT = 76;
enum SSL_CTRL_CLEAR_OPTIONS = 77;
enum SSL_CTRL_CLEAR_MODE = 78;

enum SSL_CTRL_GET_EXTRA_CHAIN_CERTS = 82;
enum SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS = 83;

enum SSL_CTRL_CHAIN = 88;
enum SSL_CTRL_CHAIN_CERT = 89;

enum SSL_CTRL_SET_GROUPS = 91;
enum SSL_CTRL_SET_GROUPS_LIST = 92;
enum SSL_CTRL_GET_SHARED_GROUP = 93;
enum SSL_CTRL_SET_ECDH_AUTO = 94;

static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	enum SSL_CTRL_GET_PEER_SIGNATURE_NID = 108;
	enum SSL_CTRL_GET_PEER_TMP_KEY = 109;
	enum SSL_CTRL_GET_SERVER_TMP_KEY = .SSL_CTRL_GET_PEER_TMP_KEY;
} else {
	enum SSL_CTRL_GET_SERVER_TMP_KEY = 109;
}

enum SSL_CTRL_GET_CHAIN_CERTS = 115;

enum SSL_CTRL_SET_DH_AUTO = 118;

enum SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
enum SSL_CTRL_SET_MAX_PROTO_VERSION = 124;
enum SSL_CTRL_GET_MIN_PROTO_VERSION = 130;
enum SSL_CTRL_GET_MAX_PROTO_VERSION = 131;

static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	enum SSL_CTRL_GET_SIGNATURE_NID = 132;
}

pragma(inline, true)
core.stdc.config.c_long DTLSv1_get_timeout(libressl_d.openssl.ossl_typ.SSL* ssl, void* arg)

	do
	{
		return .SSL_ctrl(ssl, .DTLS_CTRL_GET_TIMEOUT, 0, arg);
	}

pragma(inline, true)
core.stdc.config.c_long DTLSv1_handle_timeout(libressl_d.openssl.ossl_typ.SSL* ssl)

	do
	{
		return .SSL_ctrl(ssl, .DTLS_CTRL_HANDLE_TIMEOUT, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long DTLSv1_listen(libressl_d.openssl.ossl_typ.SSL* ssl, void* peer)

	do
	{
		return .SSL_ctrl(ssl, .DTLS_CTRL_LISTEN, 0, peer);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_session_reused(libressl_d.openssl.ossl_typ.SSL* ssl)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_GET_SESSION_REUSED, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_num_renegotiations(libressl_d.openssl.ossl_typ.SSL* ssl)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_GET_NUM_RENEGOTIATIONS, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_clear_num_renegotiations(libressl_d.openssl.ossl_typ.SSL* ssl)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_total_renegotiations(libressl_d.openssl.ossl_typ.SSL* ssl)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_GET_TOTAL_RENEGOTIATIONS, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_need_tmp_RSA(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_NEED_TMP_RSA, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_tmp_rsa(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, char* rsa)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SET_TMP_RSA, 0, rsa);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_tmp_dh(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, char* dh)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SET_TMP_DH, 0, dh);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_tmp_ecdh(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, char* ecdh)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SET_TMP_ECDH, 0, ecdh);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_dh_auto(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.config.c_long onoff)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SET_DH_AUTO, onoff, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_ecdh_auto(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.config.c_long onoff)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SET_ECDH_AUTO, onoff, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_need_tmp_RSA(libressl_d.openssl.ossl_typ.SSL* ssl)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_NEED_TMP_RSA, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_tmp_rsa(libressl_d.openssl.ossl_typ.SSL* ssl, char* rsa)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_SET_TMP_RSA, 0, rsa);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_tmp_dh(libressl_d.openssl.ossl_typ.SSL* ssl, char* dh)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_SET_TMP_DH, 0, dh);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_tmp_ecdh(libressl_d.openssl.ossl_typ.SSL* ssl, char* ecdh)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_SET_TMP_ECDH, 0, ecdh);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_dh_auto(libressl_d.openssl.ossl_typ.SSL* s, core.stdc.config.c_long onoff)

	do
	{
		return .SSL_ctrl(s, .SSL_CTRL_SET_DH_AUTO, onoff, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_ecdh_auto(libressl_d.openssl.ossl_typ.SSL* s, core.stdc.config.c_long onoff)

	do
	{
		return .SSL_ctrl(s, .SSL_CTRL_SET_ECDH_AUTO, onoff, null);
	}

int SSL_CTX_set0_chain(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .stack_st_X509* chain);
int SSL_CTX_set1_chain(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .stack_st_X509* chain);
int SSL_CTX_add0_chain_cert(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, libressl_d.openssl.ossl_typ.X509* x509);
int SSL_CTX_add1_chain_cert(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, libressl_d.openssl.ossl_typ.X509* x509);
int SSL_CTX_get0_chain_certs(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx, .stack_st_X509** out_chain);
int SSL_CTX_clear_chain_certs(libressl_d.openssl.ossl_typ.SSL_CTX* ctx);

int SSL_set0_chain(libressl_d.openssl.ossl_typ.SSL* ssl, .stack_st_X509* chain);
int SSL_set1_chain(libressl_d.openssl.ossl_typ.SSL* ssl, .stack_st_X509* chain);
int SSL_add0_chain_cert(libressl_d.openssl.ossl_typ.SSL* ssl, libressl_d.openssl.ossl_typ.X509* x509);
int SSL_add1_chain_cert(libressl_d.openssl.ossl_typ.SSL* ssl, libressl_d.openssl.ossl_typ.X509* x509);
int SSL_get0_chain_certs(const (libressl_d.openssl.ossl_typ.SSL)* ssl, .stack_st_X509** out_chain);
int SSL_clear_chain_certs(libressl_d.openssl.ossl_typ.SSL* ssl);

int SSL_CTX_set1_groups(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, const (int)* groups, size_t groups_len);
int SSL_CTX_set1_groups_list(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, const (char)* groups);

int SSL_set1_groups(libressl_d.openssl.ossl_typ.SSL* ssl, const (int)* groups, size_t groups_len);
int SSL_set1_groups_list(libressl_d.openssl.ossl_typ.SSL* ssl, const (char)* groups);

int SSL_CTX_get_min_proto_version(libressl_d.openssl.ossl_typ.SSL_CTX* ctx);
int SSL_CTX_get_max_proto_version(libressl_d.openssl.ossl_typ.SSL_CTX* ctx);
int SSL_CTX_set_min_proto_version(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.stdint.uint16_t version_);
int SSL_CTX_set_max_proto_version(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.stdint.uint16_t version_);

int SSL_get_min_proto_version(libressl_d.openssl.ossl_typ.SSL* ssl);
int SSL_get_max_proto_version(libressl_d.openssl.ossl_typ.SSL* ssl);
int SSL_set_min_proto_version(libressl_d.openssl.ossl_typ.SSL* ssl, core.stdc.stdint.uint16_t version_);
int SSL_set_max_proto_version(libressl_d.openssl.ossl_typ.SSL* ssl, core.stdc.stdint.uint16_t version_);

const (.SSL_METHOD)* SSL_CTX_get_ssl_method(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx);

version (LIBRESSL_INTERNAL) {
} else {
	enum SSL_CTRL_SET_CURVES = .SSL_CTRL_SET_GROUPS;
	enum SSL_CTRL_SET_CURVES_LIST = .SSL_CTRL_SET_GROUPS_LIST;

	alias SSL_CTX_set1_curves = .SSL_CTX_set1_groups;
	alias SSL_CTX_set1_curves_list = .SSL_CTX_set1_groups_list;
	alias SSL_set1_curves = .SSL_set1_groups;
	alias SSL_set1_curves_list = .SSL_set1_groups_list;
}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_add_extra_chain_cert(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, char* x509)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_EXTRA_CHAIN_CERT, 0, x509);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_get_extra_chain_certs(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, void* px509)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_GET_EXTRA_CHAIN_CERTS, 0, px509);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_get_extra_chain_certs_only(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, void* px509)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_GET_EXTRA_CHAIN_CERTS, 1, px509);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_clear_extra_chain_certs(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_get_shared_group(libressl_d.openssl.ossl_typ.SSL* s, core.stdc.config.c_long n)

	do
	{
		return .SSL_ctrl(s, .SSL_CTRL_GET_SHARED_GROUP, n, null);
	}

alias SSL_get_shared_curve = .SSL_get_shared_group;

pragma(inline, true)
core.stdc.config.c_long SSL_get_server_tmp_key(libressl_d.openssl.ossl_typ.SSL* s, void* pk)

	do
	{
		return .SSL_ctrl(s, .SSL_CTRL_GET_SERVER_TMP_KEY, 0, pk);
	}

static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	pragma(inline, true)
	core.stdc.config.c_long SSL_get_signature_nid(libressl_d.openssl.ossl_typ.SSL* s, void* pn)

		do
		{
			return .SSL_ctrl(s, .SSL_CTRL_GET_SIGNATURE_NID, 0, pn);
		}

	pragma(inline, true)
	core.stdc.config.c_long SSL_get_peer_signature_nid(libressl_d.openssl.ossl_typ.SSL* s, void* pn)

		do
		{
			return .SSL_ctrl(s, .SSL_CTRL_GET_PEER_SIGNATURE_NID, 0, pn);
		}

	pragma(inline, true)
	core.stdc.config.c_long SSL_get_peer_tmp_key(libressl_d.openssl.ossl_typ.SSL* s, void* pk)

		do
		{
			return .SSL_ctrl(s, .SSL_CTRL_GET_PEER_TMP_KEY, 0, pk);
		}

	int SSL_get_signature_type_nid(const (libressl_d.openssl.ossl_typ.SSL)* ssl, int* nid);
	int SSL_get_peer_signature_type_nid(const (libressl_d.openssl.ossl_typ.SSL)* ssl, int* nid);
}

version (LIBRESSL_INTERNAL) {
} else {
	/*
	 * Also provide those functions as macros for compatibility with
	 * existing users.
	 */
	alias SSL_CTX_set0_chain = .SSL_CTX_set0_chain;
	alias SSL_CTX_set1_chain = .SSL_CTX_set1_chain;
	alias SSL_CTX_add0_chain_cert = .SSL_CTX_add0_chain_cert;
	alias SSL_CTX_add1_chain_cert = .SSL_CTX_add1_chain_cert;
	alias SSL_CTX_get0_chain_certs = .SSL_CTX_get0_chain_certs;
	alias SSL_CTX_clear_chain_certs = .SSL_CTX_clear_chain_certs;

	alias SSL_add0_chain_cert = .SSL_add0_chain_cert;
	alias SSL_add1_chain_cert = .SSL_add1_chain_cert;
	alias SSL_set0_chain = .SSL_set0_chain;
	alias SSL_set1_chain = .SSL_set1_chain;
	alias SSL_get0_chain_certs = .SSL_get0_chain_certs;
	alias SSL_clear_chain_certs = .SSL_clear_chain_certs;

	alias SSL_CTX_set1_groups = .SSL_CTX_set1_groups;
	alias SSL_CTX_set1_groups_list = .SSL_CTX_set1_groups_list;
	alias SSL_set1_groups = .SSL_set1_groups;
	alias SSL_set1_groups_list = .SSL_set1_groups_list;

	alias SSL_CTX_get_min_proto_version = .SSL_CTX_get_min_proto_version;
	alias SSL_CTX_get_max_proto_version = .SSL_CTX_get_max_proto_version;
	alias SSL_CTX_set_min_proto_version = .SSL_CTX_set_min_proto_version;
	alias SSL_CTX_set_max_proto_version = .SSL_CTX_set_max_proto_version;

	alias SSL_get_min_proto_version = .SSL_get_min_proto_version;
	alias SSL_get_max_proto_version = .SSL_get_max_proto_version;
	alias SSL_set_min_proto_version = .SSL_set_min_proto_version;
	alias SSL_set_max_proto_version = .SSL_set_max_proto_version;
}

const (libressl_d.openssl.bio.BIO_METHOD)* BIO_f_ssl();
libressl_d.openssl.ossl_typ.BIO* BIO_new_ssl(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, int client);
libressl_d.openssl.ossl_typ.BIO* BIO_new_ssl_connect(libressl_d.openssl.ossl_typ.SSL_CTX* ctx);
libressl_d.openssl.ossl_typ.BIO* BIO_new_buffer_ssl_connect(libressl_d.openssl.ossl_typ.SSL_CTX* ctx);
int BIO_ssl_copy_session_id(libressl_d.openssl.ossl_typ.BIO* to, libressl_d.openssl.ossl_typ.BIO* from);
void BIO_ssl_shutdown(libressl_d.openssl.ossl_typ.BIO* ssl_bio);

.stack_st_SSL_CIPHER* SSL_CTX_get_ciphers(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx);
int SSL_CTX_set_cipher_list(libressl_d.openssl.ossl_typ.SSL_CTX*, const (char)* str);

static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	int SSL_CTX_set_ciphersuites(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, const (char)* str);
}

libressl_d.openssl.ossl_typ.SSL_CTX* SSL_CTX_new(const (.SSL_METHOD)* meth);
void SSL_CTX_free(libressl_d.openssl.ossl_typ.SSL_CTX*);
int SSL_CTX_up_ref(libressl_d.openssl.ossl_typ.SSL_CTX* ctx);
core.stdc.config.c_long SSL_CTX_set_timeout(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.config.c_long t);
core.stdc.config.c_long SSL_CTX_get_timeout(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx);
libressl_d.openssl.ossl_typ.X509_STORE* SSL_CTX_get_cert_store(const (libressl_d.openssl.ossl_typ.SSL_CTX)*);
void SSL_CTX_set_cert_store(libressl_d.openssl.ossl_typ.SSL_CTX*, libressl_d.openssl.ossl_typ.X509_STORE*);
libressl_d.openssl.ossl_typ.X509* SSL_CTX_get0_certificate(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx);
libressl_d.openssl.ossl_typ.EVP_PKEY* SSL_CTX_get0_privatekey(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx);
int SSL_want(const (libressl_d.openssl.ossl_typ.SSL)* s);
int SSL_clear(libressl_d.openssl.ossl_typ.SSL* s);

void SSL_CTX_flush_sessions(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.config.c_long tm);

const (.SSL_CIPHER)* SSL_get_current_cipher(const (libressl_d.openssl.ossl_typ.SSL)* s);
const (.SSL_CIPHER)* SSL_CIPHER_get_by_id(uint id);
const (.SSL_CIPHER)* SSL_CIPHER_get_by_value(core.stdc.stdint.uint16_t value);
int SSL_CIPHER_get_bits(const (.SSL_CIPHER)* c, int* alg_bits);
const (char)* SSL_CIPHER_get_version(const (.SSL_CIPHER)* c);
const (char)* SSL_CIPHER_get_name(const (.SSL_CIPHER)* c);
core.stdc.config.c_ulong SSL_CIPHER_get_id(const (.SSL_CIPHER)* c);
core.stdc.stdint.uint16_t SSL_CIPHER_get_value(const (.SSL_CIPHER)* c);
const (.SSL_CIPHER)* SSL_CIPHER_find(libressl_d.openssl.ossl_typ.SSL* ssl, const (ubyte)* ptr);
int SSL_CIPHER_get_cipher_nid(const (.SSL_CIPHER)* c);
int SSL_CIPHER_get_digest_nid(const (.SSL_CIPHER)* c);
int SSL_CIPHER_get_kx_nid(const (.SSL_CIPHER)* c);
int SSL_CIPHER_get_auth_nid(const (.SSL_CIPHER)* c);
int SSL_CIPHER_is_aead(const (.SSL_CIPHER)* c);

int SSL_get_fd(const (libressl_d.openssl.ossl_typ.SSL)* s);
int SSL_get_rfd(const (libressl_d.openssl.ossl_typ.SSL)* s);
int SSL_get_wfd(const (libressl_d.openssl.ossl_typ.SSL)* s);
const (char)* SSL_get_cipher_list(const (libressl_d.openssl.ossl_typ.SSL)* s, int n);
char* SSL_get_shared_ciphers(const (libressl_d.openssl.ossl_typ.SSL)* s, char* buf, int len);
int SSL_get_read_ahead(const (libressl_d.openssl.ossl_typ.SSL)* s);
int SSL_pending(const (libressl_d.openssl.ossl_typ.SSL)* s);
int SSL_set_fd(libressl_d.openssl.ossl_typ.SSL* s, int fd);
int SSL_set_rfd(libressl_d.openssl.ossl_typ.SSL* s, int fd);
int SSL_set_wfd(libressl_d.openssl.ossl_typ.SSL* s, int fd);
void SSL_set_bio(libressl_d.openssl.ossl_typ.SSL* s, libressl_d.openssl.ossl_typ.BIO* rbio, libressl_d.openssl.ossl_typ.BIO* wbio);
libressl_d.openssl.ossl_typ.BIO* SSL_get_rbio(const (libressl_d.openssl.ossl_typ.SSL)* s);
void SSL_set0_rbio(libressl_d.openssl.ossl_typ.SSL* s, libressl_d.openssl.ossl_typ.BIO* rbio);
libressl_d.openssl.ossl_typ.BIO* SSL_get_wbio(const (libressl_d.openssl.ossl_typ.SSL)* s);
int SSL_set_cipher_list(libressl_d.openssl.ossl_typ.SSL* s, const (char)* str);

static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	int SSL_set_ciphersuites(libressl_d.openssl.ossl_typ.SSL* s, const (char)* str);
}

void SSL_set_read_ahead(libressl_d.openssl.ossl_typ.SSL* s, int yes);
int SSL_get_verify_mode(const (libressl_d.openssl.ossl_typ.SSL)* s);
int SSL_get_verify_depth(const (libressl_d.openssl.ossl_typ.SSL)* s);
//int (*SSL_get_verify_callback(const (libressl_d.openssl.ossl_typ.SSL)* s))(int, libressl_d.openssl.ossl_typ.X509_STORE_CTX*);

private alias SSL_set_verify_callback = /* Temporary type */ extern (C) nothrow @nogc int function(int ok, libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);
void SSL_set_verify(libressl_d.openssl.ossl_typ.SSL* s, int mode, .SSL_set_verify_callback callback);
void SSL_set_verify_depth(libressl_d.openssl.ossl_typ.SSL* s, int depth);
int SSL_use_RSAPrivateKey(libressl_d.openssl.ossl_typ.SSL* ssl, libressl_d.openssl.ossl_typ.RSA* rsa);
int SSL_use_RSAPrivateKey_ASN1(libressl_d.openssl.ossl_typ.SSL* ssl, const (ubyte)* d, core.stdc.config.c_long len);
int SSL_use_PrivateKey(libressl_d.openssl.ossl_typ.SSL* ssl, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
int SSL_use_PrivateKey_ASN1(int pk, libressl_d.openssl.ossl_typ.SSL* ssl, const (ubyte)* d, core.stdc.config.c_long len);
int SSL_use_certificate(libressl_d.openssl.ossl_typ.SSL* ssl, libressl_d.openssl.ossl_typ.X509* x);
int SSL_use_certificate_ASN1(libressl_d.openssl.ossl_typ.SSL* ssl, const (ubyte)* d, int len);

int SSL_use_RSAPrivateKey_file(libressl_d.openssl.ossl_typ.SSL* ssl, const (char)* file, int type);
int SSL_use_PrivateKey_file(libressl_d.openssl.ossl_typ.SSL* ssl, const (char)* file, int type);
int SSL_use_certificate_file(libressl_d.openssl.ossl_typ.SSL* ssl, const (char)* file, int type);
int SSL_use_certificate_chain_file(libressl_d.openssl.ossl_typ.SSL* ssl, const (char)* file);
int SSL_CTX_use_RSAPrivateKey_file(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, const (char)* file, int type);
int SSL_CTX_use_PrivateKey_file(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, const (char)* file, int type);
int SSL_CTX_use_certificate_file(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, const (char)* file, int type);

/**
 * PEM type
 */
int SSL_CTX_use_certificate_chain_file(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, const (char)* file);

int SSL_CTX_use_certificate_chain_mem(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, void* buf, int len);
.stack_st_X509_NAME* SSL_load_client_CA_file(const (char)* file);
int SSL_add_file_cert_subjects_to_stack(.stack_st_X509_NAME* stackCAs, const (char)* file);
int SSL_add_dir_cert_subjects_to_stack(.stack_st_X509_NAME* stackCAs, const (char)* dir);

void SSL_load_error_strings();
const (char)* SSL_state_string(const (libressl_d.openssl.ossl_typ.SSL)* s);
const (char)* SSL_rstate_string(const (libressl_d.openssl.ossl_typ.SSL)* s);
const (char)* SSL_state_string_long(const (libressl_d.openssl.ossl_typ.SSL)* s);
const (char)* SSL_rstate_string_long(const (libressl_d.openssl.ossl_typ.SSL)* s);
const (.SSL_CIPHER)* SSL_SESSION_get0_cipher(const (.SSL_SESSION)* ss);
size_t SSL_SESSION_get_master_key(const (.SSL_SESSION)* ss, ubyte* out_, size_t max_out);
int SSL_SESSION_get_protocol_version(const (.SSL_SESSION)* s);
core.stdc.config.c_long SSL_SESSION_get_time(const (.SSL_SESSION)* s);
core.stdc.config.c_long SSL_SESSION_set_time(.SSL_SESSION* s, core.stdc.config.c_long t);
core.stdc.config.c_long SSL_SESSION_get_timeout(const (.SSL_SESSION)* s);
core.stdc.config.c_long SSL_SESSION_set_timeout(.SSL_SESSION* s, core.stdc.config.c_long t);
int SSL_copy_session_id(libressl_d.openssl.ossl_typ.SSL* to, const (libressl_d.openssl.ossl_typ.SSL)* from);
libressl_d.openssl.ossl_typ.X509* SSL_SESSION_get0_peer(.SSL_SESSION* s);
int SSL_SESSION_set1_id(.SSL_SESSION* s, const (ubyte)* sid, uint sid_len);
int SSL_SESSION_set1_id_context(.SSL_SESSION* s, const (ubyte)* sid_ctx, uint sid_ctx_len);

static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	int SSL_SESSION_is_resumable(const (.SSL_SESSION)* s);
}

.SSL_SESSION* SSL_SESSION_new();
void SSL_SESSION_free(.SSL_SESSION* ses);
int SSL_SESSION_up_ref(.SSL_SESSION* ss);
const (ubyte)* SSL_SESSION_get_id(const (.SSL_SESSION)* ss, uint* len);
const (ubyte)* SSL_SESSION_get0_id_context(const (.SSL_SESSION)* ss, uint* len);

static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	core.stdc.stdint.uint32_t SSL_SESSION_get_max_early_data(const (.SSL_SESSION)* sess);
	int SSL_SESSION_set_max_early_data(.SSL_SESSION* sess, core.stdc.stdint.uint32_t max_early_data);
}

core.stdc.config.c_ulong SSL_SESSION_get_ticket_lifetime_hint(const (.SSL_SESSION)* s);
int SSL_SESSION_has_ticket(const (.SSL_SESSION)* s);
uint SSL_SESSION_get_compress_id(const (.SSL_SESSION)* ss);
int SSL_SESSION_print_fp(libressl_d.compat.stdio.FILE* fp, const (.SSL_SESSION)* ses);
int SSL_SESSION_print(libressl_d.openssl.ossl_typ.BIO* fp, const (.SSL_SESSION)* ses);
int i2d_SSL_SESSION(.SSL_SESSION* in_, ubyte** pp);
int SSL_set_session(libressl_d.openssl.ossl_typ.SSL* to, .SSL_SESSION* session);
int SSL_CTX_add_session(libressl_d.openssl.ossl_typ.SSL_CTX* s, .SSL_SESSION* c);
int SSL_CTX_remove_session(libressl_d.openssl.ossl_typ.SSL_CTX*, .SSL_SESSION* c);
int SSL_CTX_set_generate_session_id(libressl_d.openssl.ossl_typ.SSL_CTX*, .GEN_SESSION_CB);
int SSL_set_generate_session_id(libressl_d.openssl.ossl_typ.SSL*, .GEN_SESSION_CB);
int SSL_has_matching_session_id(const (libressl_d.openssl.ossl_typ.SSL)* ssl, const (ubyte)* id, uint id_len);
.SSL_SESSION* d2i_SSL_SESSION(.SSL_SESSION** a, const (ubyte)** pp, core.stdc.config.c_long length_);

version (OPENSSL_NO_DEPRECATED) {
} else {
	version (OPENSSL_NO_X509) {
	} else {
		static assert(libressl_d.openssl.x509.HEADER_X509_H);
	}
}

libressl_d.openssl.ossl_typ.X509* SSL_get_peer_certificate(const (libressl_d.openssl.ossl_typ.SSL)* s);

.stack_st_X509* SSL_get_peer_cert_chain(const (libressl_d.openssl.ossl_typ.SSL)* s);

int SSL_CTX_get_verify_mode(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx);
int SSL_CTX_get_verify_depth(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx);
//int (*SSL_CTX_get_verify_callback(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx))(int, libressl_d.openssl.ossl_typ.X509_STORE_CTX*);

private alias SSL_CTX_set_verify_callback = /* Temporary type */ extern (C) nothrow @nogc int function(int, libressl_d.openssl.ossl_typ.X509_STORE_CTX*);
void SSL_CTX_set_verify(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, int mode, .SSL_CTX_set_verify_callback callback);

void SSL_CTX_set_verify_depth(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, int depth);

private alias SSL_CTX_set_cert_verify_callback_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX*, void*);
void SSL_CTX_set_cert_verify_callback(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .SSL_CTX_set_cert_verify_callback_func cb, void* arg);

int SSL_CTX_use_RSAPrivateKey(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, libressl_d.openssl.ossl_typ.RSA* rsa);
int SSL_CTX_use_RSAPrivateKey_ASN1(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, const (ubyte)* d, core.stdc.config.c_long len);
int SSL_CTX_use_PrivateKey(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, libressl_d.openssl.ossl_typ.EVP_PKEY* pkey);
int SSL_CTX_use_PrivateKey_ASN1(int pk, libressl_d.openssl.ossl_typ.SSL_CTX* ctx, const (ubyte)* d, core.stdc.config.c_long len);
int SSL_CTX_use_certificate(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, libressl_d.openssl.ossl_typ.X509* x);
int SSL_CTX_use_certificate_ASN1(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, int len, const (ubyte)* d);

libressl_d.openssl.pem.pem_password_cb SSL_CTX_get_default_passwd_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ctx);
void SSL_CTX_set_default_passwd_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, libressl_d.openssl.pem.pem_password_cb cb);
void* SSL_CTX_get_default_passwd_cb_userdata(libressl_d.openssl.ossl_typ.SSL_CTX* ctx);
void SSL_CTX_set_default_passwd_cb_userdata(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, void* u);

int SSL_CTX_check_private_key(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx);
int SSL_check_private_key(const (libressl_d.openssl.ossl_typ.SSL)* ctx);

int SSL_CTX_set_session_id_context(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, const (ubyte)* sid_ctx, uint sid_ctx_len);

int SSL_set_session_id_context(libressl_d.openssl.ossl_typ.SSL* ssl, const (ubyte)* sid_ctx, uint sid_ctx_len);

int SSL_CTX_set_purpose(libressl_d.openssl.ossl_typ.SSL_CTX* s, int purpose);
int SSL_set_purpose(libressl_d.openssl.ossl_typ.SSL* s, int purpose);
int SSL_CTX_set_trust(libressl_d.openssl.ossl_typ.SSL_CTX* s, int trust);
int SSL_set_trust(libressl_d.openssl.ossl_typ.SSL* s, int trust);
int SSL_set1_host(libressl_d.openssl.ossl_typ.SSL* s, const (char)* hostname);
void SSL_set_hostflags(libressl_d.openssl.ossl_typ.SSL* s, uint flags);
const (char)* SSL_get0_peername(libressl_d.openssl.ossl_typ.SSL* s);

libressl_d.openssl.ossl_typ.X509_VERIFY_PARAM* SSL_CTX_get0_param(libressl_d.openssl.ossl_typ.SSL_CTX* ctx);
int SSL_CTX_set1_param(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, libressl_d.openssl.ossl_typ.X509_VERIFY_PARAM* vpm);
libressl_d.openssl.ossl_typ.X509_VERIFY_PARAM* SSL_get0_param(libressl_d.openssl.ossl_typ.SSL* ssl);
int SSL_set1_param(libressl_d.openssl.ossl_typ.SSL* ssl, libressl_d.openssl.ossl_typ.X509_VERIFY_PARAM* vpm);

libressl_d.openssl.ossl_typ.SSL* SSL_new(libressl_d.openssl.ossl_typ.SSL_CTX* ctx);
void SSL_free(libressl_d.openssl.ossl_typ.SSL* ssl);
int SSL_up_ref(libressl_d.openssl.ossl_typ.SSL* ssl);
int SSL_accept(libressl_d.openssl.ossl_typ.SSL* ssl);
int SSL_connect(libressl_d.openssl.ossl_typ.SSL* ssl);
int SSL_is_dtls(const (libressl_d.openssl.ossl_typ.SSL)* s);
int SSL_is_server(const (libressl_d.openssl.ossl_typ.SSL)* s);
int SSL_read(libressl_d.openssl.ossl_typ.SSL* ssl, void* buf, int num);
int SSL_peek(libressl_d.openssl.ossl_typ.SSL* ssl, void* buf, int num);
int SSL_write(libressl_d.openssl.ossl_typ.SSL* ssl, const (void)* buf, int num);
int SSL_read_ex(libressl_d.openssl.ossl_typ.SSL* ssl, void* buf, size_t num, size_t* bytes_read);
int SSL_peek_ex(libressl_d.openssl.ossl_typ.SSL* ssl, void* buf, size_t num, size_t* bytes_peeked);
int SSL_write_ex(libressl_d.openssl.ossl_typ.SSL* ssl, const (void)* buf, size_t num, size_t* bytes_written);

static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	core.stdc.stdint.uint32_t SSL_CTX_get_max_early_data(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx);
	int SSL_CTX_set_max_early_data(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.stdint.uint32_t max_early_data);

	core.stdc.stdint.uint32_t SSL_get_max_early_data(const (libressl_d.openssl.ossl_typ.SSL)* s);
	int SSL_set_max_early_data(libressl_d.openssl.ossl_typ.SSL* s, core.stdc.stdint.uint32_t max_early_data);

	enum SSL_EARLY_DATA_NOT_SENT = 0;
	enum SSL_EARLY_DATA_REJECTED = 1;
	enum SSL_EARLY_DATA_ACCEPTED = 2;
	int SSL_get_early_data_status(const (libressl_d.openssl.ossl_typ.SSL)* s);

	enum SSL_READ_EARLY_DATA_ERROR = 0;
	enum SSL_READ_EARLY_DATA_SUCCESS = 1;
	enum SSL_READ_EARLY_DATA_FINISH = 2;
	int SSL_read_early_data(libressl_d.openssl.ossl_typ.SSL* s, void* buf, size_t num, size_t* readbytes);
	int SSL_write_early_data(libressl_d.openssl.ossl_typ.SSL* s, const (void)* buf, size_t num, size_t* written);
}

core.stdc.config.c_long SSL_ctrl(libressl_d.openssl.ossl_typ.SSL* ssl, int cmd, core.stdc.config.c_long larg, void* parg);

private alias SSL_callback_ctrl_func = /* Temporary type */ extern (C) nothrow @nogc void function();
core.stdc.config.c_long SSL_callback_ctrl(libressl_d.openssl.ossl_typ.SSL*, int, .SSL_callback_ctrl_func);

core.stdc.config.c_long SSL_CTX_ctrl(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, int cmd, core.stdc.config.c_long larg, void* parg);

private alias SSL_CTX_callback_ctrl_func = /* Temporary type */ extern (C) nothrow @nogc void function();
core.stdc.config.c_long SSL_CTX_callback_ctrl(libressl_d.openssl.ossl_typ.SSL_CTX*, int, .SSL_CTX_callback_ctrl_func);

int SSL_get_error(const (libressl_d.openssl.ossl_typ.SSL)* s, int ret_code);
const (char)* SSL_get_version(const (libressl_d.openssl.ossl_typ.SSL)* s);

/* This sets the 'default' SSL version that SSL_new() will create */
int SSL_CTX_set_ssl_version(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, const (.SSL_METHOD)* meth);

/**
 * SSLv3 or TLSv1.*
 */
const (.SSL_METHOD)* SSLv23_method();

///Ditto
const (.SSL_METHOD)* SSLv23_server_method();

///Ditto
const (.SSL_METHOD)* SSLv23_client_method();

/**
 * TLSv1.0
 */
const (.SSL_METHOD)* TLSv1_method();

///Ditto
const (.SSL_METHOD)* TLSv1_server_method();

///Ditto
const (.SSL_METHOD)* TLSv1_client_method();

/**
 * TLSv1.1
 */
const (.SSL_METHOD)* TLSv1_1_method();

///Ditto
const (.SSL_METHOD)* TLSv1_1_server_method();

///Ditto
const (.SSL_METHOD)* TLSv1_1_client_method();

/**
 * TLSv1.2
 */
const (.SSL_METHOD)* TLSv1_2_method();

///Ditto
const (.SSL_METHOD)* TLSv1_2_server_method();

///Ditto
const (.SSL_METHOD)* TLSv1_2_client_method();

/**
 * TLS v1.0 or later
 */
const (.SSL_METHOD)* TLS_method();

///Ditto
const (.SSL_METHOD)* TLS_server_method();

///Ditto
const (.SSL_METHOD)* TLS_client_method();

/**
 * DTLSv1.0
 */
const (.SSL_METHOD)* DTLSv1_method();

///Ditto
const (.SSL_METHOD)* DTLSv1_server_method();

///Ditto
const (.SSL_METHOD)* DTLSv1_client_method();

/**
 * DTLSv1.2
 */
const (.SSL_METHOD)* DTLSv1_2_method();

///Ditto
const (.SSL_METHOD)* DTLSv1_2_server_method();

///Ditto
const (.SSL_METHOD)* DTLSv1_2_client_method();

/**
 * DTLS v1.0 or later
 */
const (.SSL_METHOD)* DTLS_method();

///Ditto
const (.SSL_METHOD)* DTLS_server_method();

///Ditto
const (.SSL_METHOD)* DTLS_client_method();

.stack_st_SSL_CIPHER* SSL_get_ciphers(const (libressl_d.openssl.ossl_typ.SSL)* s);
.stack_st_SSL_CIPHER* SSL_get_client_ciphers(const (libressl_d.openssl.ossl_typ.SSL)* s);
.stack_st_SSL_CIPHER* SSL_get1_supported_ciphers(libressl_d.openssl.ossl_typ.SSL* s);

int SSL_do_handshake(libressl_d.openssl.ossl_typ.SSL* s);
int SSL_renegotiate(libressl_d.openssl.ossl_typ.SSL* s);
int SSL_renegotiate_abbreviated(libressl_d.openssl.ossl_typ.SSL* s);
int SSL_renegotiate_pending(libressl_d.openssl.ossl_typ.SSL* s);
int SSL_shutdown(libressl_d.openssl.ossl_typ.SSL* s);

const (.SSL_METHOD)* SSL_get_ssl_method(libressl_d.openssl.ossl_typ.SSL* s);
int SSL_set_ssl_method(libressl_d.openssl.ossl_typ.SSL* s, const (.SSL_METHOD)* method);
const (char)* SSL_alert_type_string_long(int value);
const (char)* SSL_alert_type_string(int value);
const (char)* SSL_alert_desc_string_long(int value);
const (char)* SSL_alert_desc_string(int value);

void SSL_set_client_CA_list(libressl_d.openssl.ossl_typ.SSL* s, .stack_st_X509_NAME* name_list);
void SSL_CTX_set_client_CA_list(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .stack_st_X509_NAME* name_list);
.stack_st_X509_NAME* SSL_get_client_CA_list(const (libressl_d.openssl.ossl_typ.SSL)* s);
.stack_st_X509_NAME* SSL_CTX_get_client_CA_list(const (libressl_d.openssl.ossl_typ.SSL_CTX)* s);

int SSL_add_client_CA(libressl_d.openssl.ossl_typ.SSL* ssl, libressl_d.openssl.ossl_typ.X509* x);
int SSL_CTX_add_client_CA(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, libressl_d.openssl.ossl_typ.X509* x);

void SSL_set_connect_state(libressl_d.openssl.ossl_typ.SSL* s);
void SSL_set_accept_state(libressl_d.openssl.ossl_typ.SSL* s);

core.stdc.config.c_long SSL_get_default_timeout(const (libressl_d.openssl.ossl_typ.SSL)* s);

int SSL_library_init();

char* SSL_CIPHER_description(const (.SSL_CIPHER)*, char* buf, int size);
.stack_st_X509_NAME* SSL_dup_CA_list(const (.stack_st_X509_NAME)* sk);

libressl_d.openssl.ossl_typ.SSL* SSL_dup(libressl_d.openssl.ossl_typ.SSL* ssl);

libressl_d.openssl.ossl_typ.X509* SSL_get_certificate(const (libressl_d.openssl.ossl_typ.SSL)* ssl);

/* libressl_d.openssl.ossl_typ.EVP_PKEY */
libressl_d.openssl.ossl_typ.evp_pkey_st* SSL_get_privatekey(const (libressl_d.openssl.ossl_typ.SSL)* ssl);

void SSL_CTX_set_quiet_shutdown(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, int mode);
int SSL_CTX_get_quiet_shutdown(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx);
void SSL_set_quiet_shutdown(libressl_d.openssl.ossl_typ.SSL* ssl, int mode);
int SSL_get_quiet_shutdown(const (libressl_d.openssl.ossl_typ.SSL)* ssl);
void SSL_set_shutdown(libressl_d.openssl.ossl_typ.SSL* ssl, int mode);
int SSL_get_shutdown(const (libressl_d.openssl.ossl_typ.SSL)* ssl);
int SSL_version(const (libressl_d.openssl.ossl_typ.SSL)* ssl);
int SSL_CTX_set_default_verify_paths(libressl_d.openssl.ossl_typ.SSL_CTX* ctx);
int SSL_CTX_load_verify_locations(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, const (char)* CAfile, const (char)* CApath);
int SSL_CTX_load_verify_mem(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, void* buf, int len);

/**
 * just peek at pointer
 */
alias SSL_get0_session = .SSL_get_session;

.SSL_SESSION* SSL_get_session(const (libressl_d.openssl.ossl_typ.SSL)* ssl);

/**
 * obtain a reference count
 */
.SSL_SESSION* SSL_get1_session(libressl_d.openssl.ossl_typ.SSL* ssl);

libressl_d.openssl.ossl_typ.SSL_CTX* SSL_get_SSL_CTX(const (libressl_d.openssl.ossl_typ.SSL)* ssl);
libressl_d.openssl.ossl_typ.SSL_CTX* SSL_set_SSL_CTX(libressl_d.openssl.ossl_typ.SSL* ssl, libressl_d.openssl.ossl_typ.SSL_CTX* ctx);

private alias SSL_set_info_callback_func = /* Temporary type */ extern (C) nothrow @nogc void function(const (libressl_d.openssl.ossl_typ.SSL)* ssl, int type, int val);
void SSL_set_info_callback(libressl_d.openssl.ossl_typ.SSL* ssl, .SSL_set_info_callback_func cb);

//void (*SSL_get_info_callback(const (libressl_d.openssl.ossl_typ.SSL)* ssl))(const (libressl_d.openssl.ossl_typ.SSL)* ssl, int type, int val);
int SSL_state(const (libressl_d.openssl.ossl_typ.SSL)* ssl);
void SSL_set_state(libressl_d.openssl.ossl_typ.SSL* ssl, int state);

void SSL_set_verify_result(libressl_d.openssl.ossl_typ.SSL* ssl, core.stdc.config.c_long v);
core.stdc.config.c_long SSL_get_verify_result(const (libressl_d.openssl.ossl_typ.SSL)* ssl);

int SSL_set_ex_data(libressl_d.openssl.ossl_typ.SSL* ssl, int idx, void* data);
void* SSL_get_ex_data(const (libressl_d.openssl.ossl_typ.SSL)* ssl, int idx);
int SSL_get_ex_new_index(core.stdc.config.c_long argl, void* argp, libressl_d.openssl.ossl_typ.CRYPTO_EX_new new_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_dup dup_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_free free_func);

int SSL_SESSION_set_ex_data(.SSL_SESSION* ss, int idx, void* data);
void* SSL_SESSION_get_ex_data(const (.SSL_SESSION)* ss, int idx);
int SSL_SESSION_get_ex_new_index(core.stdc.config.c_long argl, void* argp, libressl_d.openssl.ossl_typ.CRYPTO_EX_new new_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_dup dup_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_free free_func);

int SSL_CTX_set_ex_data(libressl_d.openssl.ossl_typ.SSL_CTX* ssl, int idx, void* data);
void* SSL_CTX_get_ex_data(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ssl, int idx);
int SSL_CTX_get_ex_new_index(core.stdc.config.c_long argl, void* argp, libressl_d.openssl.ossl_typ.CRYPTO_EX_new new_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_dup dup_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_free free_func);

int SSL_get_ex_data_X509_STORE_CTX_idx();

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_sess_set_cache_size(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.config.c_long t)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SET_SESS_CACHE_SIZE, t, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_sess_get_cache_size(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_GET_SESS_CACHE_SIZE, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_session_cache_mode(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.config.c_long m)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SET_SESS_CACHE_MODE, m, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_get_session_cache_mode(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_GET_SESS_CACHE_MODE, 0, null);
	}

alias SSL_CTX_get_default_read_ahead = .SSL_CTX_get_read_ahead;
alias SSL_CTX_set_default_read_ahead = .SSL_CTX_set_read_ahead;

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_get_read_ahead(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_GET_READ_AHEAD, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_read_ahead(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.config.c_long m)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SET_READ_AHEAD, m, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_get_max_cert_list(libressl_d.openssl.ossl_typ.SSL_CTX* ctx)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_GET_MAX_CERT_LIST, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_max_cert_list(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.config.c_long m)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SET_MAX_CERT_LIST, m, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_get_max_cert_list(libressl_d.openssl.ossl_typ.SSL* ssl)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_GET_MAX_CERT_LIST, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_max_cert_list(libressl_d.openssl.ossl_typ.SSL* ssl, core.stdc.config.c_long m)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_SET_MAX_CERT_LIST, m, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_max_send_fragment(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, core.stdc.config.c_long m)

	do
	{
		return .SSL_CTX_ctrl(ctx, .SSL_CTRL_SET_MAX_SEND_FRAGMENT, m, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_max_send_fragment(libressl_d.openssl.ossl_typ.SSL* ssl, core.stdc.config.c_long m)

	do
	{
		return .SSL_ctrl(ssl, .SSL_CTRL_SET_MAX_SEND_FRAGMENT, m, null);
	}

/* NB: the keylength is only applicable when is_export is true */
private alias SSL_CTX_set_tmp_rsa_callback_func = /* Temporary type */ extern (C) nothrow @nogc libressl_d.openssl.ossl_typ.RSA* function(libressl_d.openssl.ossl_typ.SSL* ssl, int is_export, int keylength);
void SSL_CTX_set_tmp_rsa_callback(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .SSL_CTX_set_tmp_rsa_callback_func cb);

private alias SSL_set_tmp_rsa_callback_func = /* Temporary type */ extern (C) nothrow @nogc libressl_d.openssl.ossl_typ.RSA* function(libressl_d.openssl.ossl_typ.SSL* ssl, int is_export, int keylength);
void SSL_set_tmp_rsa_callback(libressl_d.openssl.ossl_typ.SSL* ssl, .SSL_set_tmp_rsa_callback_func cb);

private alias SSL_CTX_set_tmp_dh_callback_func = /* Temporary type */ extern (C) nothrow @nogc libressl_d.openssl.ossl_typ.DH* function(libressl_d.openssl.ossl_typ.SSL* ssl, int is_export, int keylength);
void SSL_CTX_set_tmp_dh_callback(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .SSL_CTX_set_tmp_dh_callback_func dh);

private alias SSL_set_tmp_dh_callback_func = /* Temporary type */ extern (C) nothrow @nogc libressl_d.openssl.ossl_typ.DH* function(libressl_d.openssl.ossl_typ.SSL* ssl, int is_export, int keylength);
void SSL_set_tmp_dh_callback(libressl_d.openssl.ossl_typ.SSL* ssl, .SSL_set_tmp_dh_callback_func dh);

private alias SSL_CTX_set_tmp_ecdh_callback_func = /* Temporary type */ extern (C) nothrow @nogc libressl_d.openssl.ec.EC_KEY* function(libressl_d.openssl.ossl_typ.SSL* ssl, int is_export, int keylength);
void SSL_CTX_set_tmp_ecdh_callback(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, .SSL_CTX_set_tmp_ecdh_callback_func ecdh);

private alias SSL_set_tmp_ecdh_callback_func = /* Temporary type */ extern (C) nothrow @nogc libressl_d.openssl.ec.EC_KEY* function(libressl_d.openssl.ossl_typ.SSL* ssl, int is_export, int keylength);
void SSL_set_tmp_ecdh_callback(libressl_d.openssl.ossl_typ.SSL* ssl, .SSL_set_tmp_ecdh_callback_func ecdh);

size_t SSL_get_client_random(const (libressl_d.openssl.ossl_typ.SSL)* s, ubyte* out_, size_t max_out);
size_t SSL_get_server_random(const (libressl_d.openssl.ossl_typ.SSL)* s, ubyte* out_, size_t max_out);

const (void)* SSL_get_current_compression(libressl_d.openssl.ossl_typ.SSL* s);
const (void)* SSL_get_current_expansion(libressl_d.openssl.ossl_typ.SSL* s);

const (char)* SSL_COMP_get_name(const (void)* comp);
void* SSL_COMP_get_compression_methods();
int SSL_COMP_add_compression_method(int id, void* cm);

/* TLS extensions functions */
int SSL_set_session_ticket_ext(libressl_d.openssl.ossl_typ.SSL* s, void* ext_data, int ext_len);

int SSL_set_session_ticket_ext_cb(libressl_d.openssl.ossl_typ.SSL* s, .tls_session_ticket_ext_cb_fn cb, void* arg);

/* Pre-shared secret session resumption functions */
int SSL_set_session_secret_cb(libressl_d.openssl.ossl_typ.SSL* s, .tls_session_secret_cb_fn tls_session_secret_cb, void* arg);

void SSL_set_debug(libressl_d.openssl.ossl_typ.SSL* s, int debug_);
int SSL_cache_hit(libressl_d.openssl.ossl_typ.SSL* s);

/* What the "other" parameter contains in security callback */
/* Mask for type */
enum SSL_SECOP_OTHER_TYPE = 0xFFFF0000;
enum SSL_SECOP_OTHER_NONE = 0;
enum SSL_SECOP_OTHER_CIPHER = 1 << 16;
enum SSL_SECOP_OTHER_CURVE = 2 << 16;
enum SSL_SECOP_OTHER_DH = 3 << 16;
enum SSL_SECOP_OTHER_PKEY = 4 << 16;
enum SSL_SECOP_OTHER_SIGALG = 5 << 16;
enum SSL_SECOP_OTHER_CERT = 6 << 16;

/* Indicated operation refers to peer key or certificate */
enum SSL_SECOP_PEER = 0x1000;

/* Values for "op" parameter in security callback */

/* Called to filter ciphers */
/* Ciphers client supports */
enum SSL_SECOP_CIPHER_SUPPORTED = 1 | .SSL_SECOP_OTHER_CIPHER;

/* Cipher shared by client/server */
enum SSL_SECOP_CIPHER_SHARED = 2 | .SSL_SECOP_OTHER_CIPHER;

/* Sanity check of cipher server selects */
enum SSL_SECOP_CIPHER_CHECK = 3 | .SSL_SECOP_OTHER_CIPHER;

/* Curves supported by client */
enum SSL_SECOP_CURVE_SUPPORTED = 4 | .SSL_SECOP_OTHER_CURVE;

/* Curves shared by client/server */
enum SSL_SECOP_CURVE_SHARED = 5 | .SSL_SECOP_OTHER_CURVE;

/* Sanity check of curve server selects */
enum SSL_SECOP_CURVE_CHECK = 6 | .SSL_SECOP_OTHER_CURVE;
/* Temporary DH key */
/*
 * XXX: changed in OpenSSL e2b420fdd70 to (7 | SSL_SECOP_OTHER_PKEY)
 * Needs switching internal use of DH to EVP_PKEY. The code is not reachable
 * from outside the library as core.stdc.config.c_long as we do not expose the callback in the API.
 */
enum SSL_SECOP_TMP_DH = 7 | .SSL_SECOP_OTHER_DH;

/* SSL/TLS version */
enum SSL_SECOP_VERSION = 9 | .SSL_SECOP_OTHER_NONE;

/* Session tickets */
enum SSL_SECOP_TICKET = 10 | .SSL_SECOP_OTHER_NONE;

/* Supported signature algorithms sent to peer */
enum SSL_SECOP_SIGALG_SUPPORTED = 11 | .SSL_SECOP_OTHER_SIGALG;

/* Shared signature algorithm */
enum SSL_SECOP_SIGALG_SHARED = 12 | .SSL_SECOP_OTHER_SIGALG;

/* Sanity check signature algorithm allowed */
enum SSL_SECOP_SIGALG_CHECK = 13 | .SSL_SECOP_OTHER_SIGALG;

/* Used to get mask of supported public key signature algorithms */
enum SSL_SECOP_SIGALG_MASK = 14 | .SSL_SECOP_OTHER_SIGALG;

/* Use to see if compression is allowed */
enum SSL_SECOP_COMPRESSION = 15 | .SSL_SECOP_OTHER_NONE;

/* EE key in certificate */
enum SSL_SECOP_EE_KEY = 16 | .SSL_SECOP_OTHER_CERT;

/* CA key in certificate */
enum SSL_SECOP_CA_KEY = 17 | .SSL_SECOP_OTHER_CERT;

/* CA digest algorithm in certificate */
enum SSL_SECOP_CA_MD = 18 | .SSL_SECOP_OTHER_CERT;

/* Peer EE key in certificate */
enum SSL_SECOP_PEER_EE_KEY = .SSL_SECOP_EE_KEY | .SSL_SECOP_PEER;

/* Peer CA key in certificate */
enum SSL_SECOP_PEER_CA_KEY = .SSL_SECOP_CA_KEY | .SSL_SECOP_PEER;

/* Peer CA digest algorithm in certificate */
enum SSL_SECOP_PEER_CA_MD = .SSL_SECOP_CA_MD | .SSL_SECOP_PEER;

void SSL_set_security_level(libressl_d.openssl.ossl_typ.SSL* ssl, int level);
int SSL_get_security_level(const (libressl_d.openssl.ossl_typ.SSL)* ssl);

void SSL_CTX_set_security_level(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, int level);
int SSL_CTX_get_security_level(const (libressl_d.openssl.ossl_typ.SSL_CTX)* ctx);

version (LIBRESSL_HAS_QUIC_OR_LIBRESSL_INTERNAL) {
	/*
	 * QUIC integration.
	 *
	 * QUIC acts as an underlying transport for the TLS 1.3 handshake. The following
	 * functions allow a QUIC implementation to serve as the underlying transport as
	 * described in RFC 9001.
	 *
	 * When configured for QUIC, |SSL_do_handshake| will drive the handshake as
	 * before, but it will not use the configured |BIO|. It will call functions on
	 * |SSL_QUIC_METHOD| to configure secrets and send data. If data is needed from
	 * the peer, it will return |SSL_ERROR_WANT_READ|. As the caller receives data
	 * it can decrypt, it calls |SSL_provide_quic_data|. Subsequent
	 * |SSL_do_handshake| calls will then consume that data and progress the
	 * handshake. After the handshake is complete, the caller should continue to
	 * call |SSL_provide_quic_data| for any post-handshake data, followed by
	 * |SSL_process_quic_post_handshake| to process it. It is an error to call
	 * |SSL_peek|, |SSL_read| and |SSL_write| in QUIC.
	 *
	 * To avoid DoS attacks, the QUIC implementation must limit the amount of data
	 * being queued up. The implementation can call
	 * |SSL_quic_max_handshake_flight_len| to get the maximum buffer length at each
	 * encryption level.
	 *
	 * QUIC implementations must additionally configure transport parameters with
	 * |SSL_set_quic_transport_params|. |SSL_get_peer_quic_transport_params| may be
	 * used to query the value received from the peer. This extension is handled
	 * as an opaque byte string, which the caller is responsible for serializing
	 * and parsing. See RFC 9000 section 7.4 for further details.
	 */

	/**
	 * ssl_encryption_level_t specifies the QUIC encryption level used to transmit
	 * handshake messages.
	 */
	enum ssl_encryption_level_t
	{
		ssl_encryption_initial = 0,
		ssl_encryption_early_data,
		ssl_encryption_handshake,
		ssl_encryption_application,
	}

	////Declaration name in C language
	enum
	{
		ssl_encryption_initial = .ssl_encryption_level_t.ssl_encryption_initial,
		ssl_encryption_early_data = .ssl_encryption_level_t.ssl_encryption_early_data,
		ssl_encryption_handshake = .ssl_encryption_level_t.ssl_encryption_handshake,
		ssl_encryption_application = .ssl_encryption_level_t.ssl_encryption_application,
	}

	alias OSSL_ENCRYPTION_LEVEL = .ssl_encryption_level_t;

	/**
	 * ssl_quic_method_st (aka |SSL_QUIC_METHOD|) describes custom QUIC hooks.
	 *
	 * Note that we provide both the new (BoringSSL) secrets interface
	 * (set_read_secret/set_write_secret) along with the old interface
	 * (set_encryption_secrets), which quictls is still using.
	 *
	 * Since some consumers fail to use named initialisers, the order of these
	 * functions is important. Hopefully all of these consumers use the old version.
	 */
	struct ssl_quic_method_st
	{
		/**
		 * set_encryption_secrets configures the read and write secrets for the
		 * given encryption level. This function will always be called before an
		 * encryption level other than |ssl_encryption_initial| is used.
		 *
		 * When reading packets at a given level, the QUIC implementation must
		 * send ACKs at the same level, so this function provides read and write
		 * secrets together. The exception is |ssl_encryption_early_data|, where
		 * secrets are only available in the client to server direction. The
		 * other secret will be null. The server acknowledges such data at
		 * |ssl_encryption_application|, which will be configured in the same
		 * |SSL_do_handshake| call.
		 *
		 * This function should use |SSL_get_current_cipher| to determine the TLS
		 * cipher suite.
		 */
		int function(libressl_d.openssl.ossl_typ.SSL* ssl, .ssl_encryption_level_t level, const (core.stdc.stdint.uint8_t)* read_secret, const (core.stdc.stdint.uint8_t)* write_secret, size_t secret_len) set_encryption_secrets;

		/**
		 * add_handshake_data adds handshake data to the current flight at the
		 * given encryption level. It returns one on success and zero on error.
		 * Callers should defer writing data to the network until |flush_flight|
		 * to better pack QUIC packets into transport datagrams.
		 *
		 * If |level| is not |ssl_encryption_initial|, this function will not be
		 * called before |level| is initialized with |set_write_secret|.
		 */
		int function(libressl_d.openssl.ossl_typ.SSL* ssl, .ssl_encryption_level_t level, const (core.stdc.stdint.uint8_t)* data, size_t len) add_handshake_data;

		/**
		 * flush_flight is called when the current flight is complete and should
		 * be written to the transport. Note a flight may contain data at
		 * several encryption levels. It returns one on success and zero on
		 * error.
		 */
		int function(libressl_d.openssl.ossl_typ.SSL* ssl) flush_flight;

		/**
		 * send_alert sends a fatal alert at the specified encryption level. It
		 * returns one on success and zero on error.
		 *
		 * If |level| is not |ssl_encryption_initial|, this function will not be
		 * called before |level| is initialized with |set_write_secret|.
		 */
		int function(libressl_d.openssl.ossl_typ.SSL* ssl, .ssl_encryption_level_t level, core.stdc.stdint.uint8_t alert) send_alert;

		/**
		 * set_read_secret configures the read secret and cipher suite for the
		 * given encryption level. It returns one on success and zero to
		 * terminate the handshake with an error. It will be called at most once
		 * per encryption level.
		 *
		 * Read keys will not be released before QUIC may use them. Once a level
		 * has been initialized, QUIC may begin processing data from it.
		 * Handshake data should be passed to |SSL_provide_quic_data| and
		 * application data (if |level| is |ssl_encryption_early_data| or
		 * |ssl_encryption_application|) may be processed according to the rules
		 * of the QUIC protocol.
		 */
		int function(libressl_d.openssl.ossl_typ.SSL* ssl, .ssl_encryption_level_t level, const (.SSL_CIPHER)* cipher, const (core.stdc.stdint.uint8_t)* secret, size_t secret_len) set_read_secret;

		/**
		 * set_write_secret behaves like |set_read_secret| but configures the
		 * write secret and cipher suite for the given encryption level. It will
		 * be called at most once per encryption level.
		 *
		 * Write keys will not be released before QUIC may use them. If |level|
		 * is |ssl_encryption_early_data| or |ssl_encryption_application|, QUIC
		 * may begin sending application data at |level|.
		 */
		int function(libressl_d.openssl.ossl_typ.SSL* ssl, .ssl_encryption_level_t level, const (.SSL_CIPHER)* cipher, const (core.stdc.stdint.uint8_t)* secret, size_t secret_len) set_write_secret;
	}

	alias SSL_QUIC_METHOD = .ssl_quic_method_st;

	/**
	 * SSL_CTX_set_quic_method configures the QUIC hooks. This should only be
	 * configured with a minimum version of TLS 1.3. |quic_method| must remain valid
	 * for the lifetime of |ctx|. It returns one on success and zero on error.
	 */
	int SSL_CTX_set_quic_method(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, const (.SSL_QUIC_METHOD)* quic_method);

	/**
	 * SSL_set_quic_method configures the QUIC hooks. This should only be
	 * configured with a minimum version of TLS 1.3. |quic_method| must remain valid
	 * for the lifetime of |ssl|. It returns one on success and zero on error.
	 */
	int SSL_set_quic_method(libressl_d.openssl.ossl_typ.SSL* ssl, const (.SSL_QUIC_METHOD)* quic_method);

	/**
	 * SSL_is_quic returns true if an SSL has been configured for use with QUIC.
	 */
	int SSL_is_quic(const (libressl_d.openssl.ossl_typ.SSL)* ssl);

	/**
	 * SSL_quic_max_handshake_flight_len returns returns the maximum number of bytes
	 * that may be received at the given encryption level. This function should be
	 * used to limit buffering in the QUIC implementation. See RFC 9000 section 7.5.
	 */
	size_t SSL_quic_max_handshake_flight_len(const (libressl_d.openssl.ossl_typ.SSL)* ssl, .ssl_encryption_level_t level);

	/**
	 * SSL_quic_read_level returns the current read encryption level.
	 */
	.ssl_encryption_level_t SSL_quic_read_level(const (libressl_d.openssl.ossl_typ.SSL)* ssl);

	/**
	 * SSL_quic_write_level returns the current write encryption level.
	 */
	.ssl_encryption_level_t SSL_quic_write_level(const (libressl_d.openssl.ossl_typ.SSL)* ssl);

	/**
	 * SSL_provide_quic_data provides data from QUIC at a particular encryption
	 * level |level|. It returns one on success and zero on error. Note this
	 * function will return zero if the handshake is not expecting data from |level|
	 * at this time. The QUIC implementation should then close the connection with
	 * an error.
	 */
	int SSL_provide_quic_data(libressl_d.openssl.ossl_typ.SSL* ssl, .ssl_encryption_level_t level, const (core.stdc.stdint.uint8_t)* data, size_t len);

	/**
	 * SSL_process_quic_post_handshake processes any data that QUIC has provided
	 * after the handshake has completed. This includes NewSessionTicket messages
	 * sent by the server. It returns one on success and zero on error.
	 */
	int SSL_process_quic_post_handshake(libressl_d.openssl.ossl_typ.SSL* ssl);

	/**
	 * SSL_set_quic_transport_params configures |ssl| to send |params| (of length
	 * |params_len|) in the quic_transport_parameters extension in either the
	 * ClientHello or EncryptedExtensions handshake message. It is an error to set
	 * transport parameters if |ssl| is not configured for QUIC. The buffer pointed
	 * to by |params| only need be valid for the duration of the call to this
	 * function. This function returns 1 on success and 0 on failure.
	 */
	int SSL_set_quic_transport_params(libressl_d.openssl.ossl_typ.SSL* ssl, const (core.stdc.stdint.uint8_t)* params, size_t params_len);

	/**
	 * SSL_get_peer_quic_transport_params provides the caller with the value of the
	 * quic_transport_parameters extension sent by the peer. A pointer to the buffer
	 * containing the TransportParameters will be put in |*out_params|, and its
	 * length in |*params_len|. This buffer will be valid for the lifetime of the
	 * |SSL|. If no params were received from the peer, |*out_params_len| will be 0.
	 */
	void SSL_get_peer_quic_transport_params(const (libressl_d.openssl.ossl_typ.SSL)* ssl, const (core.stdc.stdint.uint8_t)** out_params, size_t* out_params_len);

	/**
	 * SSL_set_quic_use_legacy_codepoint configures whether to use the legacy QUIC
	 * extension codepoint 0xFFa5 as opposed to the official value 57. This is
	 * unsupported in LibreSSL.
	 */
	void SSL_set_quic_use_legacy_codepoint(libressl_d.openssl.ossl_typ.SSL* ssl, int use_legacy);
}

void ERR_load_SSL_strings();

/* Error codes for the SSL functions. */

/* Function codes. */
enum SSL_F_CLIENT_CERTIFICATE = 100;
enum SSL_F_CLIENT_FINISHED = 167;
enum SSL_F_CLIENT_HELLO = 101;
enum SSL_F_CLIENT_MASTER_KEY = 102;
enum SSL_F_D2I_SSL_SESSION = 103;
enum SSL_F_DO_DTLS1_WRITE = 245;
enum SSL_F_DO_SSL3_WRITE = 104;
enum SSL_F_DTLS1_ACCEPT = 246;
enum SSL_F_DTLS1_ADD_CERT_TO_BUF = 295;
enum SSL_F_DTLS1_BUFFER_RECORD = 247;
enum SSL_F_DTLS1_CHECK_TIMEOUT_NUM = 316;
enum SSL_F_DTLS1_CLIENT_HELLO = 248;
enum SSL_F_DTLS1_CONNECT = 249;
enum SSL_F_DTLS1_ENC = 250;
enum SSL_F_DTLS1_GET_HELLO_VERIFY = 251;
enum SSL_F_DTLS1_GET_MESSAGE = 252;
enum SSL_F_DTLS1_GET_MESSAGE_FRAGMENT = 253;
enum SSL_F_DTLS1_GET_RECORD = 254;
enum SSL_F_DTLS1_HANDLE_TIMEOUT = 297;
enum SSL_F_DTLS1_HEARTBEAT = 305;
enum SSL_F_DTLS1_OUTPUT_CERT_CHAIN = 255;
enum SSL_F_DTLS1_PREPROCESS_FRAGMENT = 288;
enum SSL_F_DTLS1_PROCESS_OUT_OF_SEQ_MESSAGE = 256;
enum SSL_F_DTLS1_PROCESS_RECORD = 257;
enum SSL_F_DTLS1_READ_BYTES = 258;
enum SSL_F_DTLS1_READ_FAILED = 259;
enum SSL_F_DTLS1_SEND_CERTIFICATE_REQUEST = 260;
enum SSL_F_DTLS1_SEND_CLIENT_CERTIFICATE = 261;
enum SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE = 262;
enum SSL_F_DTLS1_SEND_CLIENT_VERIFY = 263;
enum SSL_F_DTLS1_SEND_HELLO_VERIFY_REQUEST = 264;
enum SSL_F_DTLS1_SEND_SERVER_CERTIFICATE = 265;
enum SSL_F_DTLS1_SEND_SERVER_HELLO = 266;
enum SSL_F_DTLS1_SEND_SERVER_KEY_EXCHANGE = 267;
enum SSL_F_DTLS1_WRITE_APP_DATA_BYTES = 268;
enum SSL_F_GET_CLIENT_FINISHED = 105;
enum SSL_F_GET_CLIENT_HELLO = 106;
enum SSL_F_GET_CLIENT_MASTER_KEY = 107;
enum SSL_F_GET_SERVER_FINISHED = 108;
enum SSL_F_GET_SERVER_HELLO = 109;
enum SSL_F_GET_SERVER_VERIFY = 110;
enum SSL_F_I2D_SSL_SESSION = 111;
enum SSL_F_READ_N = 112;
enum SSL_F_REQUEST_CERTIFICATE = 113;
enum SSL_F_SERVER_FINISH = 239;
enum SSL_F_SERVER_HELLO = 114;
enum SSL_F_SERVER_VERIFY = 240;
enum SSL_F_SSL23_ACCEPT = 115;
enum SSL_F_SSL23_CLIENT_HELLO = 116;
enum SSL_F_SSL23_CONNECT = 117;
enum SSL_F_SSL23_GET_CLIENT_HELLO = 118;
enum SSL_F_SSL23_GET_SERVER_HELLO = 119;
enum SSL_F_SSL23_PEEK = 237;
enum SSL_F_SSL23_READ = 120;
enum SSL_F_SSL23_WRITE = 121;
enum SSL_F_SSL2_ACCEPT = 122;
enum SSL_F_SSL2_CONNECT = 123;
enum SSL_F_SSL2_ENC_INIT = 124;
enum SSL_F_SSL2_GENERATE_KEY_MATERIAL = 241;
enum SSL_F_SSL2_PEEK = 234;
enum SSL_F_SSL2_READ = 125;
enum SSL_F_SSL2_READ_INTERNAL = 236;
enum SSL_F_SSL2_SET_CERTIFICATE = 126;
enum SSL_F_SSL2_WRITE = 127;
enum SSL_F_SSL3_ACCEPT = 128;
enum SSL_F_SSL3_ADD_CERT_TO_BUF = 296;
enum SSL_F_SSL3_CALLBACK_CTRL = 233;
enum SSL_F_SSL3_CHANGE_CIPHER_STATE = 129;
enum SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM = 130;
enum SSL_F_SSL3_CHECK_CLIENT_HELLO = 304;
enum SSL_F_SSL3_CLIENT_HELLO = 131;
enum SSL_F_SSL3_CONNECT = 132;
enum SSL_F_SSL3_CTRL = 213;
enum SSL_F_SSL3_CTX_CTRL = 133;
enum SSL_F_SSL3_DIGEST_CACHED_RECORDS = 293;
enum SSL_F_SSL3_DO_CHANGE_CIPHER_SPEC = 292;
enum SSL_F_SSL3_ENC = 134;
enum SSL_F_SSL3_GENERATE_KEY_BLOCK = 238;
enum SSL_F_SSL3_GET_CERTIFICATE_REQUEST = 135;
enum SSL_F_SSL3_GET_CERT_STATUS = 289;
enum SSL_F_SSL3_GET_CERT_VERIFY = 136;
enum SSL_F_SSL3_GET_CLIENT_CERTIFICATE = 137;
enum SSL_F_SSL3_GET_CLIENT_HELLO = 138;
enum SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE = 139;
enum SSL_F_SSL3_GET_FINISHED = 140;
enum SSL_F_SSL3_GET_KEY_EXCHANGE = 141;
enum SSL_F_SSL3_GET_MESSAGE = 142;
enum SSL_F_SSL3_GET_NEW_SESSION_TICKET = 283;
enum SSL_F_SSL3_GET_NEXT_PROTO = 306;
enum SSL_F_SSL3_GET_RECORD = 143;
enum SSL_F_SSL3_GET_SERVER_CERTIFICATE = 144;
enum SSL_F_SSL3_GET_SERVER_DONE = 145;
enum SSL_F_SSL3_GET_SERVER_HELLO = 146;
enum SSL_F_SSL3_HANDSHAKE_MAC = 285;
enum SSL_F_SSL3_NEW_SESSION_TICKET = 287;
enum SSL_F_SSL3_OUTPUT_CERT_CHAIN = 147;
enum SSL_F_SSL3_PEEK = 235;
enum SSL_F_SSL3_READ_BYTES = 148;
enum SSL_F_SSL3_READ_N = 149;
enum SSL_F_SSL3_SEND_CERTIFICATE_REQUEST = 150;
enum SSL_F_SSL3_SEND_CLIENT_CERTIFICATE = 151;
enum SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE = 152;
enum SSL_F_SSL3_SEND_CLIENT_VERIFY = 153;
enum SSL_F_SSL3_SEND_SERVER_CERTIFICATE = 154;
enum SSL_F_SSL3_SEND_SERVER_HELLO = 242;
enum SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE = 155;
enum SSL_F_SSL3_SETUP_KEY_BLOCK = 157;
enum SSL_F_SSL3_SETUP_READ_BUFFER = 156;
enum SSL_F_SSL3_SETUP_WRITE_BUFFER = 291;
enum SSL_F_SSL3_WRITE_BYTES = 158;
enum SSL_F_SSL3_WRITE_PENDING = 159;
enum SSL_F_SSL_ADD_CLIENTHELLO_RENEGOTIATE_EXT = 298;
enum SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT = 277;
enum SSL_F_SSL_ADD_CLIENTHELLO_USE_SRTP_EXT = 307;
enum SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK = 215;
enum SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK = 216;
enum SSL_F_SSL_ADD_SERVERHELLO_RENEGOTIATE_EXT = 299;
enum SSL_F_SSL_ADD_SERVERHELLO_TLSEXT = 278;
enum SSL_F_SSL_ADD_SERVERHELLO_USE_SRTP_EXT = 308;
enum SSL_F_SSL_BAD_METHOD = 160;
enum SSL_F_SSL_BYTES_TO_CIPHER_LIST = 161;
enum SSL_F_SSL_CERT_DUP = 221;
enum SSL_F_SSL_CERT_INST = 222;
enum SSL_F_SSL_CERT_INSTANTIATE = 214;
enum SSL_F_SSL_CERT_NEW = 162;
enum SSL_F_SSL_CHECK_PRIVATE_KEY = 163;
enum SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT = 280;
enum SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG = 279;
enum SSL_F_SSL_CIPHER_PROCESS_RULESTR = 230;
enum SSL_F_SSL_CIPHER_STRENGTH_SORT = 231;
enum SSL_F_SSL_CLEAR = 164;
enum SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD = 165;
enum SSL_F_SSL_CREATE_CIPHER_LIST = 166;
enum SSL_F_SSL_CTRL = 232;
enum SSL_F_SSL_CTX_CHECK_PRIVATE_KEY = 168;
enum SSL_F_SSL_CTX_MAKE_PROFILES = 309;
enum SSL_F_SSL_CTX_NEW = 169;
enum SSL_F_SSL_CTX_SET_CIPHER_LIST = 269;
enum SSL_F_SSL_CTX_SET_CLIENT_CERT_ENGINE = 290;
enum SSL_F_SSL_CTX_SET_PURPOSE = 226;
enum SSL_F_SSL_CTX_SET_SESSION_ID_CONTEXT = 219;
enum SSL_F_SSL_CTX_SET_SSL_VERSION = 170;
enum SSL_F_SSL_CTX_SET_TRUST = 229;
enum SSL_F_SSL_CTX_USE_CERTIFICATE = 171;
enum SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1 = 172;
enum SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE = 220;
enum SSL_F_SSL_CTX_USE_CERTIFICATE_FILE = 173;
enum SSL_F_SSL_CTX_USE_PRIVATEKEY = 174;
enum SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1 = 175;
enum SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE = 176;
enum SSL_F_SSL_CTX_USE_PSK_IDENTITY_HINT = 272;
enum SSL_F_SSL_CTX_USE_RSAPRIVATEKEY = 177;
enum SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1 = 178;
enum SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE = 179;
enum SSL_F_SSL_DO_HANDSHAKE = 180;
enum SSL_F_SSL_GET_NEW_SESSION = 181;
enum SSL_F_SSL_GET_PREV_SESSION = 217;
enum SSL_F_SSL_GET_SERVER_SEND_CERT = 182;
enum SSL_F_SSL_GET_SERVER_SEND_PKEY = 317;
enum SSL_F_SSL_GET_SIGN_PKEY = 183;
enum SSL_F_SSL_INIT_WBIO_BUFFER = 184;
enum SSL_F_SSL_LOAD_CLIENT_CA_FILE = 185;
enum SSL_F_SSL_NEW = 186;
enum SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT = 300;
enum SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT = 302;
enum SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT = 310;
enum SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT = 301;
enum SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT = 303;
enum SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT = 311;
enum SSL_F_SSL_PEEK = 270;
enum SSL_F_SSL_PREPARE_CLIENTHELLO_TLSEXT = 281;
enum SSL_F_SSL_PREPARE_SERVERHELLO_TLSEXT = 282;
enum SSL_F_SSL_READ = 223;
enum SSL_F_SSL_RSA_PRIVATE_DECRYPT = 187;
enum SSL_F_SSL_RSA_PUBLIC_ENCRYPT = 188;
enum SSL_F_SSL_SESSION_NEW = 189;
enum SSL_F_SSL_SESSION_PRINT_FP = 190;
enum SSL_F_SSL_SESSION_SET1_ID_CONTEXT = 312;
enum SSL_F_SSL_SESS_CERT_NEW = 225;
enum SSL_F_SSL_SET_CERT = 191;
enum SSL_F_SSL_SET_CIPHER_LIST = 271;
enum SSL_F_SSL_SET_FD = 192;
enum SSL_F_SSL_SET_PKEY = 193;
enum SSL_F_SSL_SET_PURPOSE = 227;
enum SSL_F_SSL_SET_RFD = 194;
enum SSL_F_SSL_SET_SESSION = 195;
enum SSL_F_SSL_SET_SESSION_ID_CONTEXT = 218;
enum SSL_F_SSL_SET_SESSION_TICKET_EXT = 294;
enum SSL_F_SSL_SET_TRUST = 228;
enum SSL_F_SSL_SET_WFD = 196;
enum SSL_F_SSL_SHUTDOWN = 224;
enum SSL_F_SSL_SRP_CTX_INIT = 313;
enum SSL_F_SSL_UNDEFINED_CONST_FUNCTION = 243;
enum SSL_F_SSL_UNDEFINED_FUNCTION = 197;
enum SSL_F_SSL_UNDEFINED_VOID_FUNCTION = 244;
enum SSL_F_SSL_USE_CERTIFICATE = 198;
enum SSL_F_SSL_USE_CERTIFICATE_ASN1 = 199;
enum SSL_F_SSL_USE_CERTIFICATE_FILE = 200;
enum SSL_F_SSL_USE_PRIVATEKEY = 201;
enum SSL_F_SSL_USE_PRIVATEKEY_ASN1 = 202;
enum SSL_F_SSL_USE_PRIVATEKEY_FILE = 203;
enum SSL_F_SSL_USE_PSK_IDENTITY_HINT = 273;
enum SSL_F_SSL_USE_RSAPRIVATEKEY = 204;
enum SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1 = 205;
enum SSL_F_SSL_USE_RSAPRIVATEKEY_FILE = 206;
enum SSL_F_SSL_VERIFY_CERT_CHAIN = 207;
enum SSL_F_SSL_WRITE = 208;
enum SSL_F_TLS1_AEAD_CTX_INIT = 339;
enum SSL_F_TLS1_CERT_VERIFY_MAC = 286;
enum SSL_F_TLS1_CHANGE_CIPHER_STATE = 209;
enum SSL_F_TLS1_CHANGE_CIPHER_STATE_AEAD = 340;
enum SSL_F_TLS1_CHANGE_CIPHER_STATE_CIPHER = 338;
enum SSL_F_TLS1_CHECK_SERVERHELLO_TLSEXT = 274;
enum SSL_F_TLS1_ENC = 210;
enum SSL_F_TLS1_EXPORT_KEYING_MATERIAL = 314;
enum SSL_F_TLS1_HEARTBEAT = 315;
enum SSL_F_TLS1_PREPARE_CLIENTHELLO_TLSEXT = 275;
enum SSL_F_TLS1_PREPARE_SERVERHELLO_TLSEXT = 276;
enum SSL_F_TLS1_PRF = 284;
enum SSL_F_TLS1_SETUP_KEY_BLOCK = 211;
enum SSL_F_WRITE_PENDING = 212;

/* Reason codes. */
enum SSL_R_APP_DATA_IN_HANDSHAKE = 100;
enum SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT = 272;
enum SSL_R_BAD_ALERT_RECORD = 101;
enum SSL_R_BAD_AUTHENTICATION_TYPE = 102;
enum SSL_R_BAD_CHANGE_CIPHER_SPEC = 103;
enum SSL_R_BAD_CHECKSUM = 104;
enum SSL_R_BAD_DATA_RETURNED_BY_CALLBACK = 106;
enum SSL_R_BAD_DECOMPRESSION = 107;
enum SSL_R_BAD_DH_G_LENGTH = 108;
enum SSL_R_BAD_DH_PUB_KEY_LENGTH = 109;
enum SSL_R_BAD_DH_P_LENGTH = 110;
enum SSL_R_BAD_DIGEST_LENGTH = 111;
enum SSL_R_BAD_DSA_SIGNATURE = 112;
enum SSL_R_BAD_ECC_CERT = 304;
enum SSL_R_BAD_ECDSA_SIGNATURE = 305;
enum SSL_R_BAD_ECPOINT = 306;
enum SSL_R_BAD_HANDSHAKE_LENGTH = 332;
enum SSL_R_BAD_HELLO_REQUEST = 105;
enum SSL_R_BAD_LENGTH = 271;
enum SSL_R_BAD_MAC_DECODE = 113;
enum SSL_R_BAD_MAC_LENGTH = 333;
enum SSL_R_BAD_MESSAGE_TYPE = 114;
enum SSL_R_BAD_PACKET_LENGTH = 115;
enum SSL_R_BAD_PROTOCOL_VERSION_NUMBER = 116;
enum SSL_R_BAD_PSK_IDENTITY_HINT_LENGTH = 316;
enum SSL_R_BAD_RESPONSE_ARGUMENT = 117;
enum SSL_R_BAD_RSA_DECRYPT = 118;
enum SSL_R_BAD_RSA_ENCRYPT = 119;
enum SSL_R_BAD_RSA_E_LENGTH = 120;
enum SSL_R_BAD_RSA_MODULUS_LENGTH = 121;
enum SSL_R_BAD_RSA_SIGNATURE = 122;
enum SSL_R_BAD_SIGNATURE = 123;
enum SSL_R_BAD_SRP_A_LENGTH = 347;
enum SSL_R_BAD_SRP_B_LENGTH = 348;
enum SSL_R_BAD_SRP_G_LENGTH = 349;
enum SSL_R_BAD_SRP_N_LENGTH = 350;
enum SSL_R_BAD_SRP_S_LENGTH = 351;
enum SSL_R_BAD_SRTP_MKI_VALUE = 352;
enum SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST = 353;
enum SSL_R_BAD_SSL_FILETYPE = 124;
enum SSL_R_BAD_SSL_SESSION_ID_LENGTH = 125;
enum SSL_R_BAD_STATE = 126;
enum SSL_R_BAD_WRITE_RETRY = 127;
enum SSL_R_BIO_NOT_SET = 128;
enum SSL_R_BLOCK_CIPHER_PAD_IS_WRONG = 129;
enum SSL_R_BN_LIB = 130;
enum SSL_R_CA_DN_LENGTH_MISMATCH = 131;
enum SSL_R_CA_DN_TOO_LONG = 132;
enum SSL_R_CA_KEY_TOO_SMALL = 397;
enum SSL_R_CA_MD_TOO_WEAK = 398;
enum SSL_R_CCS_RECEIVED_EARLY = 133;
enum SSL_R_CERTIFICATE_VERIFY_FAILED = 134;
enum SSL_R_CERT_LENGTH_MISMATCH = 135;
enum SSL_R_CHALLENGE_IS_DIFFERENT = 136;
enum SSL_R_CIPHER_CODE_WRONG_LENGTH = 137;
enum SSL_R_CIPHER_COMPRESSION_UNAVAILABLE = 371;
enum SSL_R_CIPHER_OR_HASH_UNAVAILABLE = 138;
enum SSL_R_CIPHER_TABLE_SRC_ERROR = 139;
enum SSL_R_CLIENTHELLO_TLSEXT = 226;
enum SSL_R_COMPRESSED_LENGTH_TOO_LONG = 140;
enum SSL_R_COMPRESSION_DISABLED = 343;
enum SSL_R_COMPRESSION_FAILURE = 141;
enum SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE = 307;
enum SSL_R_COMPRESSION_LIBRARY_ERROR = 142;
enum SSL_R_CONNECTION_ID_IS_DIFFERENT = 143;
enum SSL_R_CONNECTION_TYPE_NOT_SET = 144;
enum SSL_R_COOKIE_MISMATCH = 308;
enum SSL_R_DATA_BETWEEN_CCS_AND_FINISHED = 145;
enum SSL_R_DATA_LENGTH_TOO_LONG = 146;
enum SSL_R_DECRYPTION_FAILED = 147;
enum SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC = 281;
enum SSL_R_DH_KEY_TOO_SMALL = 394;
enum SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG = 148;
enum SSL_R_DIGEST_CHECK_FAILED = 149;
enum SSL_R_DTLS_MESSAGE_TOO_BIG = 334;
enum SSL_R_DUPLICATE_COMPRESSION_ID = 309;
enum SSL_R_ECC_CERT_NOT_FOR_KEY_AGREEMENT = 317;
enum SSL_R_ECC_CERT_NOT_FOR_SIGNING = 318;
enum SSL_R_ECC_CERT_SHOULD_HAVE_RSA_SIGNATURE = 322;
enum SSL_R_ECC_CERT_SHOULD_HAVE_SHA1_SIGNATURE = 323;
enum SSL_R_ECGROUP_TOO_LARGE_FOR_CIPHER = 310;
enum SSL_R_EE_KEY_TOO_SMALL = 399;
enum SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST = 354;
enum SSL_R_ENCRYPTED_LENGTH_TOO_LONG = 150;
enum SSL_R_ERROR_GENERATING_TMP_RSA_KEY = 282;
enum SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST = 151;
enum SSL_R_EXCESSIVE_MESSAGE_SIZE = 152;
enum SSL_R_EXTRA_DATA_IN_MESSAGE = 153;
enum SSL_R_GOT_A_FIN_BEFORE_A_CCS = 154;
enum SSL_R_GOT_NEXT_PROTO_BEFORE_A_CCS = 355;
enum SSL_R_GOT_NEXT_PROTO_WITHOUT_EXTENSION = 356;
enum SSL_R_HTTPS_PROXY_REQUEST = 155;
enum SSL_R_HTTP_REQUEST = 156;
enum SSL_R_ILLEGAL_PADDING = 283;
enum SSL_R_INAPPROPRIATE_FALLBACK = 373;
enum SSL_R_INCONSISTENT_COMPRESSION = 340;
enum SSL_R_INVALID_CHALLENGE_LENGTH = 158;
enum SSL_R_INVALID_COMMAND = 280;
enum SSL_R_INVALID_COMPRESSION_ALGORITHM = 341;
enum SSL_R_INVALID_PURPOSE = 278;
enum SSL_R_INVALID_SRP_USERNAME = 357;
enum SSL_R_INVALID_STATUS_RESPONSE = 328;
enum SSL_R_INVALID_TICKET_KEYS_LENGTH = 325;
enum SSL_R_INVALID_TRUST = 279;
enum SSL_R_KEY_ARG_TOO_LONG = 284;
enum SSL_R_KRB5 = 285;
enum SSL_R_KRB5_C_CC_PRINC = 286;
enum SSL_R_KRB5_C_GET_CRED = 287;
enum SSL_R_KRB5_C_INIT = 288;
enum SSL_R_KRB5_C_MK_REQ = 289;
enum SSL_R_KRB5_S_BAD_TICKET = 290;
enum SSL_R_KRB5_S_INIT = 291;
enum SSL_R_KRB5_S_RD_REQ = 292;
enum SSL_R_KRB5_S_TKT_EXPIRED = 293;
enum SSL_R_KRB5_S_TKT_NYV = 294;
enum SSL_R_KRB5_S_TKT_SKEW = 295;
enum SSL_R_LENGTH_MISMATCH = 159;
enum SSL_R_LENGTH_TOO_SHORT = 160;
enum SSL_R_LIBRARY_BUG = 274;
enum SSL_R_LIBRARY_HAS_NO_CIPHERS = 161;
enum SSL_R_MESSAGE_TOO_LONG = 296;
enum SSL_R_MISSING_DH_DSA_CERT = 162;
enum SSL_R_MISSING_DH_KEY = 163;
enum SSL_R_MISSING_DH_RSA_CERT = 164;
enum SSL_R_MISSING_DSA_SIGNING_CERT = 165;
enum SSL_R_MISSING_EXPORT_TMP_DH_KEY = 166;
enum SSL_R_MISSING_EXPORT_TMP_RSA_KEY = 167;
enum SSL_R_MISSING_RSA_CERTIFICATE = 168;
enum SSL_R_MISSING_RSA_ENCRYPTING_CERT = 169;
enum SSL_R_MISSING_RSA_SIGNING_CERT = 170;
enum SSL_R_MISSING_SRP_PARAM = 358;
enum SSL_R_MISSING_TMP_DH_KEY = 171;
enum SSL_R_MISSING_TMP_ECDH_KEY = 311;
enum SSL_R_MISSING_TMP_RSA_KEY = 172;
enum SSL_R_MISSING_TMP_RSA_PKEY = 173;
enum SSL_R_MISSING_VERIFY_MESSAGE = 174;
enum SSL_R_MULTIPLE_SGC_RESTARTS = 346;
enum SSL_R_NON_SSLV2_INITIAL_PACKET = 175;
enum SSL_R_NO_APPLICATION_PROTOCOL = 235;
enum SSL_R_NO_CERTIFICATES_RETURNED = 176;
enum SSL_R_NO_CERTIFICATE_ASSIGNED = 177;
enum SSL_R_NO_CERTIFICATE_RETURNED = 178;
enum SSL_R_NO_CERTIFICATE_SET = 179;
enum SSL_R_NO_CERTIFICATE_SPECIFIED = 180;
enum SSL_R_NO_CIPHERS_AVAILABLE = 181;
enum SSL_R_NO_CIPHERS_PASSED = 182;
enum SSL_R_NO_CIPHERS_SPECIFIED = 183;
enum SSL_R_NO_CIPHER_LIST = 184;
enum SSL_R_NO_CIPHER_MATCH = 185;
enum SSL_R_NO_CLIENT_CERT_METHOD = 331;
enum SSL_R_NO_CLIENT_CERT_RECEIVED = 186;
enum SSL_R_NO_COMPRESSION_SPECIFIED = 187;
enum SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER = 330;
enum SSL_R_NO_METHOD_SPECIFIED = 188;
enum SSL_R_NO_PRIVATEKEY = 189;
enum SSL_R_NO_PRIVATE_KEY_ASSIGNED = 190;
enum SSL_R_NO_PROTOCOLS_AVAILABLE = 191;
enum SSL_R_NO_PUBLICKEY = 192;
enum SSL_R_NO_RENEGOTIATION = 339;
enum SSL_R_NO_REQUIRED_DIGEST = 324;
enum SSL_R_NO_SHARED_CIPHER = 193;
enum SSL_R_NO_SRTP_PROFILES = 359;
enum SSL_R_NO_VERIFY_CALLBACK = 194;
enum SSL_R_NULL_SSL_CTX = 195;
enum SSL_R_NULL_SSL_METHOD_PASSED = 196;
enum SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED = 197;
enum SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED = 344;
enum SSL_R_ONLY_TLS_ALLOWED_IN_FIPS_MODE = 297;
enum SSL_R_PACKET_LENGTH_TOO_LONG = 198;
enum SSL_R_PARSE_TLSEXT = 227;
enum SSL_R_PATH_TOO_LONG = 270;
enum SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE = 199;
enum SSL_R_PEER_ERROR = 200;
enum SSL_R_PEER_ERROR_CERTIFICATE = 201;
enum SSL_R_PEER_ERROR_NO_CERTIFICATE = 202;
enum SSL_R_PEER_ERROR_NO_CIPHER = 203;
enum SSL_R_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE = 204;
enum SSL_R_PRE_MAC_LENGTH_TOO_LONG = 205;
enum SSL_R_PROBLEMS_MAPPING_CIPHER_FUNCTIONS = 206;
enum SSL_R_PROTOCOL_IS_SHUTDOWN = 207;
enum SSL_R_PSK_IDENTITY_NOT_FOUND = 223;
enum SSL_R_PSK_NO_CLIENT_CB = 224;
enum SSL_R_PSK_NO_SERVER_CB = 225;
enum SSL_R_PUBLIC_KEY_ENCRYPT_ERROR = 208;
enum SSL_R_PUBLIC_KEY_IS_NOT_RSA = 209;
enum SSL_R_PUBLIC_KEY_NOT_RSA = 210;
enum SSL_R_READ_BIO_NOT_SET = 211;
enum SSL_R_READ_TIMEOUT_EXPIRED = 312;
enum SSL_R_READ_WRONG_PACKET_TYPE = 212;
enum SSL_R_RECORD_LENGTH_MISMATCH = 213;
enum SSL_R_RECORD_TOO_LARGE = 214;
enum SSL_R_RECORD_TOO_SMALL = 298;
enum SSL_R_RENEGOTIATE_EXT_TOO_LONG = 335;
enum SSL_R_RENEGOTIATION_ENCODING_ERR = 336;
enum SSL_R_RENEGOTIATION_MISMATCH = 337;
enum SSL_R_REQUIRED_CIPHER_MISSING = 215;
enum SSL_R_REQUIRED_COMPRESSSION_ALGORITHM_MISSING = 342;
enum SSL_R_REUSE_CERT_LENGTH_NOT_ZERO = 216;
enum SSL_R_REUSE_CERT_TYPE_NOT_ZERO = 217;
enum SSL_R_REUSE_CIPHER_LIST_NOT_ZERO = 218;
enum SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING = 345;
enum SSL_R_SERVERHELLO_TLSEXT = 275;
enum SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED = 277;
enum SSL_R_SHORT_READ = 219;
enum SSL_R_SIGNATURE_ALGORITHMS_ERROR = 360;
enum SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE = 220;
enum SSL_R_SRP_A_CALC = 361;
enum SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES = 362;
enum SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG = 363;
enum SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE = 364;
enum SSL_R_SSL23_DOING_SESSION_ID_REUSE = 221;
enum SSL_R_SSL2_CONNECTION_ID_TOO_LONG = 299;
enum SSL_R_SSL3_EXT_INVALID_ECPOINTFORMAT = 321;
enum SSL_R_SSL3_EXT_INVALID_SERVERNAME = 319;
enum SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE = 320;
enum SSL_R_SSL3_SESSION_ID_TOO_LONG = 300;
enum SSL_R_SSL3_SESSION_ID_TOO_SHORT = 222;
enum SSL_R_SSLV3_ALERT_BAD_CERTIFICATE = 1042;
enum SSL_R_SSLV3_ALERT_BAD_RECORD_MAC = 1020;
enum SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED = 1045;
enum SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED = 1044;
enum SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN = 1046;
enum SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE = 1030;
enum SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE = 1040;
enum SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER = 1047;
enum SSL_R_SSLV3_ALERT_NO_CERTIFICATE = 1041;
enum SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE = 1010;
enum SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE = 1043;
enum SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION = 228;
enum SSL_R_SSL_HANDSHAKE_FAILURE = 229;
enum SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS = 230;
enum SSL_R_SSL_SESSION_ID_CALLBACK_FAILED = 301;
enum SSL_R_SSL_SESSION_ID_CONFLICT = 302;
enum SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG = 273;
enum SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH = 303;
enum SSL_R_SSL_SESSION_ID_IS_DIFFERENT = 231;
enum SSL_R_SSL_SESSION_ID_TOO_LONG = 408;
enum SSL_R_TLSV1_ALERT_ACCESS_DENIED = 1049;
enum SSL_R_TLSV1_ALERT_DECODE_ERROR = 1050;
enum SSL_R_TLSV1_ALERT_DECRYPTION_FAILED = 1021;
enum SSL_R_TLSV1_ALERT_DECRYPT_ERROR = 1051;
enum SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION = 1060;
enum SSL_R_TLSV1_ALERT_INAPPROPRIATE_FALLBACK = 1086;
enum SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY = 1071;
enum SSL_R_TLSV1_ALERT_INTERNAL_ERROR = 1080;
enum SSL_R_TLSV1_ALERT_NO_RENEGOTIATION = 1100;
enum SSL_R_TLSV1_ALERT_PROTOCOL_VERSION = 1070;
enum SSL_R_TLSV1_ALERT_RECORD_OVERFLOW = 1022;
enum SSL_R_TLSV1_ALERT_UNKNOWN_CA = 1048;
enum SSL_R_TLSV1_ALERT_USER_CANCELLED = 1090;
enum SSL_R_TLSV1_BAD_CERTIFICATE_HASH_VALUE = 1114;
enum SSL_R_TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE = 1113;
enum SSL_R_TLSV1_CERTIFICATE_UNOBTAINABLE = 1111;
enum SSL_R_TLSV1_UNRECOGNIZED_NAME = 1112;
enum SSL_R_TLSV1_UNSUPPORTED_EXTENSION = 1110;
enum SSL_R_TLS_CLIENT_CERT_REQ_WITH_ANON_CIPHER = 232;
enum SSL_R_TLS_HEARTBEAT_PEER_DOESNT_ACCEPT = 365;
enum SSL_R_TLS_HEARTBEAT_PENDING = 366;
enum SSL_R_TLS_ILLEGAL_EXPORTER_LABEL = 367;
enum SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST = 157;
enum SSL_R_TLS_PEER_DID_NOT_RESPOND_WITH_CERTIFICATE_LIST = 233;
enum SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG = 234;
enum SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER = 235;
enum SSL_R_UNABLE_TO_DECODE_DH_CERTS = 236;
enum SSL_R_UNABLE_TO_DECODE_ECDH_CERTS = 313;
enum SSL_R_UNABLE_TO_EXTRACT_PUBLIC_KEY = 237;
enum SSL_R_UNABLE_TO_FIND_DH_PARAMETERS = 238;
enum SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS = 314;
enum SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS = 239;
enum SSL_R_UNABLE_TO_FIND_SSL_METHOD = 240;
enum SSL_R_UNABLE_TO_LOAD_SSL2_MD5_ROUTINES = 241;
enum SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES = 242;
enum SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES = 243;
enum SSL_R_UNEXPECTED_MESSAGE = 244;
enum SSL_R_UNEXPECTED_RECORD = 245;
enum SSL_R_UNINITIALIZED = 276;
enum SSL_R_UNKNOWN_ALERT_TYPE = 246;
enum SSL_R_UNKNOWN_CERTIFICATE_TYPE = 247;
enum SSL_R_UNKNOWN_CIPHER_RETURNED = 248;
enum SSL_R_UNKNOWN_CIPHER_TYPE = 249;
enum SSL_R_UNKNOWN_DIGEST = 368;
enum SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE = 250;
enum SSL_R_UNKNOWN_PKEY_TYPE = 251;
enum SSL_R_UNKNOWN_PROTOCOL = 252;
enum SSL_R_UNKNOWN_REMOTE_ERROR_TYPE = 253;
enum SSL_R_UNKNOWN_SSL_VERSION = 254;
enum SSL_R_UNKNOWN_STATE = 255;
enum SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED = 338;
enum SSL_R_UNSUPPORTED_CIPHER = 256;
enum SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM = 257;
enum SSL_R_UNSUPPORTED_DIGEST_TYPE = 326;
enum SSL_R_UNSUPPORTED_ELLIPTIC_CURVE = 315;
enum SSL_R_UNSUPPORTED_PROTOCOL = 258;
enum SSL_R_UNSUPPORTED_SSL_VERSION = 259;
enum SSL_R_UNSUPPORTED_STATUS_TYPE = 329;
enum SSL_R_USE_SRTP_NOT_NEGOTIATED = 369;
enum SSL_R_VERSION_TOO_LOW = 396;
enum SSL_R_WRITE_BIO_NOT_SET = 260;
enum SSL_R_WRONG_CIPHER_RETURNED = 261;
enum SSL_R_WRONG_CURVE = 378;
enum SSL_R_WRONG_MESSAGE_TYPE = 262;
enum SSL_R_WRONG_NUMBER_OF_KEY_BITS = 263;
enum SSL_R_WRONG_SIGNATURE_LENGTH = 264;
enum SSL_R_WRONG_SIGNATURE_SIZE = 265;
enum SSL_R_WRONG_SIGNATURE_TYPE = 370;
enum SSL_R_WRONG_SSL_VERSION = 266;
enum SSL_R_WRONG_VERSION_NUMBER = 267;
enum SSL_R_X509_LIB = 268;
enum SSL_R_X509_VERIFICATION_SETUP_PROBLEMS = 269;
enum SSL_R_PEER_BEHAVING_BADLY = 666;
enum SSL_R_QUIC_INTERNAL_ERROR = 667;
enum SSL_R_WRONG_ENCRYPTION_LEVEL_RECEIVED = 668;
enum SSL_R_UNKNOWN = 999;

/*
 * OpenSSL compatible OPENSSL_INIT options
 */

/*
 * These are provided for compatibiliy, but have no effect
 * on how LibreSSL is initialized.
 */
enum OPENSSL_INIT_LOAD_SSL_STRINGS = libressl_d.openssl.crypto._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_SSL_DEFAULT = libressl_d.openssl.crypto._OPENSSL_INIT_FLAG_NOOP;

int OPENSSL_init_ssl(core.stdc.stdint.uint64_t opts, const (void)* settings);
