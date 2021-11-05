/* $OpenBSD: tls1.h,v 1.49 2021/09/10 14:57:31 tb Exp $ */
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
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * ECC cipher suite support in OpenSSL originally written by
 * Vipul Gupta and Sumit Gupta of Sun Microsystems Laboratories.
 *
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
module libressl_d.openssl.tls1;


private static import core.stdc.config;
private static import libressl_d.openssl.opensslfeatures;
private static import libressl_d.openssl.ossl_typ;
private static import libressl_d.openssl.ssl;
public import libressl_d.openssl.buffer;
public import libressl_d.openssl.opensslconf;

extern (C):
nothrow @nogc:

enum TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES = 0;

static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	enum TLS1_3_VERSION = 0x0304;
}

enum TLS1_2_VERSION = 0x0303;
enum TLS1_2_VERSION_MAJOR = 0x03;
enum TLS1_2_VERSION_MINOR = 0x03;

enum TLS1_1_VERSION = 0x0302;
enum TLS1_1_VERSION_MAJOR = 0x03;
enum TLS1_1_VERSION_MINOR = 0x02;

enum TLS1_VERSION = 0x0301;
enum TLS1_VERSION_MAJOR = 0x03;
enum TLS1_VERSION_MINOR = 0x01;

version (LIBRESSL_INTERNAL) {
} else {
	enum TLS1_AD_DECRYPTION_FAILED = 21;
	enum TLS1_AD_RECORD_OVERFLOW = 22;

	/**
	 *  fatal
	 */
	enum TLS1_AD_UNKNOWN_CA = 48;

	/**
	 *  fatal
	 */
	enum TLS1_AD_ACCESS_DENIED = 49;

	/**
	 *  fatal
	 */
	enum TLS1_AD_DECODE_ERROR = 50;

	enum TLS1_AD_DECRYPT_ERROR = 51;

	/**
	 *  fatal
	 */
	enum TLS1_AD_EXPORT_RESTRICTION = 60;

	/**
	 *  fatal
	 */
	enum TLS1_AD_PROTOCOL_VERSION = 70;

	/**
	 *  fatal
	 */
	enum TLS1_AD_INSUFFICIENT_SECURITY = 71;

	/**
	 *  fatal
	 */
	enum TLS1_AD_INTERNAL_ERROR = 80;

	/* Code 86 from RFC 7507. */

	/**
	 *  fatal
	 */
	enum TLS1_AD_INAPPROPRIATE_FALLBACK = 86;

	enum TLS1_AD_USER_CANCELLED = 90;
	enum TLS1_AD_NO_RENEGOTIATION = 100;
	/* Codes 110-114 from RFC 3546. */
	enum TLS1_AD_UNSUPPORTED_EXTENSION = 110;
	enum TLS1_AD_CERTIFICATE_UNOBTAINABLE = 111;
	enum TLS1_AD_UNRECOGNIZED_NAME = 112;
	enum TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE = 113;
	enum TLS1_AD_BAD_CERTIFICATE_HASH_VALUE = 114;
	/* Code 115 from RFC 4279. */

	/**
	 *  fatal
	 */
	enum TLS1_AD_UNKNOWN_PSK_IDENTITY = 115;
}

/*
 * TLS ExtensionType values.
 *
 * https://www.iana.org/assignments/tls-extensiontype-values/
 */

/* ExtensionType values from RFC 3546, RFC 4366 and RFC 6066. */
enum TLSEXT_TYPE_server_name = 0;
enum TLSEXT_TYPE_max_fragment_length = 1;
enum TLSEXT_TYPE_client_certificate_url = 2;
enum TLSEXT_TYPE_trusted_ca_keys = 3;
enum TLSEXT_TYPE_truncated_hmac = 4;
enum TLSEXT_TYPE_status_request = 5;

/**
 * ExtensionType values from RFC 4681.
 */
enum TLSEXT_TYPE_user_mapping = 6;

/* ExtensionType values from RFC 5878. */
enum TLSEXT_TYPE_client_authz = 7;
enum TLSEXT_TYPE_server_authz = 8;

/**
 * ExtensionType values from RFC 6091.
 */
enum TLSEXT_TYPE_cert_type = 9;

/**
 * ExtensionType values from RFC 7919.
 */
enum TLSEXT_TYPE_supported_groups = 10;

/* ExtensionType values from RFC 4492. */
version (LIBRESSL_INTERNAL) {
} else {
	alias TLSEXT_TYPE_elliptic_curves = .TLSEXT_TYPE_supported_groups;
}

enum TLSEXT_TYPE_ec_point_formats = 11;

/**
 * ExtensionType value from RFC 5054.
 */
enum TLSEXT_TYPE_srp = 12;

/**
 * ExtensionType value from RFC 5246/RFC 8446.
 */
enum TLSEXT_TYPE_signature_algorithms = 13;

/**
 * ExtensionType value from RFC 5764.
 */
enum TLSEXT_TYPE_use_srtp = 14;

/**
 * ExtensionType value from RFC 5620.
 */
enum TLSEXT_TYPE_heartbeat = 15;

/**
 * ExtensionType value from RFC 7301.
 */
enum TLSEXT_TYPE_application_layer_protocol_negotiation = 16;

/**
 * ExtensionType value from RFC 7685.
 */
enum TLSEXT_TYPE_padding = 21;

/**
 * ExtensionType value from RFC 4507.
 */
enum TLSEXT_TYPE_session_ticket = 35;

/* ExtensionType values from RFC 8446 section 4.2 */
static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	enum TLSEXT_TYPE_pre_shared_key = 41;
	enum TLSEXT_TYPE_early_data = 42;
	enum TLSEXT_TYPE_supported_versions = 43;
	enum TLSEXT_TYPE_cookie = 44;
	enum TLSEXT_TYPE_psk_key_exchange_modes = 45;
	enum TLSEXT_TYPE_certificate_authorities = 47;
	enum TLSEXT_TYPE_oid_filters = 48;
	enum TLSEXT_TYPE_post_handshake_auth = 49;
	enum TLSEXT_TYPE_signature_algorithms_cert = 50;
	enum TLSEXT_TYPE_key_share = 51;
}

/*
 * TLS 1.3 extension names from OpenSSL, where they decided to use a different
 * name from that given in RFC 8446.
 */
version (LIBRESSL_HAS_TLS1_3) {
	enum TLSEXT_TYPE_psk = .TLSEXT_TYPE_pre_shared_key;
	enum TLSEXT_TYPE_psk_kex_modes = .TLSEXT_TYPE_psk_key_exchange_modes;
}

/**
 * Temporary extension type
 */
enum TLSEXT_TYPE_renegotiate = 0xFF01;

/**
 * NameType value from RFC 3546.
 */
enum TLSEXT_NAMETYPE_host_name = 0;

/**
 * status request value from RFC 3546
 */
enum TLSEXT_STATUSTYPE_ocsp = 1;

/* ECPointFormat values from RFC 4492. */
enum TLSEXT_ECPOINTFORMAT_first = 0;
enum TLSEXT_ECPOINTFORMAT_uncompressed = 0;
enum TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime = 1;
enum TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2 = 2;
enum TLSEXT_ECPOINTFORMAT_last = 2;

enum TLSEXT_MAXLEN_host_name = 255;

const (char)* SSL_get_servername(const (libressl_d.openssl.ossl_typ.SSL)* s, const int type);
int SSL_get_servername_type(const (libressl_d.openssl.ossl_typ.SSL)* s);

/**
 * SSL_export_keying_material exports a value derived from the master secret,
 * as specified in RFC 5705. It writes |olen| bytes to |out| given a label and
 * optional context. (Since a zero length context is allowed, the |use_context|
 * flag controls whether a context is included.)
 *
 * It returns 1 on success and zero otherwise.
 */
int SSL_export_keying_material(libressl_d.openssl.ossl_typ.SSL* s, ubyte* out_, size_t olen, const (char)* label, size_t llen, const (ubyte)* p, size_t plen, int use_context);

pragma(inline, true)
core.stdc.config.c_long SSL_set_tlsext_host_name(libressl_d.openssl.ossl_typ.SSL* s, char* name)

	do
	{
		return libressl_d.openssl.ssl.SSL_ctrl(s, libressl_d.openssl.ssl.SSL_CTRL_SET_TLSEXT_HOSTNAME, .TLSEXT_NAMETYPE_host_name, name);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_tlsext_debug_callback(libressl_d.openssl.ossl_typ.SSL* ssl, void function() cb)

	do
	{
		return libressl_d.openssl.ssl.SSL_callback_ctrl(ssl, libressl_d.openssl.ssl.SSL_CTRL_SET_TLSEXT_DEBUG_CB, cb);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_tlsext_debug_arg(libressl_d.openssl.ossl_typ.SSL* ssl, void* arg)

	do
	{
		return libressl_d.openssl.ssl.SSL_ctrl(ssl, libressl_d.openssl.ssl.SSL_CTRL_SET_TLSEXT_DEBUG_ARG, 0, arg);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_get_tlsext_status_type(libressl_d.openssl.ossl_typ.SSL* ssl, void* arg)

	do
	{
		return libressl_d.openssl.ssl.SSL_ctrl(ssl, libressl_d.openssl.ssl.SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE, 0, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_tlsext_status_type(libressl_d.openssl.ossl_typ.SSL* ssl, core.stdc.config.c_long type)

	do
	{
		return libressl_d.openssl.ssl.SSL_ctrl(ssl, libressl_d.openssl.ssl.SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE, type, null);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_get_tlsext_status_exts(libressl_d.openssl.ossl_typ.SSL* ssl, void* arg)

	do
	{
		return libressl_d.openssl.ssl.SSL_ctrl(ssl, libressl_d.openssl.ssl.SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS, 0, arg);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_tlsext_status_exts(libressl_d.openssl.ossl_typ.SSL* ssl, void* arg)

	do
	{
		return libressl_d.openssl.ssl.SSL_ctrl(ssl, libressl_d.openssl.ssl.SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS, 0, arg);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_get_tlsext_status_ids(libressl_d.openssl.ossl_typ.SSL* ssl, void* arg)

	do
	{
		return libressl_d.openssl.ssl.SSL_ctrl(ssl, libressl_d.openssl.ssl.SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS, 0, arg);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_tlsext_status_ids(libressl_d.openssl.ossl_typ.SSL* ssl, void* arg)

	do
	{
		return libressl_d.openssl.ssl.SSL_ctrl(ssl, libressl_d.openssl.ssl.SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS, 0, arg);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_get_tlsext_status_ocsp_resp(libressl_d.openssl.ossl_typ.SSL* ssl, void* arg)

	do
	{
		return libressl_d.openssl.ssl.SSL_ctrl(ssl, libressl_d.openssl.ssl.SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP, 0, arg);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_set_tlsext_status_ocsp_resp(libressl_d.openssl.ossl_typ.SSL* ssl, void* arg, core.stdc.config.c_long arglen)

	do
	{
		return libressl_d.openssl.ssl.SSL_ctrl(ssl, libressl_d.openssl.ssl.SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP, arglen, arg);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_tlsext_servername_callback(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, void function() cb)

	do
	{
		return libressl_d.openssl.ssl.SSL_CTX_callback_ctrl(ctx, libressl_d.openssl.ssl.SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, cb);
	}

enum SSL_TLSEXT_ERR_OK = 0;
enum SSL_TLSEXT_ERR_ALERT_WARNING = 1;
enum SSL_TLSEXT_ERR_ALERT_FATAL = 2;
enum SSL_TLSEXT_ERR_NOACK = 3;

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_tlsext_servername_arg(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, void* arg)

	do
	{
		return libressl_d.openssl.ssl.SSL_CTX_ctrl(ctx, libressl_d.openssl.ssl.SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, arg);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_get_tlsext_ticket_keys(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, void* keys, core.stdc.config.c_long keylen)

	do
	{
		return libressl_d.openssl.ssl.SSL_CTX_ctrl(ctx, libressl_d.openssl.ssl.SSL_CTRL_GET_TLSEXT_TICKET_KEYS, keylen, keys);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_tlsext_ticket_keys(libressl_d.openssl.ossl_typ.SSL_CTX* ctx, void* keys, core.stdc.config.c_long keylen)

	do
	{
		return libressl_d.openssl.ssl.SSL_CTX_ctrl(ctx, libressl_d.openssl.ssl.SSL_CTRL_SET_TLSEXT_TICKET_KEYS, keylen, keys);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_get_tlsext_status_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ssl, void function() cb)

	do
	{
		return libressl_d.openssl.ssl.SSL_CTX_callback_ctrl(ssl, libressl_d.openssl.ssl.SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB, cb);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_tlsext_status_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ssl, void function() cb)

	do
	{
		return libressl_d.openssl.ssl.SSL_CTX_callback_ctrl(ssl, libressl_d.openssl.ssl.SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB, cb);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_get_tlsext_status_arg(libressl_d.openssl.ossl_typ.SSL_CTX* ssl, void* arg)

	do
	{
		return libressl_d.openssl.ssl.SSL_CTX_ctrl(ssl, libressl_d.openssl.ssl.SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG, 0, arg);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_tlsext_status_arg(libressl_d.openssl.ossl_typ.SSL_CTX* ssl, void* arg)

	do
	{
		return libressl_d.openssl.ssl.SSL_CTX_ctrl(ssl, libressl_d.openssl.ssl.SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG, 0, arg);
	}

pragma(inline, true)
core.stdc.config.c_long SSL_CTX_set_tlsext_ticket_key_cb(libressl_d.openssl.ossl_typ.SSL_CTX* ssl, void function() cb)

	do
	{
		return libressl_d.openssl.ssl.SSL_CTX_callback_ctrl(ssl, libressl_d.openssl.ssl.SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB, cb);
	}

/* PSK ciphersuites from RFC 4279. */
enum TLS1_CK_PSK_WITH_RC4_128_SHA = 0x0300008A;
enum TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA = 0x0300008B;
enum TLS1_CK_PSK_WITH_AES_128_CBC_SHA = 0x0300008C;
enum TLS1_CK_PSK_WITH_AES_256_CBC_SHA = 0x0300008D;

/*
 * Additional TLS ciphersuites from expired Internet Draft
 * draft-ietf-tls-56-bit-ciphersuites-01.txt
 * (available if TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES is defined, see
 * s3_lib.c).  We actually treat them like SSL 3.0 ciphers, which we probably
 * shouldn't.  Note that the first two are actually not in the IDs.
 */

/**
 *  not in ID
 */
enum TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5 = 0x03000060;

/**
 *  not in ID
 */
enum TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 = 0x03000061;

enum TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA = 0x03000062;
enum TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = 0x03000063;
enum TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA = 0x03000064;
enum TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA = 0x03000065;
enum TLS1_CK_DHE_DSS_WITH_RC4_128_SHA = 0x03000066;

/* AES ciphersuites from RFC 3268. */

enum TLS1_CK_RSA_WITH_AES_128_SHA = 0x0300002F;
enum TLS1_CK_DH_DSS_WITH_AES_128_SHA = 0x03000030;
enum TLS1_CK_DH_RSA_WITH_AES_128_SHA = 0x03000031;
enum TLS1_CK_DHE_DSS_WITH_AES_128_SHA = 0x03000032;
enum TLS1_CK_DHE_RSA_WITH_AES_128_SHA = 0x03000033;
enum TLS1_CK_ADH_WITH_AES_128_SHA = 0x03000034;

enum TLS1_CK_RSA_WITH_AES_256_SHA = 0x03000035;
enum TLS1_CK_DH_DSS_WITH_AES_256_SHA = 0x03000036;
enum TLS1_CK_DH_RSA_WITH_AES_256_SHA = 0x03000037;
enum TLS1_CK_DHE_DSS_WITH_AES_256_SHA = 0x03000038;
enum TLS1_CK_DHE_RSA_WITH_AES_256_SHA = 0x03000039;
enum TLS1_CK_ADH_WITH_AES_256_SHA = 0x0300003A;

/* TLS v1.2 ciphersuites */
enum TLS1_CK_RSA_WITH_NULL_SHA256 = 0x0300003B;
enum TLS1_CK_RSA_WITH_AES_128_SHA256 = 0x0300003C;
enum TLS1_CK_RSA_WITH_AES_256_SHA256 = 0x0300003D;
enum TLS1_CK_DH_DSS_WITH_AES_128_SHA256 = 0x0300003E;
enum TLS1_CK_DH_RSA_WITH_AES_128_SHA256 = 0x0300003F;
enum TLS1_CK_DHE_DSS_WITH_AES_128_SHA256 = 0x03000040;

/* Camellia ciphersuites from RFC 4132. */
enum TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x03000041;
enum TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x03000042;
enum TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x03000043;
enum TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x03000044;
enum TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x03000045;
enum TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA = 0x03000046;

/* TLS v1.2 ciphersuites */
enum TLS1_CK_DHE_RSA_WITH_AES_128_SHA256 = 0x03000067;
enum TLS1_CK_DH_DSS_WITH_AES_256_SHA256 = 0x03000068;
enum TLS1_CK_DH_RSA_WITH_AES_256_SHA256 = 0x03000069;
enum TLS1_CK_DHE_DSS_WITH_AES_256_SHA256 = 0x0300006A;
enum TLS1_CK_DHE_RSA_WITH_AES_256_SHA256 = 0x0300006B;
enum TLS1_CK_ADH_WITH_AES_128_SHA256 = 0x0300006C;
enum TLS1_CK_ADH_WITH_AES_256_SHA256 = 0x0300006D;

/* Camellia ciphersuites from RFC 4132. */
enum TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x03000084;
enum TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x03000085;
enum TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x03000086;
enum TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x03000087;
enum TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x03000088;
enum TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA = 0x03000089;

/* SEED ciphersuites from RFC 4162. */
enum TLS1_CK_RSA_WITH_SEED_SHA = 0x03000096;
enum TLS1_CK_DH_DSS_WITH_SEED_SHA = 0x03000097;
enum TLS1_CK_DH_RSA_WITH_SEED_SHA = 0x03000098;
enum TLS1_CK_DHE_DSS_WITH_SEED_SHA = 0x03000099;
enum TLS1_CK_DHE_RSA_WITH_SEED_SHA = 0x0300009A;
enum TLS1_CK_ADH_WITH_SEED_SHA = 0x0300009B;

/* TLS v1.2 GCM ciphersuites from RFC 5288. */
enum TLS1_CK_RSA_WITH_AES_128_GCM_SHA256 = 0x0300009C;
enum TLS1_CK_RSA_WITH_AES_256_GCM_SHA384 = 0x0300009D;
enum TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x0300009E;
enum TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x0300009F;
enum TLS1_CK_DH_RSA_WITH_AES_128_GCM_SHA256 = 0x030000A0;
enum TLS1_CK_DH_RSA_WITH_AES_256_GCM_SHA384 = 0x030000A1;
enum TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256 = 0x030000A2;
enum TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384 = 0x030000A3;
enum TLS1_CK_DH_DSS_WITH_AES_128_GCM_SHA256 = 0x030000A4;
enum TLS1_CK_DH_DSS_WITH_AES_256_GCM_SHA384 = 0x030000A5;
enum TLS1_CK_ADH_WITH_AES_128_GCM_SHA256 = 0x030000A6;
enum TLS1_CK_ADH_WITH_AES_256_GCM_SHA384 = 0x030000A7;

/* TLS 1.2 Camellia SHA-256 ciphersuites from RFC5932 */
enum TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x030000BA;
enum TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0x030000BB;
enum TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x030000BC;
enum TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0x030000BD;
enum TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x030000BE;
enum TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA256 = 0x030000BF;

enum TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x030000C0;
enum TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0x030000C1;
enum TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x030000C2;
enum TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0x030000C3;
enum TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x030000C4;
enum TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA256 = 0x030000C5;

/* TLS 1.3 cipher suites from RFC 8446 appendix B.4. */
static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	enum TLS1_3_CK_AES_128_GCM_SHA256 = 0x03001301;
	enum TLS1_3_CK_AES_256_GCM_SHA384 = 0x03001302;
	enum TLS1_3_CK_CHACHA20_POLY1305_SHA256 = 0x03001303;
	enum TLS1_3_CK_AES_128_CCM_SHA256 = 0x03001304;
	enum TLS1_3_CK_AES_128_CCM_8_SHA256 = 0x03001305;
}

/* ECC ciphersuites from RFC 4492. */
enum TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA = 0x0300C001;
enum TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA = 0x0300C002;
enum TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA = 0x0300C003;
enum TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0x0300C004;
enum TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0x0300C005;

enum TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA = 0x0300C006;
enum TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA = 0x0300C007;
enum TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA = 0x0300C008;
enum TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0x0300C009;
enum TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0x0300C00A;

enum TLS1_CK_ECDH_RSA_WITH_NULL_SHA = 0x0300C00B;
enum TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA = 0x0300C00C;
enum TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA = 0x0300C00D;
enum TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA = 0x0300C00E;
enum TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA = 0x0300C00F;

enum TLS1_CK_ECDHE_RSA_WITH_NULL_SHA = 0x0300C010;
enum TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA = 0x0300C011;
enum TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA = 0x0300C012;
enum TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0x0300C013;
enum TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0x0300C014;

enum TLS1_CK_ECDH_anon_WITH_NULL_SHA = 0x0300C015;
enum TLS1_CK_ECDH_anon_WITH_RC4_128_SHA = 0x0300C016;
enum TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA = 0x0300C017;
enum TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA = 0x0300C018;
enum TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA = 0x0300C019;

/* SRP ciphersuites from RFC 5054. */
enum TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA = 0x0300C01A;
enum TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 0x0300C01B;
enum TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = 0x0300C01C;
enum TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA = 0x0300C01D;
enum TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0x0300C01E;
enum TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = 0x0300C01F;
enum TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA = 0x0300C020;
enum TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0x0300C021;
enum TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0x0300C022;

/* ECDH HMAC based ciphersuites from RFC 5289. */
enum TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256 = 0x0300C023;
enum TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384 = 0x0300C024;
enum TLS1_CK_ECDH_ECDSA_WITH_AES_128_SHA256 = 0x0300C025;
enum TLS1_CK_ECDH_ECDSA_WITH_AES_256_SHA384 = 0x0300C026;
enum TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256 = 0x0300C027;
enum TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384 = 0x0300C028;
enum TLS1_CK_ECDH_RSA_WITH_AES_128_SHA256 = 0x0300C029;
enum TLS1_CK_ECDH_RSA_WITH_AES_256_SHA384 = 0x0300C02A;

/* ECDH GCM based ciphersuites from RFC 5289. */
enum TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0x0300C02B;
enum TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0x0300C02C;
enum TLS1_CK_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0x0300C02D;
enum TLS1_CK_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0x0300C02E;
enum TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0x0300C02F;
enum TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0x0300C030;
enum TLS1_CK_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0x0300C031;
enum TLS1_CK_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0x0300C032;

/* ChaCha20-Poly1305 based ciphersuites. */
enum TLS1_CK_ECDHE_RSA_CHACHA20_POLY1305 = 0x0300CCA8;
enum TLS1_CK_ECDHE_ECDSA_CHACHA20_POLY1305 = 0x0300CCA9;
enum TLS1_CK_DHE_RSA_CHACHA20_POLY1305 = 0x0300CCAA;

enum TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_MD5 = "EXP1024-RC4-MD5";
enum TLS1_TXT_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 = "EXP1024-RC2-CBC-MD5";
enum TLS1_TXT_RSA_EXPORT1024_WITH_DES_CBC_SHA = "EXP1024-DES-CBC-SHA";
enum TLS1_TXT_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = "EXP1024-DHE-DSS-DES-CBC-SHA";
enum TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_SHA = "EXP1024-RC4-SHA";
enum TLS1_TXT_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA = "EXP1024-DHE-DSS-RC4-SHA";
enum TLS1_TXT_DHE_DSS_WITH_RC4_128_SHA = "DHE-DSS-RC4-SHA";

/* AES ciphersuites from RFC 3268. */
enum TLS1_TXT_RSA_WITH_AES_128_SHA = "AES128-SHA";
enum TLS1_TXT_DH_DSS_WITH_AES_128_SHA = "DH-DSS-AES128-SHA";
enum TLS1_TXT_DH_RSA_WITH_AES_128_SHA = "DH-RSA-AES128-SHA";
enum TLS1_TXT_DHE_DSS_WITH_AES_128_SHA = "DHE-DSS-AES128-SHA";
enum TLS1_TXT_DHE_RSA_WITH_AES_128_SHA = "DHE-RSA-AES128-SHA";
enum TLS1_TXT_ADH_WITH_AES_128_SHA = "ADH-AES128-SHA";

enum TLS1_TXT_RSA_WITH_AES_256_SHA = "AES256-SHA";
enum TLS1_TXT_DH_DSS_WITH_AES_256_SHA = "DH-DSS-AES256-SHA";
enum TLS1_TXT_DH_RSA_WITH_AES_256_SHA = "DH-RSA-AES256-SHA";
enum TLS1_TXT_DHE_DSS_WITH_AES_256_SHA = "DHE-DSS-AES256-SHA";
enum TLS1_TXT_DHE_RSA_WITH_AES_256_SHA = "DHE-RSA-AES256-SHA";
enum TLS1_TXT_ADH_WITH_AES_256_SHA = "ADH-AES256-SHA";

/* ECC ciphersuites from draft-ietf-tls-ecc-01.txt (Mar 15, 2001) */
enum TLS1_TXT_ECDH_ECDSA_WITH_NULL_SHA = "ECDH-ECDSA-null-SHA";
enum TLS1_TXT_ECDH_ECDSA_WITH_RC4_128_SHA = "ECDH-ECDSA-RC4-SHA";
enum TLS1_TXT_ECDH_ECDSA_WITH_DES_192_CBC3_SHA = "ECDH-ECDSA-DES-CBC3-SHA";
enum TLS1_TXT_ECDH_ECDSA_WITH_AES_128_CBC_SHA = "ECDH-ECDSA-AES128-SHA";
enum TLS1_TXT_ECDH_ECDSA_WITH_AES_256_CBC_SHA = "ECDH-ECDSA-AES256-SHA";

enum TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA = "ECDHE-ECDSA-null-SHA";
enum TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA = "ECDHE-ECDSA-RC4-SHA";
enum TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA = "ECDHE-ECDSA-DES-CBC3-SHA";
enum TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = "ECDHE-ECDSA-AES128-SHA";
enum TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = "ECDHE-ECDSA-AES256-SHA";

enum TLS1_TXT_ECDH_RSA_WITH_NULL_SHA = "ECDH-RSA-null-SHA";
enum TLS1_TXT_ECDH_RSA_WITH_RC4_128_SHA = "ECDH-RSA-RC4-SHA";
enum TLS1_TXT_ECDH_RSA_WITH_DES_192_CBC3_SHA = "ECDH-RSA-DES-CBC3-SHA";
enum TLS1_TXT_ECDH_RSA_WITH_AES_128_CBC_SHA = "ECDH-RSA-AES128-SHA";
enum TLS1_TXT_ECDH_RSA_WITH_AES_256_CBC_SHA = "ECDH-RSA-AES256-SHA";

enum TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA = "ECDHE-RSA-null-SHA";
enum TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA = "ECDHE-RSA-RC4-SHA";
enum TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA = "ECDHE-RSA-DES-CBC3-SHA";
enum TLS1_TXT_ECDHE_RSA_WITH_AES_128_CBC_SHA = "ECDHE-RSA-AES128-SHA";
enum TLS1_TXT_ECDHE_RSA_WITH_AES_256_CBC_SHA = "ECDHE-RSA-AES256-SHA";

enum TLS1_TXT_ECDH_anon_WITH_NULL_SHA = "AECDH-null-SHA";
enum TLS1_TXT_ECDH_anon_WITH_RC4_128_SHA = "AECDH-RC4-SHA";
enum TLS1_TXT_ECDH_anon_WITH_DES_192_CBC3_SHA = "AECDH-DES-CBC3-SHA";
enum TLS1_TXT_ECDH_anon_WITH_AES_128_CBC_SHA = "AECDH-AES128-SHA";
enum TLS1_TXT_ECDH_anon_WITH_AES_256_CBC_SHA = "AECDH-AES256-SHA";

/* PSK ciphersuites from RFC 4279. */
enum TLS1_TXT_PSK_WITH_RC4_128_SHA = "PSK-RC4-SHA";
enum TLS1_TXT_PSK_WITH_3DES_EDE_CBC_SHA = "PSK-3DES-EDE-CBC-SHA";
enum TLS1_TXT_PSK_WITH_AES_128_CBC_SHA = "PSK-AES128-CBC-SHA";
enum TLS1_TXT_PSK_WITH_AES_256_CBC_SHA = "PSK-AES256-CBC-SHA";

/* SRP ciphersuite from RFC 5054. */
enum TLS1_TXT_SRP_SHA_WITH_3DES_EDE_CBC_SHA = "SRP-3DES-EDE-CBC-SHA";
enum TLS1_TXT_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = "SRP-RSA-3DES-EDE-CBC-SHA";
enum TLS1_TXT_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = "SRP-DSS-3DES-EDE-CBC-SHA";
enum TLS1_TXT_SRP_SHA_WITH_AES_128_CBC_SHA = "SRP-AES-128-CBC-SHA";
enum TLS1_TXT_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = "SRP-RSA-AES-128-CBC-SHA";
enum TLS1_TXT_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = "SRP-DSS-AES-128-CBC-SHA";
enum TLS1_TXT_SRP_SHA_WITH_AES_256_CBC_SHA = "SRP-AES-256-CBC-SHA";
enum TLS1_TXT_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = "SRP-RSA-AES-256-CBC-SHA";
enum TLS1_TXT_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = "SRP-DSS-AES-256-CBC-SHA";

/* Camellia ciphersuites from RFC 4132. */
enum TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA = "CAMELLIA128-SHA";
enum TLS1_TXT_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = "DH-DSS-CAMELLIA128-SHA";
enum TLS1_TXT_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = "DH-RSA-CAMELLIA128-SHA";
enum TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = "DHE-DSS-CAMELLIA128-SHA";
enum TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = "DHE-RSA-CAMELLIA128-SHA";
enum TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA = "ADH-CAMELLIA128-SHA";

enum TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA = "CAMELLIA256-SHA";
enum TLS1_TXT_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = "DH-DSS-CAMELLIA256-SHA";
enum TLS1_TXT_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = "DH-RSA-CAMELLIA256-SHA";
enum TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = "DHE-DSS-CAMELLIA256-SHA";
enum TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = "DHE-RSA-CAMELLIA256-SHA";
enum TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA = "ADH-CAMELLIA256-SHA";

/* TLS 1.2 Camellia SHA-256 ciphersuites from RFC5932 */
enum TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA256 = "CAMELLIA128-SHA256";
enum TLS1_TXT_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = "DH-DSS-CAMELLIA128-SHA256";
enum TLS1_TXT_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = "DH-RSA-CAMELLIA128-SHA256";
enum TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = "DHE-DSS-CAMELLIA128-SHA256";
enum TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = "DHE-RSA-CAMELLIA128-SHA256";
enum TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA256 = "ADH-CAMELLIA128-SHA256";

enum TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA256 = "CAMELLIA256-SHA256";
enum TLS1_TXT_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = "DH-DSS-CAMELLIA256-SHA256";
enum TLS1_TXT_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = "DH-RSA-CAMELLIA256-SHA256";
enum TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = "DHE-DSS-CAMELLIA256-SHA256";
enum TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = "DHE-RSA-CAMELLIA256-SHA256";
enum TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA256 = "ADH-CAMELLIA256-SHA256";

/* SEED ciphersuites from RFC 4162. */
enum TLS1_TXT_RSA_WITH_SEED_SHA = "SEED-SHA";
enum TLS1_TXT_DH_DSS_WITH_SEED_SHA = "DH-DSS-SEED-SHA";
enum TLS1_TXT_DH_RSA_WITH_SEED_SHA = "DH-RSA-SEED-SHA";
enum TLS1_TXT_DHE_DSS_WITH_SEED_SHA = "DHE-DSS-SEED-SHA";
enum TLS1_TXT_DHE_RSA_WITH_SEED_SHA = "DHE-RSA-SEED-SHA";
enum TLS1_TXT_ADH_WITH_SEED_SHA = "ADH-SEED-SHA";

/* TLS v1.2 ciphersuites. */
enum TLS1_TXT_RSA_WITH_NULL_SHA256 = "null-SHA256";
enum TLS1_TXT_RSA_WITH_AES_128_SHA256 = "AES128-SHA256";
enum TLS1_TXT_RSA_WITH_AES_256_SHA256 = "AES256-SHA256";
enum TLS1_TXT_DH_DSS_WITH_AES_128_SHA256 = "DH-DSS-AES128-SHA256";
enum TLS1_TXT_DH_RSA_WITH_AES_128_SHA256 = "DH-RSA-AES128-SHA256";
enum TLS1_TXT_DHE_DSS_WITH_AES_128_SHA256 = "DHE-DSS-AES128-SHA256";
enum TLS1_TXT_DHE_RSA_WITH_AES_128_SHA256 = "DHE-RSA-AES128-SHA256";
enum TLS1_TXT_DH_DSS_WITH_AES_256_SHA256 = "DH-DSS-AES256-SHA256";
enum TLS1_TXT_DH_RSA_WITH_AES_256_SHA256 = "DH-RSA-AES256-SHA256";
enum TLS1_TXT_DHE_DSS_WITH_AES_256_SHA256 = "DHE-DSS-AES256-SHA256";
enum TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256 = "DHE-RSA-AES256-SHA256";
enum TLS1_TXT_ADH_WITH_AES_128_SHA256 = "ADH-AES128-SHA256";
enum TLS1_TXT_ADH_WITH_AES_256_SHA256 = "ADH-AES256-SHA256";

/* TLS v1.2 GCM ciphersuites from RFC 5288. */
enum TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256 = "AES128-GCM-SHA256";
enum TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384 = "AES256-GCM-SHA384";
enum TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256 = "DHE-RSA-AES128-GCM-SHA256";
enum TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384 = "DHE-RSA-AES256-GCM-SHA384";
enum TLS1_TXT_DH_RSA_WITH_AES_128_GCM_SHA256 = "DH-RSA-AES128-GCM-SHA256";
enum TLS1_TXT_DH_RSA_WITH_AES_256_GCM_SHA384 = "DH-RSA-AES256-GCM-SHA384";
enum TLS1_TXT_DHE_DSS_WITH_AES_128_GCM_SHA256 = "DHE-DSS-AES128-GCM-SHA256";
enum TLS1_TXT_DHE_DSS_WITH_AES_256_GCM_SHA384 = "DHE-DSS-AES256-GCM-SHA384";
enum TLS1_TXT_DH_DSS_WITH_AES_128_GCM_SHA256 = "DH-DSS-AES128-GCM-SHA256";
enum TLS1_TXT_DH_DSS_WITH_AES_256_GCM_SHA384 = "DH-DSS-AES256-GCM-SHA384";
enum TLS1_TXT_ADH_WITH_AES_128_GCM_SHA256 = "ADH-AES128-GCM-SHA256";
enum TLS1_TXT_ADH_WITH_AES_256_GCM_SHA384 = "ADH-AES256-GCM-SHA384";

/* ECDH HMAC based ciphersuites from RFC 5289. */
enum TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256 = "ECDHE-ECDSA-AES128-SHA256";
enum TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384 = "ECDHE-ECDSA-AES256-SHA384";
enum TLS1_TXT_ECDH_ECDSA_WITH_AES_128_SHA256 = "ECDH-ECDSA-AES128-SHA256";
enum TLS1_TXT_ECDH_ECDSA_WITH_AES_256_SHA384 = "ECDH-ECDSA-AES256-SHA384";
enum TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256 = "ECDHE-RSA-AES128-SHA256";
enum TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384 = "ECDHE-RSA-AES256-SHA384";
enum TLS1_TXT_ECDH_RSA_WITH_AES_128_SHA256 = "ECDH-RSA-AES128-SHA256";
enum TLS1_TXT_ECDH_RSA_WITH_AES_256_SHA384 = "ECDH-RSA-AES256-SHA384";

/* ECDH GCM based ciphersuites from RFC 5289. */
enum TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = "ECDHE-ECDSA-AES128-GCM-SHA256";
enum TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = "ECDHE-ECDSA-AES256-GCM-SHA384";
enum TLS1_TXT_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = "ECDH-ECDSA-AES128-GCM-SHA256";
enum TLS1_TXT_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = "ECDH-ECDSA-AES256-GCM-SHA384";
enum TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = "ECDHE-RSA-AES128-GCM-SHA256";
enum TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = "ECDHE-RSA-AES256-GCM-SHA384";
enum TLS1_TXT_ECDH_RSA_WITH_AES_128_GCM_SHA256 = "ECDH-RSA-AES128-GCM-SHA256";
enum TLS1_TXT_ECDH_RSA_WITH_AES_256_GCM_SHA384 = "ECDH-RSA-AES256-GCM-SHA384";

/* ChaCha20-Poly1305 based ciphersuites. */
enum TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305 = "ECDHE-RSA-CHACHA20-POLY1305";
enum TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 = "ECDHE-ECDSA-CHACHA20-POLY1305";
enum TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305 = "DHE-RSA-CHACHA20-POLY1305";

/* TLS 1.3 cipher suites from RFC 8446 appendix B.4. */
static if ((libressl_d.openssl.opensslfeatures.LIBRESSL_HAS_TLS1_3) || (libressl_d.openssl.opensslfeatures.LIBRESSL_INTERNAL)) {
	enum TLS1_3_TXT_AES_128_GCM_SHA256 = "AEAD-AES128-GCM-SHA256";
	enum TLS1_3_TXT_AES_256_GCM_SHA384 = "AEAD-AES256-GCM-SHA384";
	enum TLS1_3_TXT_CHACHA20_POLY1305_SHA256 = "AEAD-CHACHA20-POLY1305-SHA256";
	enum TLS1_3_TXT_AES_128_CCM_SHA256 = "AEAD-AES128-CCM-SHA256";
	enum TLS1_3_TXT_AES_128_CCM_8_SHA256 = "AEAD-AES128-CCM-8-SHA256";
}

enum TLS_CT_RSA_SIGN = 1;
enum TLS_CT_DSS_SIGN = 2;
enum TLS_CT_RSA_FIXED_DH = 3;
enum TLS_CT_DSS_FIXED_DH = 4;
enum TLS_CT_GOST94_SIGN = 21;
enum TLS_CT_GOST01_SIGN = 22;
enum TLS_CT_ECDSA_SIGN = 64;
enum TLS_CT_RSA_FIXED_ECDH = 65;
enum TLS_CT_ECDSA_FIXED_ECDH = 66;
enum TLS_CT_GOST12_256_SIGN = 67;
enum TLS_CT_GOST12_512_SIGN = 68;

/**
 *  pre-IANA, for compat
 */
enum TLS_CT_GOST12_256_SIGN_COMPAT = 238;

/**
 *  pre-IANA, for compat
 */
enum TLS_CT_GOST12_512_SIGN_COMPAT = 239;

/**
 * when correcting this number, correct also SSL3_CT_NUMBER in ssl3.h (see
 * comment there)
 */
enum TLS_CT_NUMBER = 13;

enum TLS1_FINISH_MAC_LENGTH = 12;

enum TLS_MD_MAX_CONST_SIZE = 20;
enum TLS_MD_CLIENT_FINISH_CONST = "client finished";
enum TLS_MD_CLIENT_FINISH_CONST_SIZE = 15;
enum TLS_MD_SERVER_FINISH_CONST = "server finished";
enum TLS_MD_SERVER_FINISH_CONST_SIZE = 15;
enum TLS_MD_SERVER_WRITE_KEY_CONST = "server write key";
enum TLS_MD_SERVER_WRITE_KEY_CONST_SIZE = 16;
enum TLS_MD_KEY_EXPANSION_CONST = "key expansion";
enum TLS_MD_KEY_EXPANSION_CONST_SIZE = 13;
enum TLS_MD_CLIENT_WRITE_KEY_CONST = "client write key";
enum TLS_MD_CLIENT_WRITE_KEY_CONST_SIZE = 16;

version (none) {
	enum TLS_MD_SERVER_WRITE_KEY_CONST = "server write key";
	enum TLS_MD_SERVER_WRITE_KEY_CONST_SIZE = 16;
}

enum TLS_MD_IV_BLOCK_CONST = "IV block";
enum TLS_MD_IV_BLOCK_CONST_SIZE = 8;
enum TLS_MD_MASTER_SECRET_CONST = "master secret";
enum TLS_MD_MASTER_SECRET_CONST_SIZE = 13;

version (LIBRESSL_INTERNAL) {
	/**
	 * TLS Session Ticket extension struct.
	 */
	struct tls_session_ticket_ext_st
	{
		ushort length_;
		void* data;
	}
}
