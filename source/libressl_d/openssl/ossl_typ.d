/* $OpenBSD: ossl_typ.h,v 1.13 2015/09/30 04:10:07 doug Exp $ */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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
module libressl_d.openssl.ossl_typ;


private static import core.stdc.config;
private static import libressl_d.openssl.asn1;
private static import libressl_d.openssl.asn1t;
private static import libressl_d.openssl.bn;
private static import libressl_d.openssl.buffer;
private static import libressl_d.openssl.conf;
private static import libressl_d.openssl.crypto;
private static import libressl_d.openssl.dh;
private static import libressl_d.openssl.dsa;
private static import libressl_d.openssl.ecdsa;
private static import libressl_d.openssl.evp;
private static import libressl_d.openssl.ocsp;
private static import libressl_d.openssl.rand;
private static import libressl_d.openssl.rsa;
private static import libressl_d.openssl.ssl;
private static import libressl_d.openssl.x509;
private static import libressl_d.openssl.x509_vfy;
private static import libressl_d.openssl.x509v3;
public import libressl_d.openssl.opensslconf;

alias ASN1_INTEGER = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_ENUMERATED = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_BIT_STRING = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_OCTET_STRING = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_PRINTABLESTRING = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_T61STRING = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_IA5STRING = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_GENERALSTRING = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_UNIVERSALSTRING = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_BMPSTRING = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_UTCTIME = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_TIME = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_GENERALIZEDTIME = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_VISIBLESTRING = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_UTF8STRING = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_STRING = libressl_d.openssl.asn1.asn1_string_st;
alias ASN1_BOOLEAN = int;
alias ASN1_NULL = int;

alias ASN1_ITEM = libressl_d.openssl.asn1t.ASN1_ITEM_st;
//alias ASN1_PCTX = asn1_pctx_st;
package alias ASN1_PCTX = void;

//#if defined(_WIN32) && defined(__WINCRYPT_H__)
	version (LIBRESSL_INTERNAL) {
	} else {
		//pragma(msg, "Warning, overriding WinCrypt defines");
	}

	//#undef X509_NAME
	//#undef libressl_d.openssl.x509.X509_CERT_PAIR
	//#undef X509_EXTENSIONS
	//#undef OCSP_REQUEST
	//#undef OCSP_RESPONSE
	//#undef PKCS7_ISSUER_AND_SERIAL
//#endif

alias BIGNUM = libressl_d.openssl.bn.bignum_st;

//alias BN_CTX = bignum_ctx;
package alias BN_CTX = void;

//alias BN_BLINDING = bn_blinding_st;
package alias BN_BLINDING = void;

alias BN_MONT_CTX = libressl_d.openssl.bn.bn_mont_ctx_st;
alias BN_RECP_CTX = libressl_d.openssl.bn.bn_recp_ctx_st;
alias BN_GENCB = libressl_d.openssl.bn.bn_gencb_st;

alias BUF_MEM = libressl_d.openssl.buffer.buf_mem_st;

alias EVP_CIPHER = libressl_d.openssl.evp.evp_cipher_st;

alias EVP_CIPHER_CTX = libressl_d.openssl.evp.evp_cipher_ctx_st;
alias EVP_MD = libressl_d.openssl.evp.env_md_st;
alias EVP_MD_CTX = libressl_d.openssl.evp.env_md_ctx_st;
alias EVP_PKEY = libressl_d.openssl.evp.evp_pkey_st;

//alias EVP_PKEY_ASN1_METHOD = evp_pkey_asn1_method_st;
package alias EVP_PKEY_ASN1_METHOD = void;

//alias EVP_PKEY_METHOD = evp_pkey_method_st;
package alias EVP_PKEY_METHOD = void;
//alias EVP_PKEY_CTX = evp_pkey_ctx_st;
package alias EVP_PKEY_CTX = void;

alias DH = libressl_d.openssl.dh.dh_st;
alias DH_METHOD = libressl_d.openssl.dh.dh_method;

alias DSA = libressl_d.openssl.dsa.dsa_st;
alias DSA_METHOD = libressl_d.openssl.dsa.dsa_method;

alias RSA = libressl_d.openssl.rsa.rsa_st;
alias RSA_METHOD = libressl_d.openssl.rsa.rsa_meth_st;

alias RAND_METHOD = libressl_d.openssl.rand.rand_meth_st;

//alias ECDH_METHOD = ecdh_method;
package alias ECDH_METHOD = void;
alias ECDSA_METHOD = libressl_d.openssl.ecdsa.ecdsa_method;

alias X509 = libressl_d.openssl.x509.x509_st;
alias X509_ALGOR = libressl_d.openssl.x509.X509_algor_st;
alias X509_CRL = libressl_d.openssl.x509.X509_crl_st;
//alias X509_CRL_METHOD = x509_crl_method_st;
package alias X509_CRL_METHOD = void;
alias X509_REVOKED = libressl_d.openssl.x509.x509_revoked_st;
alias X509_NAME = libressl_d.openssl.x509.X509_name_st;
alias X509_PUBKEY = libressl_d.openssl.x509.X509_pubkey_st;
alias X509_STORE = libressl_d.openssl.x509_vfy.x509_store_st;
alias X509_STORE_CTX = libressl_d.openssl.x509_vfy.x509_store_ctx_st;

alias PKCS8_PRIV_KEY_INFO = libressl_d.openssl.x509.pkcs8_priv_key_info_st;

alias X509V3_CTX = libressl_d.openssl.x509v3.v3_ext_ctx;
alias CONF = libressl_d.openssl.conf.conf_st;

//alias STORE = store_st;
package alias STORE = void;
//alias STORE_METHOD = store_method_st;
package alias STORE_METHOD = void;

//alias UI = ui_st;
package alias UI = void;
//alias UI_METHOD = ui_method_st;
package alias UI_METHOD = void;

//alias ERR_FNS = st_ERR_FNS;
package alias ERR_FNS = void;

//alias ENGINE = engine_st;
package alias ENGINE = void;

alias SSL = libressl_d.openssl.ssl.ssl_st;
alias SSL_CTX = libressl_d.openssl.ssl.ssl_ctx_st;

//alias X509_POLICY_NODE = X509_POLICY_NODE_st;
package alias X509_POLICY_NODE = void;

//alias X509_POLICY_LEVEL = X509_POLICY_LEVEL_st;
package alias X509_POLICY_LEVEL = void;

//alias X509_POLICY_TREE = X509_POLICY_TREE_st;
package alias X509_POLICY_TREE = void;

//alias X509_POLICY_CACHE = X509_POLICY_CACHE_st;
package alias X509_POLICY_CACHE = void;

alias AUTHORITY_KEYID = libressl_d.openssl.x509v3.AUTHORITY_KEYID_st;
alias DIST_POINT = libressl_d.openssl.x509v3.DIST_POINT_st;
alias ISSUING_DIST_POINT = libressl_d.openssl.x509v3.ISSUING_DIST_POINT_st;
alias NAME_CONSTRAINTS = libressl_d.openssl.x509v3.NAME_CONSTRAINTS_st;

/* If placed in pkcs12.h, we end up with a circular depency with pkcs7.h */
//#define DECLARE_PKCS12_STACK_OF(type) /* Nothing */
//#define IMPLEMENT_PKCS12_STACK_OF(type) /* Nothing */

alias CRYPTO_EX_DATA = libressl_d.openssl.crypto.crypto_ex_data_st;

/* Callback types for crypto.h */
alias CRYPTO_EX_new = extern (C) nothrow @nogc int function(void* parent, void* ptr_, .CRYPTO_EX_DATA* ad, int idx, core.stdc.config.c_long argl, void* argp);
alias CRYPTO_EX_free = extern (C) nothrow @nogc void function(void* parent, void* ptr_, .CRYPTO_EX_DATA* ad, int idx, core.stdc.config.c_long argl, void* argp);
alias CRYPTO_EX_dup = extern (C) nothrow @nogc int function(.CRYPTO_EX_DATA* to, .CRYPTO_EX_DATA* from, void* from_d, int idx, core.stdc.config.c_long argl, void* argp);

//alias OCSP_REQ_CTX = ocsp_req_ctx_st;
package alias OCSP_REQ_CTX = void;

alias OCSP_RESPONSE = libressl_d.openssl.ocsp.ocsp_response_st;
alias OCSP_RESPID = libressl_d.openssl.ocsp.ocsp_responder_id_st;
