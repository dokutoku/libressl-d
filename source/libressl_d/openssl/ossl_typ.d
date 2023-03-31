/* $OpenBSD: ossl_typ.h,v 1.22 2022/12/26 07:18:50 jmc Exp $ */
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
module libressl.openssl.ossl_typ;


private static import core.stdc.config;
private static import libressl.openssl.asn1;
private static import libressl.openssl.asn1t;
private static import libressl.openssl.buffer;
private static import libressl.openssl.conf;
private static import libressl.openssl.crypto;
private static import libressl.openssl.ecdsa;
private static import libressl.openssl.rand;
private static import libressl.openssl.rsa;
private static import libressl.openssl.x509;
private static import libressl.openssl.x509v3;
public import libressl.openssl.opensslconf;

alias ASN1_INTEGER = libressl.openssl.asn1.asn1_string_st;
alias ASN1_ENUMERATED = libressl.openssl.asn1.asn1_string_st;
alias ASN1_BIT_STRING = libressl.openssl.asn1.asn1_string_st;
alias ASN1_OCTET_STRING = libressl.openssl.asn1.asn1_string_st;
alias ASN1_PRINTABLESTRING = libressl.openssl.asn1.asn1_string_st;
alias ASN1_T61STRING = libressl.openssl.asn1.asn1_string_st;
alias ASN1_IA5STRING = libressl.openssl.asn1.asn1_string_st;
alias ASN1_GENERALSTRING = libressl.openssl.asn1.asn1_string_st;
alias ASN1_UNIVERSALSTRING = libressl.openssl.asn1.asn1_string_st;
alias ASN1_BMPSTRING = libressl.openssl.asn1.asn1_string_st;
alias ASN1_UTCTIME = libressl.openssl.asn1.asn1_string_st;
alias ASN1_TIME = libressl.openssl.asn1.asn1_string_st;
alias ASN1_GENERALIZEDTIME = libressl.openssl.asn1.asn1_string_st;
alias ASN1_VISIBLESTRING = libressl.openssl.asn1.asn1_string_st;
alias ASN1_UTF8STRING = libressl.openssl.asn1.asn1_string_st;
alias ASN1_STRING = libressl.openssl.asn1.asn1_string_st;
alias ASN1_BOOLEAN = int;
alias ASN1_NULL = int;

struct asn1_object_st;
alias ASN1_OBJECT = .asn1_object_st;

alias ASN1_ITEM = libressl.openssl.asn1t.ASN1_ITEM_st;
struct asn1_pctx_st;
alias ASN1_PCTX = .asn1_pctx_st;

//#if defined(_WIN32) && defined(__WINCRYPT_H__)
	version (LIBRESSL_INTERNAL) {
	} else {
		//pragma(msg, "Warning, overriding WinCrypt defines");
	}

	//#undef X509_NAME
	//#undef libressl.openssl.x509.X509_CERT_PAIR
	//#undef X509_EXTENSIONS
	//#undef OCSP_REQUEST
	//#undef OCSP_RESPONSE
	//#undef PKCS7_ISSUER_AND_SERIAL
//#endif

struct bignum_st;
alias BIGNUM = .bignum_st;

struct bignum_ctx;
alias BN_CTX = .bignum_ctx;

struct bn_blinding_st;
alias BN_BLINDING = .bn_blinding_st;

struct bn_mont_ctx_st;
alias BN_MONT_CTX = .bn_mont_ctx_st;

struct bn_recp_ctx_st;
alias BN_RECP_CTX = .bn_recp_ctx_st;

struct bn_gencb_st;
alias BN_GENCB = .bn_gencb_st;

struct bio_st;
alias BIO = .bio_st;

alias BUF_MEM = libressl.openssl.buffer.buf_mem_st;

struct comp_ctx_st;
alias COMP_CTX = .comp_ctx_st;

struct comp_method_st;
alias COMP_METHOD = .comp_method_st;

struct evp_cipher_st;
alias EVP_CIPHER = .evp_cipher_st;

struct evp_cipher_ctx_st;
alias EVP_CIPHER_CTX = .evp_cipher_ctx_st;

struct env_md_st;
alias EVP_MD = .env_md_st;

struct env_md_ctx_st;
alias EVP_MD_CTX = .env_md_ctx_st;

struct evp_pkey_st;
alias EVP_PKEY = .evp_pkey_st;

struct evp_pkey_asn1_method_st;
alias EVP_PKEY_ASN1_METHOD = .evp_pkey_asn1_method_st;

struct evp_pkey_method_st;
alias EVP_PKEY_METHOD = .evp_pkey_method_st;

struct evp_pkey_ctx_st;
alias EVP_PKEY_CTX = .evp_pkey_ctx_st;

struct evp_Encode_Ctx_st;
alias EVP_ENCODE_CTX = .evp_Encode_Ctx_st;

struct hmac_ctx_st;
alias HMAC_CTX = .hmac_ctx_st;

struct dh_st;
alias DH = .dh_st;

struct dh_method;
alias DH_METHOD = .dh_method;

struct dsa_st;
alias DSA = .dsa_st;

struct dsa_method;
alias DSA_METHOD = .dsa_method;

struct rsa_st;
alias RSA = .rsa_st;

struct rsa_meth_st;
alias RSA_METHOD = .rsa_meth_st;

alias RSA_PSS_PARAMS = libressl.openssl.rsa.rsa_pss_params_st;

alias RAND_METHOD = libressl.openssl.rand.rand_meth_st;

struct ecdh_method;
alias ECDH_METHOD = .ecdh_method;

alias ECDSA_METHOD = libressl.openssl.ecdsa.ecdsa_method;

struct x509_st;
alias X509 = .x509_st;

alias X509_ALGOR = libressl.openssl.x509.X509_algor_st;

struct X509_crl_st;
alias X509_CRL = .X509_crl_st;

struct x509_crl_method_st;
alias X509_CRL_METHOD = .x509_crl_method_st;

struct x509_revoked_st;
alias X509_REVOKED = .x509_revoked_st;

struct X509_name_st;
alias X509_NAME = .X509_name_st;

struct X509_pubkey_st;
alias X509_PUBKEY = .X509_pubkey_st;

struct x509_store_st;
alias X509_STORE = .x509_store_st;

struct x509_store_ctx_st;
alias X509_STORE_CTX = .x509_store_ctx_st;

struct x509_object_st;
alias X509_OBJECT = .x509_object_st;

struct x509_lookup_st;
alias X509_LOOKUP = .x509_lookup_st;

struct x509_lookup_method_st;
alias X509_LOOKUP_METHOD = .x509_lookup_method_st;

struct X509_VERIFY_PARAM_st;
alias X509_VERIFY_PARAM = .X509_VERIFY_PARAM_st;

struct pkcs8_priv_key_info_st;
alias PKCS8_PRIV_KEY_INFO = .pkcs8_priv_key_info_st;

alias X509V3_CTX = libressl.openssl.x509v3.v3_ext_ctx;
alias CONF = libressl.openssl.conf.conf_st;

struct store_st;
alias STORE = .store_st;
struct store_method_st;
alias STORE_METHOD = .store_method_st;

struct ui_st;
alias UI = .ui_st;
struct ui_method_st;
alias UI_METHOD = .ui_method_st;

struct st_ERR_FNS;
alias ERR_FNS = .st_ERR_FNS;

struct engine_st;
alias ENGINE = .engine_st;

struct ssl_st;
alias SSL = .ssl_st;

struct ssl_ctx_st;
alias SSL_CTX = .ssl_ctx_st;

struct X509_POLICY_NODE_st;
alias X509_POLICY_NODE = .X509_POLICY_NODE_st;
struct X509_POLICY_LEVEL_st;
alias X509_POLICY_LEVEL = .X509_POLICY_LEVEL_st;
struct X509_POLICY_TREE_st;
alias X509_POLICY_TREE = .X509_POLICY_TREE_st;
struct X509_POLICY_CACHE_st;
alias X509_POLICY_CACHE = .X509_POLICY_CACHE_st;

alias AUTHORITY_KEYID = libressl.openssl.x509v3.AUTHORITY_KEYID_st;
alias DIST_POINT = libressl.openssl.x509v3.DIST_POINT_st;
alias ISSUING_DIST_POINT = libressl.openssl.x509v3.ISSUING_DIST_POINT_st;
alias NAME_CONSTRAINTS = libressl.openssl.x509v3.NAME_CONSTRAINTS_st;

/* If placed in pkcs12.h, we end up with a circular dependency with pkcs7.h */
//#define DECLARE_PKCS12_STACK_OF(type) /* Nothing */
//#define IMPLEMENT_PKCS12_STACK_OF(type) /* Nothing */

alias CRYPTO_EX_DATA = libressl.openssl.crypto.crypto_ex_data_st;

/* Callback types for crypto.h */
package alias CRYPTO_EX_new = /* Not a function pointer type */ extern (C) nothrow @nogc int function(void* parent, void* ptr_, .CRYPTO_EX_DATA* ad, int idx, core.stdc.config.c_long argl, void* argp);
package alias CRYPTO_EX_free = /* Not a function pointer type */ extern (C) nothrow @nogc void function(void* parent, void* ptr_, .CRYPTO_EX_DATA* ad, int idx, core.stdc.config.c_long argl, void* argp);
package alias CRYPTO_EX_dup = /* Not a function pointer type */ extern (C) nothrow @nogc int function(.CRYPTO_EX_DATA* to, .CRYPTO_EX_DATA* from, void* from_d, int idx, core.stdc.config.c_long argl, void* argp);

struct ocsp_req_ctx_st;
alias OCSP_REQ_CTX = .ocsp_req_ctx_st;

struct ocsp_response_st;
alias OCSP_RESPONSE = .ocsp_response_st;

struct ocsp_responder_id_st;
alias OCSP_RESPID = .ocsp_responder_id_st;

struct sct_st;
alias SCT = .sct_st;

struct sct_ctx_st;
alias SCT_CTX = .sct_ctx_st;

struct ctlog_st;
alias CTLOG = .ctlog_st;

struct ctlog_store_st;
alias CTLOG_STORE = .ctlog_store_st;

struct ct_policy_eval_ctx_st;
alias CT_POLICY_EVAL_CTX = .ct_policy_eval_ctx_st;
