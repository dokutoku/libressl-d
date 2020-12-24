/* $OpenBSD: x509_vfy.h,v 1.30 2018/08/24 19:21:09 tb Exp $ */
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
module libressl_d.openssl.x509_vfy;


private static import core.stdc.config;
private static import libressl_d.compat.time;
private static import libressl_d.openssl.asn1;
private static import libressl_d.openssl.ossl_typ;
private static import libressl_d.openssl.stack;
private static import libressl_d.openssl.x509v3;
public import libressl_d.openssl.bio;
public import libressl_d.openssl.crypto;
public import libressl_d.openssl.lhash;
public import libressl_d.openssl.opensslconf;
public import libressl_d.openssl.x509;

//#if !defined(HEADER_X509_H)
	//public import libressl_d.openssl.x509;
	/*
	 * openssl/x509.h ends up #include-ing this file at about the only
	 * appropriate moment.
	 */
//#endif

//#if !defined(OPENSSL_NO_LHASH)
	//public import libressl_d.openssl.lhash;
//#endif

extern (C):
nothrow @nogc:

struct x509_file_st
{
	/**
	 * number of paths to files or directories
	 */
	int num_paths;

	int num_alloced;

	/**
	 * the list of paths or directories
	 */
	char** paths;

	int* path_type;
}

alias X509_CERT_FILE_CTX = .x509_file_st;

/*******************************/
/*
 * SL_CTX . X509_STORE
 *     . X509_LOOKUP
 *         .X509_LOOKUP_METHOD
 *     . X509_LOOKUP
 *         .X509_LOOKUP_METHOD
 *
 * SSL    . X509_STORE_CTX
 *     .X509_STORE
 *
 * The X509_STORE holds the tables etc for verification stuff.
 * A X509_STORE_CTX is used while validating a single certificate.
 * The X509_STORE has X509_LOOKUPs for looking up certs.
 * The X509_STORE then calls a function to actually verify the
 * certificate chain.
 */

enum X509_LU_RETRY = -1;
enum X509_LU_FAIL = 0;
enum X509_LU_X509 = 1;
enum X509_LU_CRL = 2;
enum X509_LU_PKEY = 3;

struct x509_object_st
{
	/**
	 * one of the above types
	 */
	int type;

	union data_
	{
		char* ptr_;
		libressl_d.openssl.ossl_typ.X509* x509;
		libressl_d.openssl.ossl_typ.X509_CRL* crl;
		libressl_d.openssl.ossl_typ.EVP_PKEY* pkey;
	}

	data_ data;
}

alias X509_OBJECT = .x509_object_st;

alias X509_LOOKUP = .x509_lookup_st;

//DECLARE_STACK_OF(X509_LOOKUP)
struct stack_st_X509_LOOKUP
{
	libressl_d.openssl.stack._STACK stack;
}

//DECLARE_STACK_OF(X509_OBJECT)
struct stack_st_X509_OBJECT
{
	libressl_d.openssl.stack._STACK stack;
}

/**
 * This is a static that defines the function interface
 */
struct x509_lookup_method_st
{
	const (char)* name;
	int function(.X509_LOOKUP* ctx) new_item;
	void function(.X509_LOOKUP* ctx) free;
	int function(.X509_LOOKUP* ctx) init;
	int function(.X509_LOOKUP* ctx) shutdown;
	int function(.X509_LOOKUP* ctx, int cmd, const (char)* argc, core.stdc.config.c_long argl, char** ret) ctrl;
	int function(.X509_LOOKUP* ctx, int type, libressl_d.openssl.ossl_typ.X509_NAME* name, .X509_OBJECT* ret) get_by_subject;
	int function(.X509_LOOKUP* ctx, int type, libressl_d.openssl.ossl_typ.X509_NAME* name, libressl_d.openssl.ossl_typ.ASN1_INTEGER* serial, .X509_OBJECT* ret) get_by_issuer_serial;
	int function(.X509_LOOKUP* ctx, int type, const (ubyte)* bytes, int len, .X509_OBJECT* ret) get_by_fingerprint;
	int function(.X509_LOOKUP* ctx, int type, const (char)* str, int len, .X509_OBJECT* ret) get_by_alias;
}

alias X509_LOOKUP_METHOD = .x509_lookup_method_st;

package alias X509_VERIFY_PARAM_ID_st = void;
alias X509_VERIFY_PARAM_ID = X509_VERIFY_PARAM_ID_st;

/**
 * This structure hold all parameters associated with a verify operation
 * by including an X509_VERIFY_PARAM structure in related structures the
 * parameters used can be customized
 */
struct X509_VERIFY_PARAM_st
{
	char* name;

	/**
	 * Time to use
	 */
	libressl_d.compat.time.time_t check_time;

	/**
	 * Inheritance flags
	 */
	core.stdc.config.c_ulong inh_flags;

	/**
	 * Various verify flags
	 */
	core.stdc.config.c_ulong flags;

	/**
	 * purpose to check untrusted certificates
	 */
	int purpose;

	/**
	 * trust setting to check
	 */
	int trust;

	/**
	 * Verify depth
	 */
	int depth;

	/**
	 * Permissible policies
	 */
	libressl_d.openssl.asn1.stack_st_ASN1_OBJECT* policies;

	/**
	 * opaque ID data
	 */
	.X509_VERIFY_PARAM_ID* id;
}

alias X509_VERIFY_PARAM = .X509_VERIFY_PARAM_st;

//DECLARE_STACK_OF(X509_VERIFY_PARAM)
struct stack_st_X509_VERIFY_PARAM
{
	libressl_d.openssl.stack._STACK stack;
}

/**
 * This is used to hold everything.  It is used for all certificate
 * validation.  Once we have a certificate chain, the 'verify'
 * function is then called to actually check the cert chain.
 */
struct x509_store_st
{
	/* The following is a cache of trusted certs */

	/**
	 * if true, stash any hits
	 */
	int cache;

	/**
	 * Cache of all objects
	 */
	.stack_st_X509_OBJECT* objs;

	/* These are external lookup methods */
	.stack_st_X509_LOOKUP* get_cert_methods;

	.X509_VERIFY_PARAM* param;

	/* Callbacks for various operations */

	/**
	 * called to verify a certificate
	 */
	int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx) verify;

	/**
	 * error callback
	 */
	int function(int ok, libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx) verify_cb;

	/**
	 * get issuers cert from ctx
	 */
	int function(libressl_d.openssl.ossl_typ.X509** issuer, libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509* x) get_issuer;

	/**
	 * check issued
	 */
	int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509* x, libressl_d.openssl.ossl_typ.X509* issuer) check_issued;

	/**
	 * Check revocation status of chain
	 */
	int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx) check_revocation;

	/**
	 * retrieve CRL
	 */
	int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509_CRL** crl, libressl_d.openssl.ossl_typ.X509* x) get_crl;

	/**
	 * Check CRL validity
	 */
	int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509_CRL* crl) check_crl;

	/**
	 * Check certificate against CRL
	 */
	int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509_CRL* crl, libressl_d.openssl.ossl_typ.X509* x) cert_crl;

	libressl_d.openssl.x509.stack_st_X509* function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509_NAME* nm) lookup_certs;
	libressl_d.openssl.x509.stack_st_X509_CRL* function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509_NAME* nm) lookup_crls;
	int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx) cleanup;

	libressl_d.openssl.ossl_typ.CRYPTO_EX_DATA ex_data;
	int references;
}

int X509_STORE_set_depth(libressl_d.openssl.ossl_typ.X509_STORE* store, int depth);

//#define X509_STORE_set_verify_cb_func(ctx, func) (ctx.verify_cb = func)
//#define X509_STORE_set_verify_func(ctx, func) (ctx.verify = func)

/**
 * This is the functions plus an instance of the local variables.
 */
struct x509_lookup_st
{
	/**
	 * have we been started
	 */
	int init;

	/**
	 * don't use us.
	 */
	int skip;

	/**
	 * the functions
	 */
	.X509_LOOKUP_METHOD* method;

	/**
	 * method data
	 */
	char* method_data;

	/**
	 * who owns us
	 */
	libressl_d.openssl.ossl_typ.X509_STORE* store_ctx;
}

/**
 * This is a used when verifying cert chains.  Since the
 * gathering of the cert chain can take some time (and have to be
 * 'retried', this needs to be kept and passed around.
 */
struct x509_store_ctx_st
{
	libressl_d.openssl.ossl_typ.X509_STORE* ctx;

	/**
	 * used when looking up certs
	 */
	int current_method;

	/* The following are set by the caller */

	/**
	 * The cert to check
	 */
	libressl_d.openssl.ossl_typ.X509* cert;

	/**
	 * chain of X509s - untrusted - passed in
	 */
	libressl_d.openssl.x509.stack_st_X509* untrusted;

	/**
	 * set of CRLs passed in
	 */
	libressl_d.openssl.x509.stack_st_X509_CRL* crls;

	.X509_VERIFY_PARAM* param;

	/**
	 * Other info for use with get_issuer()
	 */
	void* other_ctx;

	/* Callbacks for various operations */

	/**
	 * called to verify a certificate
	 */
	int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx) verify;

	/**
	 * error callback
	 */
	int function(int ok, libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx) verify_cb;

	/**
	 * get issuers cert from ctx
	 */
	int function(libressl_d.openssl.ossl_typ.X509** issuer, libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509* x) get_issuer;

	/**
	 * check issued
	 */
	int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509* x, libressl_d.openssl.ossl_typ.X509* issuer) check_issued;

	/**
	 * Check revocation status of chain
	 */
	int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx) check_revocation;

	/**
	 * retrieve CRL
	 */
	int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509_CRL** crl, libressl_d.openssl.ossl_typ.X509* x) get_crl;

	/**
	 * Check CRL validity
	 */
	int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509_CRL* crl) check_crl;

	/**
	 * Check certificate against CRL
	 */
	int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509_CRL* crl, libressl_d.openssl.ossl_typ.X509* x) cert_crl;

	int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx) check_policy;
	libressl_d.openssl.x509.stack_st_X509* function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509_NAME* nm) lookup_certs;
	libressl_d.openssl.x509.stack_st_X509_CRL* function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509_NAME* nm) lookup_crls;
	int function(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx) cleanup;

	/* The following is built up */

	/**
	 * if 0, rebuild chain
	 */
	int valid;

	/**
	 * index of last untrusted cert
	 */
	int last_untrusted;

	/**
	 * chain of X509s - built up and trusted
	 */
	libressl_d.openssl.x509.stack_st_X509* chain;

	/**
	 * Valid policy tree
	 */
	libressl_d.openssl.ossl_typ.X509_POLICY_TREE* tree;

	/**
	 * Require explicit policy value
	 */
	int explicit_policy;

	/* When something goes wrong, this is why */
	int error_depth;
	int error;
	libressl_d.openssl.ossl_typ.X509* current_cert;

	/**
	 * cert currently being tested as valid issuer
	 */
	libressl_d.openssl.ossl_typ.X509* current_issuer;

	/**
	 * current CRL
	 */
	libressl_d.openssl.ossl_typ.X509_CRL* current_crl;

	/**
	 * score of current CRL
	 */
	int current_crl_score;

	/**
	 * Reason mask
	 */
	uint current_reasons;

	/**
	 * For CRL path validation: parent context
	 */
	libressl_d.openssl.ossl_typ.X509_STORE_CTX* parent;

	libressl_d.openssl.ossl_typ.CRYPTO_EX_DATA ex_data;
}

void X509_STORE_CTX_set_depth(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, int depth);

//#define X509_STORE_CTX_set_app_data(ctx, data) X509_STORE_CTX_set_ex_data(ctx, 0, data)
//#define X509_STORE_CTX_get_app_data(ctx) X509_STORE_CTX_get_ex_data(ctx, 0)

enum X509_L_FILE_LOAD = 1;
enum X509_L_ADD_DIR = 2;
enum X509_L_MEM = 3;

//#define X509_LOOKUP_load_file(x, name, type) X509_LOOKUP_ctrl(x, .X509_L_FILE_LOAD, name, cast(core.stdc.config.c_long)(type), null)

//#define X509_LOOKUP_add_dir(x, name, type) X509_LOOKUP_ctrl(x, .X509_L_ADD_DIR, name, cast(core.stdc.config.c_long)(type), null)

//#define X509_LOOKUP_add_mem(x, iov, type) X509_LOOKUP_ctrl(x, .X509_L_MEM, cast(const (char)*)(iov), cast(core.stdc.config.c_long)(type), null)

enum X509_V_OK = 0;
enum X509_V_ERR_UNSPECIFIED = 1;
enum X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = 2;
enum X509_V_ERR_UNABLE_TO_GET_CRL = 3;
enum X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = 4;
enum X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE = 5;
enum X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = 6;
enum X509_V_ERR_CERT_SIGNATURE_FAILURE = 7;
enum X509_V_ERR_CRL_SIGNATURE_FAILURE = 8;
enum X509_V_ERR_CERT_NOT_YET_VALID = 9;
enum X509_V_ERR_CERT_HAS_EXPIRED = 10;
enum X509_V_ERR_CRL_NOT_YET_VALID = 11;
enum X509_V_ERR_CRL_HAS_EXPIRED = 12;
enum X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 13;
enum X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD = 14;
enum X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD = 15;
enum X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 16;
enum X509_V_ERR_OUT_OF_MEM = 17;
enum X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18;
enum X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19;
enum X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20;
enum X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = 21;
enum X509_V_ERR_CERT_CHAIN_TOO_LONG = 22;
enum X509_V_ERR_CERT_REVOKED = 23;
enum X509_V_ERR_INVALID_CA = 24;
enum X509_V_ERR_PATH_LENGTH_EXCEEDED = 25;
enum X509_V_ERR_INVALID_PURPOSE = 26;
enum X509_V_ERR_CERT_UNTRUSTED = 27;
enum X509_V_ERR_CERT_REJECTED = 28;
/* These are 'informational' when looking for issuer cert */
enum X509_V_ERR_SUBJECT_ISSUER_MISMATCH = 29;
enum X509_V_ERR_AKID_SKID_MISMATCH = 30;
enum X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH = 31;
enum X509_V_ERR_KEYUSAGE_NO_CERTSIGN = 32;

enum X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER = 33;
enum X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION = 34;
enum X509_V_ERR_KEYUSAGE_NO_CRL_SIGN = 35;
enum X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION = 36;
enum X509_V_ERR_INVALID_NON_CA = 37;
enum X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED = 38;
enum X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 39;
enum X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED = 40;

enum X509_V_ERR_INVALID_EXTENSION = 41;
enum X509_V_ERR_INVALID_POLICY_EXTENSION = 42;
enum X509_V_ERR_NO_EXPLICIT_POLICY = 43;
enum X509_V_ERR_DIFFERENT_CRL_SCOPE = 44;
enum X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE = 45;

enum X509_V_ERR_UNNESTED_RESOURCE = 46;

enum X509_V_ERR_PERMITTED_VIOLATION = 47;
enum X509_V_ERR_EXCLUDED_VIOLATION = 48;
enum X509_V_ERR_SUBTREE_MINMAX = 49;
enum X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE = 51;
enum X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX = 52;
enum X509_V_ERR_UNSUPPORTED_NAME_SYNTAX = 53;
enum X509_V_ERR_CRL_PATH_VALIDATION_ERROR = 54;

/**
 * The application is not happy
 */
enum X509_V_ERR_APPLICATION_VERIFICATION = 50;

/* Host, email and IP check errors */
enum X509_V_ERR_HOSTNAME_MISMATCH = 62;
enum X509_V_ERR_EMAIL_MISMATCH = 63;
enum X509_V_ERR_IP_ADDRESS_MISMATCH = 64;

/**
 * Caller error
 */
enum X509_V_ERR_INVALID_CALL = 65;

/**
 * Issuer lookup error
 */
enum X509_V_ERR_STORE_LOOKUP = 66;

/* Certificate verify flags */

/**
 * Send issuer+subject checks to verify_cb
 */
enum X509_V_FLAG_CB_ISSUER_CHECK = 0x01;

/**
 * Use check time instead of current time
 */
enum X509_V_FLAG_USE_CHECK_TIME = 0x02;

/**
 * Lookup CRLs
 */
enum X509_V_FLAG_CRL_CHECK = 0x04;

/**
 * Lookup CRLs for whole chain
 */
enum X509_V_FLAG_CRL_CHECK_ALL = 0x08;

/**
 * Ignore unhandled critical extensions
 */
enum X509_V_FLAG_IGNORE_CRITICAL = 0x10;

/**
 * Disable workarounds for broken certificates
 */
enum X509_V_FLAG_X509_STRICT = 0x20;

/**
 * Enable proxy certificate validation
 */
enum X509_V_FLAG_ALLOW_PROXY_CERTS = 0x40;

/**
 * Enable policy checking
 */
enum X509_V_FLAG_POLICY_CHECK = 0x80;

/**
 * Policy variable require-explicit-policy
 */
enum X509_V_FLAG_EXPLICIT_POLICY = 0x0100;

/**
 * Policy variable inhibit-any-policy
 */
enum X509_V_FLAG_INHIBIT_ANY = 0x0200;

/**
 * Policy variable inhibit-policy-mapping
 */
enum X509_V_FLAG_INHIBIT_MAP = 0x0400;

/**
 * Notify callback that policy is OK
 */
enum X509_V_FLAG_NOTIFY_POLICY = 0x0800;

/**
 * Extended CRL features such as indirect CRLs, alternate CRL signing keys
 */
enum X509_V_FLAG_EXTENDED_CRL_SUPPORT = 0x1000;

/**
 * Delta CRL support
 */
enum X509_V_FLAG_USE_DELTAS = 0x2000;

/**
 * Check selfsigned CA signature
 */
enum X509_V_FLAG_CHECK_SS_SIGNATURE = 0x4000;

/**
 * Use trusted store first
 */
enum X509_V_FLAG_TRUSTED_FIRST = 0x8000;

/**
 * Allow partial chains if at least one certificate is in trusted store
 */
enum X509_V_FLAG_PARTIAL_CHAIN = 0x080000;

/**
 * If the initial chain is not trusted, do not attempt to build an alternative
 * chain. Alternate chain checking was introduced in 1.0.2b. Setting this flag
 * will force the behaviour to match that of previous versions.
 */
enum X509_V_FLAG_NO_ALT_CHAINS = 0x100000;

/**
 * Do not check certificate or CRL validity against current time.
 */
enum X509_V_FLAG_NO_CHECK_TIME = 0x200000;

enum X509_VP_FLAG_DEFAULT = 0x01;
enum X509_VP_FLAG_OVERWRITE = 0x02;
enum X509_VP_FLAG_RESET_FLAGS = 0x04;
enum X509_VP_FLAG_LOCKED = 0x08;
enum X509_VP_FLAG_ONCE = 0x10;

/**
 * Internal use: mask of policy related options
 */
enum X509_V_FLAG_POLICY_MASK = .X509_V_FLAG_POLICY_CHECK | .X509_V_FLAG_EXPLICIT_POLICY | .X509_V_FLAG_INHIBIT_ANY | .X509_V_FLAG_INHIBIT_MAP;

int X509_OBJECT_idx_by_subject(.stack_st_X509_OBJECT* h, int type, libressl_d.openssl.ossl_typ.X509_NAME* name);
.X509_OBJECT* X509_OBJECT_retrieve_by_subject(.stack_st_X509_OBJECT* h, int type, libressl_d.openssl.ossl_typ.X509_NAME* name);
.X509_OBJECT* X509_OBJECT_retrieve_match(.stack_st_X509_OBJECT * h, .X509_OBJECT* x);
int X509_OBJECT_up_ref_count(.X509_OBJECT* a);
int X509_OBJECT_get_type(const (.X509_OBJECT)* a);
void X509_OBJECT_free_contents(.X509_OBJECT* a);
libressl_d.openssl.ossl_typ.X509* X509_OBJECT_get0_X509(const (.X509_OBJECT)* xo);
libressl_d.openssl.ossl_typ.X509_CRL* X509_OBJECT_get0_X509_CRL(.X509_OBJECT* xo);

libressl_d.openssl.ossl_typ.X509_STORE* X509_STORE_new();
void X509_STORE_free(libressl_d.openssl.ossl_typ.X509_STORE* v);
int X509_STORE_up_ref(libressl_d.openssl.ossl_typ.X509_STORE* x);
libressl_d.openssl.x509.stack_st_X509* X509_STORE_get1_certs(libressl_d.openssl.ossl_typ.X509_STORE_CTX* st, libressl_d.openssl.ossl_typ.X509_NAME* nm);
libressl_d.openssl.x509.stack_st_X509_CRL* X509_STORE_get1_crls(libressl_d.openssl.ossl_typ.X509_STORE_CTX* st, libressl_d.openssl.ossl_typ.X509_NAME* nm);
.stack_st_X509_OBJECT* X509_STORE_get0_objects(libressl_d.openssl.ossl_typ.X509_STORE* xs);
void* X509_STORE_get_ex_data(libressl_d.openssl.ossl_typ.X509_STORE* xs, int idx);
int X509_STORE_set_ex_data(libressl_d.openssl.ossl_typ.X509_STORE* xs, int idx, void* data);

//#define X509_STORE_get_ex_new_index(l, p, newf, dupf, freef) libressl_d.openssl.crypto.CRYPTO_get_ex_new_index(libressl_d.openssl.crypto.CRYPTO_EX_INDEX_X509_STORE, l, p, newf, dupf, freef)

int X509_STORE_set_flags(libressl_d.openssl.ossl_typ.X509_STORE* ctx, core.stdc.config.c_ulong flags);
int X509_STORE_set_purpose(libressl_d.openssl.ossl_typ.X509_STORE* ctx, int purpose);
int X509_STORE_set_trust(libressl_d.openssl.ossl_typ.X509_STORE* ctx, int trust);
int X509_STORE_set1_param(libressl_d.openssl.ossl_typ.X509_STORE* ctx, .X509_VERIFY_PARAM* pm);
.X509_VERIFY_PARAM* X509_STORE_get0_param(libressl_d.openssl.ossl_typ.X509_STORE* ctx);

void X509_STORE_set_verify_cb(libressl_d.openssl.ossl_typ.X509_STORE* ctx, int function(int, libressl_d.openssl.ossl_typ.X509_STORE_CTX*) verify_cb);

libressl_d.openssl.ossl_typ.X509_STORE_CTX* X509_STORE_CTX_new();

int X509_STORE_CTX_get1_issuer(libressl_d.openssl.ossl_typ.X509** issuer, libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509* x);

void X509_STORE_CTX_free(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);
int X509_STORE_CTX_init(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.ossl_typ.X509_STORE* store, libressl_d.openssl.ossl_typ.X509* x509, libressl_d.openssl.x509.stack_st_X509* chain);
libressl_d.openssl.ossl_typ.X509* X509_STORE_CTX_get0_cert(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);
libressl_d.openssl.x509.stack_st_X509* X509_STORE_CTX_get0_chain(libressl_d.openssl.ossl_typ.X509_STORE_CTX* xs);
libressl_d.openssl.ossl_typ.X509_STORE* X509_STORE_CTX_get0_store(libressl_d.openssl.ossl_typ.X509_STORE_CTX* xs);
libressl_d.openssl.x509.stack_st_X509* X509_STORE_CTX_get0_untrusted(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);
void X509_STORE_CTX_set0_untrusted(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.x509.stack_st_X509* sk);
void X509_STORE_CTX_trusted_stack(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.x509.stack_st_X509* sk);
void X509_STORE_CTX_set0_trusted_stack(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, libressl_d.openssl.x509.stack_st_X509* sk);
void X509_STORE_CTX_cleanup(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);

.X509_LOOKUP* X509_STORE_add_lookup(libressl_d.openssl.ossl_typ.X509_STORE* v, .X509_LOOKUP_METHOD* m);

.X509_LOOKUP_METHOD* X509_LOOKUP_hash_dir();
.X509_LOOKUP_METHOD* X509_LOOKUP_file();
.X509_LOOKUP_METHOD* X509_LOOKUP_mem();

int X509_STORE_add_cert(libressl_d.openssl.ossl_typ.X509_STORE* ctx, libressl_d.openssl.ossl_typ.X509* x);
int X509_STORE_add_crl(libressl_d.openssl.ossl_typ.X509_STORE* ctx, libressl_d.openssl.ossl_typ.X509_CRL* x);

int X509_STORE_get_by_subject(libressl_d.openssl.ossl_typ.X509_STORE_CTX* vs, int type, libressl_d.openssl.ossl_typ.X509_NAME* name, .X509_OBJECT* ret);

int X509_LOOKUP_ctrl(.X509_LOOKUP* ctx, int cmd, const (char)* argc, core.stdc.config.c_long argl, char** ret);

int X509_load_cert_file(.X509_LOOKUP* ctx, const (char)* file, int type);
int X509_load_crl_file(.X509_LOOKUP* ctx, const (char)* file, int type);
int X509_load_cert_crl_file(.X509_LOOKUP* ctx, const (char)* file, int type);

.X509_LOOKUP* X509_LOOKUP_new(.X509_LOOKUP_METHOD* method);
void X509_LOOKUP_free(.X509_LOOKUP* ctx);
int X509_LOOKUP_init(.X509_LOOKUP* ctx);
int X509_LOOKUP_by_subject(.X509_LOOKUP* ctx, int type, libressl_d.openssl.ossl_typ.X509_NAME* name, .X509_OBJECT* ret);
int X509_LOOKUP_by_issuer_serial(.X509_LOOKUP* ctx, int type, libressl_d.openssl.ossl_typ.X509_NAME* name, libressl_d.openssl.ossl_typ.ASN1_INTEGER* serial, .X509_OBJECT* ret);
int X509_LOOKUP_by_fingerprint(.X509_LOOKUP* ctx, int type, const (ubyte)* bytes, int len, .X509_OBJECT* ret);
int X509_LOOKUP_by_alias(.X509_LOOKUP* ctx, int type, const (char)* str, int len, .X509_OBJECT* ret);
int X509_LOOKUP_shutdown(.X509_LOOKUP* ctx);

int X509_STORE_load_locations(libressl_d.openssl.ossl_typ.X509_STORE* ctx, const (char)* file, const (char)* dir);
int X509_STORE_load_mem(libressl_d.openssl.ossl_typ.X509_STORE* ctx, void* buf, int len);
int X509_STORE_set_default_paths(libressl_d.openssl.ossl_typ.X509_STORE* ctx);

int X509_STORE_CTX_get_ex_new_index(core.stdc.config.c_long argl, void* argp, libressl_d.openssl.ossl_typ.CRYPTO_EX_new* new_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_dup* dup_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_free* free_func);
int X509_STORE_CTX_set_ex_data(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, int idx, void* data);
void* X509_STORE_CTX_get_ex_data(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, int idx);
int X509_STORE_CTX_get_error(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);
void X509_STORE_CTX_set_error(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, int s);
int X509_STORE_CTX_get_error_depth(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);
libressl_d.openssl.ossl_typ.X509* X509_STORE_CTX_get_current_cert(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);
libressl_d.openssl.ossl_typ.X509* X509_STORE_CTX_get0_current_issuer(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);
libressl_d.openssl.ossl_typ.X509_CRL* X509_STORE_CTX_get0_current_crl(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);
libressl_d.openssl.ossl_typ.X509_STORE_CTX* X509_STORE_CTX_get0_parent_ctx(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);
libressl_d.openssl.x509.stack_st_X509* X509_STORE_CTX_get_chain(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);
libressl_d.openssl.x509.stack_st_X509* X509_STORE_CTX_get1_chain(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);
void X509_STORE_CTX_set_cert(libressl_d.openssl.ossl_typ.X509_STORE_CTX* c, libressl_d.openssl.ossl_typ.X509* x);
void X509_STORE_CTX_set_chain(libressl_d.openssl.ossl_typ.X509_STORE_CTX* c, libressl_d.openssl.x509.stack_st_X509* sk);
void X509_STORE_CTX_set0_crls(libressl_d.openssl.ossl_typ.X509_STORE_CTX* c, libressl_d.openssl.x509.stack_st_X509_CRL* sk);
int X509_STORE_CTX_set_purpose(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, int purpose);
int X509_STORE_CTX_set_trust(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, int trust);
int X509_STORE_CTX_purpose_inherit(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, int def_purpose, int purpose, int trust);
void X509_STORE_CTX_set_flags(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, core.stdc.config.c_ulong flags);
void X509_STORE_CTX_set_time(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, core.stdc.config.c_ulong flags, libressl_d.compat.time.time_t t);
void X509_STORE_CTX_set_verify_cb(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, int function(int, libressl_d.openssl.ossl_typ.X509_STORE_CTX*) verify_cb);

libressl_d.openssl.ossl_typ.X509_POLICY_TREE* X509_STORE_CTX_get0_policy_tree(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);
int X509_STORE_CTX_get_explicit_policy(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);

.X509_VERIFY_PARAM* X509_STORE_CTX_get0_param(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx);
void X509_STORE_CTX_set0_param(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, .X509_VERIFY_PARAM* param);
int X509_STORE_CTX_set_default(libressl_d.openssl.ossl_typ.X509_STORE_CTX* ctx, const (char)* name);

/* X509_VERIFY_PARAM functions */

.X509_VERIFY_PARAM* X509_VERIFY_PARAM_new();
void X509_VERIFY_PARAM_free(.X509_VERIFY_PARAM* param);
int X509_VERIFY_PARAM_inherit(.X509_VERIFY_PARAM* to, const (.X509_VERIFY_PARAM)* from);
int X509_VERIFY_PARAM_set1(.X509_VERIFY_PARAM* to, const (.X509_VERIFY_PARAM)* from);
int X509_VERIFY_PARAM_set1_name(.X509_VERIFY_PARAM* param, const (char)* name);
int X509_VERIFY_PARAM_set_flags(.X509_VERIFY_PARAM* param, core.stdc.config.c_ulong flags);
int X509_VERIFY_PARAM_clear_flags(.X509_VERIFY_PARAM* param, core.stdc.config.c_ulong flags);
core.stdc.config.c_ulong X509_VERIFY_PARAM_get_flags(.X509_VERIFY_PARAM* param);
int X509_VERIFY_PARAM_set_purpose(.X509_VERIFY_PARAM* param, int purpose);
int X509_VERIFY_PARAM_set_trust(.X509_VERIFY_PARAM* param, int trust);
void X509_VERIFY_PARAM_set_depth(.X509_VERIFY_PARAM* param, int depth);
void X509_VERIFY_PARAM_set_time(.X509_VERIFY_PARAM* param, libressl_d.compat.time.time_t t);
int X509_VERIFY_PARAM_add0_policy(.X509_VERIFY_PARAM* param, libressl_d.openssl.asn1.ASN1_OBJECT* policy);
int X509_VERIFY_PARAM_set1_policies(.X509_VERIFY_PARAM* param, libressl_d.openssl.asn1.stack_st_ASN1_OBJECT* policies);
int X509_VERIFY_PARAM_get_depth(const (.X509_VERIFY_PARAM)* param);
int X509_VERIFY_PARAM_set1_host(.X509_VERIFY_PARAM* param, const (char)* name, size_t namelen);
int X509_VERIFY_PARAM_add1_host(.X509_VERIFY_PARAM* param, const (char)* name, size_t namelen);
void X509_VERIFY_PARAM_set_hostflags(.X509_VERIFY_PARAM* param, uint flags);
char* X509_VERIFY_PARAM_get0_peername(.X509_VERIFY_PARAM* param);
int X509_VERIFY_PARAM_set1_email(.X509_VERIFY_PARAM* param, const (char)* email, size_t emaillen);
int X509_VERIFY_PARAM_set1_ip(.X509_VERIFY_PARAM* param, const (ubyte)* ip, size_t iplen);
int X509_VERIFY_PARAM_set1_ip_asc(.X509_VERIFY_PARAM* param, const (char)* ipasc);
const (char)* X509_VERIFY_PARAM_get0_name(const (.X509_VERIFY_PARAM)* param);
const (.X509_VERIFY_PARAM)* X509_VERIFY_PARAM_get0(int id);
int X509_VERIFY_PARAM_get_count();

int X509_VERIFY_PARAM_add0_table(.X509_VERIFY_PARAM* param);
const (.X509_VERIFY_PARAM)* X509_VERIFY_PARAM_lookup(const (char)* name);
void X509_VERIFY_PARAM_table_cleanup();

int X509_policy_check(libressl_d.openssl.ossl_typ.X509_POLICY_TREE** ptree, int* pexplicit_policy, libressl_d.openssl.x509.stack_st_X509* certs, libressl_d.openssl.asn1.stack_st_ASN1_OBJECT* policy_oids, uint flags);

void X509_policy_tree_free(libressl_d.openssl.ossl_typ.X509_POLICY_TREE* tree);

int X509_policy_tree_level_count(const (libressl_d.openssl.ossl_typ.X509_POLICY_TREE)* tree);
libressl_d.openssl.ossl_typ.X509_POLICY_LEVEL* X509_policy_tree_get0_level(const (libressl_d.openssl.ossl_typ.X509_POLICY_TREE)* tree, int i);

libressl_d.openssl.x509v3.stack_st_X509_POLICY_NODE* X509_policy_tree_get0_policies(const (libressl_d.openssl.ossl_typ.X509_POLICY_TREE)* tree);

libressl_d.openssl.x509v3.stack_st_X509_POLICY_NODE* X509_policy_tree_get0_user_policies(const (libressl_d.openssl.ossl_typ.X509_POLICY_TREE)* tree);

int X509_policy_level_node_count(libressl_d.openssl.ossl_typ.X509_POLICY_LEVEL* level);

libressl_d.openssl.ossl_typ.X509_POLICY_NODE* X509_policy_level_get0_node(libressl_d.openssl.ossl_typ.X509_POLICY_LEVEL* level, int i);

const (libressl_d.openssl.asn1.ASN1_OBJECT)* X509_policy_node_get0_policy(const (libressl_d.openssl.ossl_typ.X509_POLICY_NODE)* node);

libressl_d.openssl.x509v3.stack_st_POLICYQUALINFO* X509_policy_node_get0_qualifiers(const (libressl_d.openssl.ossl_typ.X509_POLICY_NODE)* node);
const (libressl_d.openssl.ossl_typ.X509_POLICY_NODE)* X509_policy_node_get0_parent(const (libressl_d.openssl.ossl_typ.X509_POLICY_NODE)* node);
