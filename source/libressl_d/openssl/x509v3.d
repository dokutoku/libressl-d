/* $OpenBSD: x509v3.h,v 1.5 2021/09/02 13:48:39 job Exp $ */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 1999.
 */
/* ====================================================================
 * Copyright (c) 1999-2004 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
module libressl_d.openssl.x509v3;


private static import core.stdc.config;
private static import libressl_d.compat.stdio;
private static import libressl_d.openssl.asn1;
private static import libressl_d.openssl.err;
private static import libressl_d.openssl.ossl_typ;
private static import libressl_d.openssl.safestack;
private static import libressl_d.openssl.stack;
public import libressl_d.openssl.bio;
public import libressl_d.openssl.conf;
public import libressl_d.openssl.opensslconf;
public import libressl_d.openssl.x509;

enum HEADER_X509V3_H = true;

extern (C):
nothrow @nogc:

/* Useful typedefs */

alias X509V3_EXT_NEW = extern (C) nothrow @nogc void* function();
alias X509V3_EXT_FREE = extern (C) nothrow @nogc void function(void*);
alias X509V3_EXT_D2I = extern (C) nothrow @nogc void* function(void*, const (ubyte)**, core.stdc.config.c_long);
alias X509V3_EXT_I2D = extern (C) nothrow @nogc int function(void*, ubyte**);
alias X509V3_EXT_I2V = extern (C) nothrow @nogc libressl_d.openssl.conf.stack_st_CONF_VALUE* function(const (.v3_ext_method)* method, void* ext, libressl_d.openssl.conf.stack_st_CONF_VALUE* extlist);
alias X509V3_EXT_V2I = extern (C) nothrow @nogc void* function(const (.v3_ext_method)* method, .v3_ext_ctx* ctx, libressl_d.openssl.conf.stack_st_CONF_VALUE* values);
alias X509V3_EXT_I2S = extern (C) nothrow @nogc char* function(const (.v3_ext_method)* method, void* ext);
alias X509V3_EXT_S2I = extern (C) nothrow @nogc void* function(const (.v3_ext_method)* method, .v3_ext_ctx* ctx, const (char)* str);
alias X509V3_EXT_I2R = extern (C) nothrow @nogc int function(const (.v3_ext_method)* method, void* ext, libressl_d.openssl.bio.BIO* out_, int indent);
alias X509V3_EXT_R2I = extern (C) nothrow @nogc void* function(const (.v3_ext_method)* method, .v3_ext_ctx* ctx, const (char)* str);

/* V3 extension structure */

struct v3_ext_method
{
	int ext_nid;
	int ext_flags;
	/* If this is set the following four fields are ignored */
	libressl_d.openssl.asn1.ASN1_ITEM_EXP* it;
	/* Old style ASN1 calls */
	.X509V3_EXT_NEW ext_new;
	.X509V3_EXT_FREE ext_free;
	.X509V3_EXT_D2I d2i;
	.X509V3_EXT_I2D i2d;

	/* The following pair is used for string extensions */
	.X509V3_EXT_I2S i2s;
	.X509V3_EXT_S2I s2i;

	/* The following pair is used for multi-valued extensions */
	.X509V3_EXT_I2V i2v;
	.X509V3_EXT_V2I v2i;

	/* The following are used for raw extensions */
	.X509V3_EXT_I2R i2r;
	.X509V3_EXT_R2I r2i;

	/**
	 * Any extension specific data
	 */
	void* usr_data;
}

struct X509V3_CONF_METHOD_st
{
	char* function(void* db, const (char)* section, const (char)* value) get_string;
	libressl_d.openssl.conf.stack_st_CONF_VALUE* function(void* db, const (char)* section) get_section;
	void function(void* db, char* string_) free_string;
	void function(void* db, libressl_d.openssl.conf.stack_st_CONF_VALUE* section) free_section;
}

alias X509V3_CONF_METHOD = .X509V3_CONF_METHOD_st;

enum CTX_TEST = 0x01;

/**
 * Context specific info
 */
struct v3_ext_ctx
{
	int flags;
	libressl_d.openssl.ossl_typ.X509* issuer_cert;
	libressl_d.openssl.ossl_typ.X509* subject_cert;
	libressl_d.openssl.x509.X509_REQ* subject_req;
	libressl_d.openssl.ossl_typ.X509_CRL* crl;
	.X509V3_CONF_METHOD* db_meth;
	void* db;
	/* Maybe more here */
}

alias X509V3_EXT_METHOD = .v3_ext_method;

//DECLARE_STACK_OF(X509V3_EXT_METHOD)
struct stack_st_X509V3_EXT_METHOD
{
	libressl_d.openssl.stack._STACK stack;
}

/* ext_flags values */
enum X509V3_EXT_DYNAMIC = 0x01;
enum X509V3_EXT_CTX_DEP = 0x02;
enum X509V3_EXT_MULTILINE = 0x04;

alias ENUMERATED_NAMES = libressl_d.openssl.asn1.BIT_STRING_BITNAME;

struct BASIC_CONSTRAINTS_st
{
	int ca;
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* pathlen;
}

alias BASIC_CONSTRAINTS = .BASIC_CONSTRAINTS_st;

struct PKEY_USAGE_PERIOD_st
{
	libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME* notBefore;
	libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME* notAfter;
}

alias PKEY_USAGE_PERIOD = .PKEY_USAGE_PERIOD_st;

struct otherName_st
{
	libressl_d.openssl.asn1.ASN1_OBJECT* type_id;
	libressl_d.openssl.asn1.ASN1_TYPE* value;
}

alias OTHERNAME = .otherName_st;

struct EDIPartyName_st
{
	libressl_d.openssl.ossl_typ.ASN1_STRING* nameAssigner;
	libressl_d.openssl.ossl_typ.ASN1_STRING* partyName;
}

alias EDIPARTYNAME = .EDIPartyName_st;

struct GENERAL_NAME_st
{
	enum GEN_OTHERNAME = 0;
	enum GEN_EMAIL = 1;
	enum GEN_DNS = 2;
	enum GEN_X400 = 3;
	enum GEN_DIRNAME = 4;
	enum GEN_EDIPARTY = 5;
	enum GEN_URI = 6;
	enum GEN_IPADD = 7;
	enum GEN_RID = 8;

	int type;

	union d_
	{
		char* ptr_;

		/**
		 * otherName
		 */
		.OTHERNAME* otherName;

		libressl_d.openssl.ossl_typ.ASN1_IA5STRING* rfc822Name;
		libressl_d.openssl.ossl_typ.ASN1_IA5STRING* dNSName;
		libressl_d.openssl.asn1.ASN1_TYPE* x400Address;
		libressl_d.openssl.ossl_typ.X509_NAME* directoryName;
		.EDIPARTYNAME* ediPartyName;
		libressl_d.openssl.ossl_typ.ASN1_IA5STRING* uniformResourceIdentifier;
		libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* iPAddress;
		libressl_d.openssl.asn1.ASN1_OBJECT* registeredID;

		/* Old names */

		/**
		 * iPAddress
		 */
		libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* ip;

		/**
		 * dirn
		 */
		libressl_d.openssl.ossl_typ.X509_NAME* dirn;

		/**
		 * rfc822Name, dNSName, uniformResourceIdentifier
		 */
		libressl_d.openssl.ossl_typ.ASN1_IA5STRING* ia5;

		/**
		 * registeredID
		 */
		libressl_d.openssl.asn1.ASN1_OBJECT* rid;

		/**
		 * x400Address
		 */
		libressl_d.openssl.asn1.ASN1_TYPE* other;
	}

	d_ d;
}

alias GENERAL_NAME = .GENERAL_NAME_st;

alias GENERAL_NAMES = .stack_st_GENERAL_NAME;

struct ACCESS_DESCRIPTION_st
{
	libressl_d.openssl.asn1.ASN1_OBJECT* method;
	.GENERAL_NAME* location;
}

alias ACCESS_DESCRIPTION = .ACCESS_DESCRIPTION_st;

alias AUTHORITY_INFO_ACCESS = .stack_st_ACCESS_DESCRIPTION;

alias EXTENDED_KEY_USAGE = libressl_d.openssl.asn1.stack_st_ASN1_OBJECT;

//DECLARE_STACK_OF(GENERAL_NAME)
struct stack_st_GENERAL_NAME
{
	libressl_d.openssl.stack._STACK stack;
}

//DECLARE_STACK_OF(ACCESS_DESCRIPTION)
struct stack_st_ACCESS_DESCRIPTION
{
	libressl_d.openssl.stack._STACK stack;
}

struct DIST_POINT_NAME_st
{
	int type;

	union name_
	{
		.GENERAL_NAMES* fullname;
		libressl_d.openssl.x509.stack_st_X509_NAME_ENTRY* relativename;
	}

	name_ name;

	/**
	 * If relativename then this contains the full distribution point name
	 */
	libressl_d.openssl.ossl_typ.X509_NAME* dpname;
}

alias DIST_POINT_NAME = .DIST_POINT_NAME_st;

/**
 * All existing reasons
 */
enum CRLDP_ALL_REASONS = 0x807F;

enum CRL_REASON_NONE = -1;
enum CRL_REASON_UNSPECIFIED = 0;
enum CRL_REASON_KEY_COMPROMISE = 1;
enum CRL_REASON_CA_COMPROMISE = 2;
enum CRL_REASON_AFFILIATION_CHANGED = 3;
enum CRL_REASON_SUPERSEDED = 4;
enum CRL_REASON_CESSATION_OF_OPERATION = 5;
enum CRL_REASON_CERTIFICATE_HOLD = 6;
enum CRL_REASON_REMOVE_FROM_CRL = 8;
enum CRL_REASON_PRIVILEGE_WITHDRAWN = 9;
enum CRL_REASON_AA_COMPROMISE = 10;

struct DIST_POINT_st
{
	.DIST_POINT_NAME* distpoint;
	libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* reasons;
	.GENERAL_NAMES* CRLissuer;
	int dp_reasons;
}

alias CRL_DIST_POINTS = .stack_st_DIST_POINT;

//DECLARE_STACK_OF(DIST_POINT)
struct stack_st_DIST_POINT
{
	libressl_d.openssl.stack._STACK stack;
}

struct AUTHORITY_KEYID_st
{
	libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* keyid;
	.GENERAL_NAMES* issuer;
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* serial;
}

/* Strong extranet structures */

struct SXNET_ID_st
{
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* zone;
	libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* user;
}

alias SXNETID = .SXNET_ID_st;

//DECLARE_STACK_OF(SXNETID)
struct stack_st_SXNETID
{
	libressl_d.openssl.stack._STACK stack;
}

struct SXNET_st
{
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* version_;
	.stack_st_SXNETID* ids;
}

alias SXNET = .SXNET_st;

struct NOTICEREF_st
{
	libressl_d.openssl.ossl_typ.ASN1_STRING* organization;
	libressl_d.openssl.asn1.stack_st_ASN1_INTEGER* noticenos;
}

alias NOTICEREF = .NOTICEREF_st;

struct USERNOTICE_st
{
	.NOTICEREF* noticeref;
	libressl_d.openssl.ossl_typ.ASN1_STRING* exptext;
}

alias USERNOTICE = .USERNOTICE_st;

struct POLICYQUALINFO_st
{
	libressl_d.openssl.asn1.ASN1_OBJECT* pqualid;

	union d_
	{
		libressl_d.openssl.ossl_typ.ASN1_IA5STRING* cpsuri;
		.USERNOTICE* usernotice;
		libressl_d.openssl.asn1.ASN1_TYPE* other;
	}

	d_ d;
}

alias POLICYQUALINFO = .POLICYQUALINFO_st;

//DECLARE_STACK_OF(POLICYQUALINFO)
struct stack_st_POLICYQUALINFO
{
	libressl_d.openssl.stack._STACK stack;
}

struct POLICYINFO_st
{
	libressl_d.openssl.asn1.ASN1_OBJECT* policyid;
	.stack_st_POLICYQUALINFO* qualifiers;
}

alias POLICYINFO = .POLICYINFO_st;

alias CERTIFICATEPOLICIES = .stack_st_POLICYINFO;

//DECLARE_STACK_OF(POLICYINFO)
struct stack_st_POLICYINFO
{
	libressl_d.openssl.stack._STACK stack;
}

struct POLICY_MAPPING_st
{
	libressl_d.openssl.asn1.ASN1_OBJECT* issuerDomainPolicy;
	libressl_d.openssl.asn1.ASN1_OBJECT* subjectDomainPolicy;
}

alias POLICY_MAPPING = .POLICY_MAPPING_st;

//DECLARE_STACK_OF(POLICY_MAPPING)
struct stack_st_POLICY_MAPPING
{
	libressl_d.openssl.stack._STACK stack;
}

alias POLICY_MAPPINGS = .stack_st_POLICY_MAPPING;

struct GENERAL_SUBTREE_st
{
	.GENERAL_NAME* base;
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* minimum;
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* maximum;
}

alias GENERAL_SUBTREE = .GENERAL_SUBTREE_st;

//DECLARE_STACK_OF(GENERAL_SUBTREE)
struct stack_st_GENERAL_SUBTREE
{
	libressl_d.openssl.stack._STACK stack;
}

struct NAME_CONSTRAINTS_st
{
	.stack_st_GENERAL_SUBTREE* permittedSubtrees;
	.stack_st_GENERAL_SUBTREE* excludedSubtrees;
}

struct POLICY_CONSTRAINTS_st
{
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* requireExplicitPolicy;
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* inhibitPolicyMapping;
}

alias POLICY_CONSTRAINTS = .POLICY_CONSTRAINTS_st;

/* Proxy certificate structures, see RFC 3820 */
struct PROXY_POLICY_st
{
	libressl_d.openssl.asn1.ASN1_OBJECT* policyLanguage;
	libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* policy;
}

alias PROXY_POLICY = .PROXY_POLICY_st;

struct PROXY_CERT_INFO_EXTENSION_st
{
	libressl_d.openssl.ossl_typ.ASN1_INTEGER* pcPathLengthConstraint;
	.PROXY_POLICY* proxyPolicy;
}

alias PROXY_CERT_INFO_EXTENSION = .PROXY_CERT_INFO_EXTENSION_st;

.PROXY_POLICY* PROXY_POLICY_new();
void PROXY_POLICY_free(.PROXY_POLICY* a);
.PROXY_POLICY* d2i_PROXY_POLICY(.PROXY_POLICY** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PROXY_POLICY(.PROXY_POLICY* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM PROXY_POLICY_it;
.PROXY_CERT_INFO_EXTENSION* PROXY_CERT_INFO_EXTENSION_new();
void PROXY_CERT_INFO_EXTENSION_free(.PROXY_CERT_INFO_EXTENSION* a);
.PROXY_CERT_INFO_EXTENSION* d2i_PROXY_CERT_INFO_EXTENSION(.PROXY_CERT_INFO_EXTENSION** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PROXY_CERT_INFO_EXTENSION(.PROXY_CERT_INFO_EXTENSION* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM PROXY_CERT_INFO_EXTENSION_it;

struct ISSUING_DIST_POINT_st
{
	.DIST_POINT_NAME* distpoint;
	int onlyuser;
	int onlyCA;
	libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* onlysomereasons;
	int indirectCRL;
	int onlyattr;
}

/* Values in idp_flags field */
/**
 * IDP present
 */
enum IDP_PRESENT = 0x01;

/**
 * IDP values inconsistent
 */
enum IDP_INVALID = 0x02;

/**
 * onlyuser true
 */
enum IDP_ONLYUSER = 0x04;

/**
 * onlyCA true
 */
enum IDP_ONLYCA = 0x08;

/**
 * onlyattr true
 */
enum IDP_ONLYATTR = 0x10;

/**
 * indirectCRL true
 */
enum IDP_INDIRECT = 0x20;

/**
 * onlysomereasons present
 */
enum IDP_REASONS = 0x40;

pragma(inline, true)
void X509V3_conf_err(libressl_d.openssl.conf.CONF_VALUE* val)

	in
	{
		assert(val != null);
	}

	do
	{
		libressl_d.openssl.err.ERR_asprintf_error_data(cast(char*)(&("section:%s,name:%s,value:%s\0"[0])), val.section, val.name, val.value);
	}

pragma(inline, true)
void X509V3_set_ctx_test(libressl_d.openssl.ossl_typ.X509V3_CTX* ctx)

	do
	{
		.X509V3_set_ctx(ctx, null, null, null, null, .CTX_TEST);
	}

pragma(inline, true)
pure nothrow @trusted @nogc @live
void X509V3_set_ctx_nodb(scope libressl_d.openssl.ossl_typ.X509V3_CTX* ctx)

	in
	{
		assert(ctx != null);
	}

	do
	{
		ctx.db = null;
	}

//#define EXT_BITSTRING(nid, table) { nid, 0, &ASN1_BIT_STRING_it, 0, 0, 0, 0, 0, 0, cast(.X509V3_EXT_I2V)(.i2v_ASN1_BIT_STRING), cast(.X509V3_EXT_V2I)(.v2i_ASN1_BIT_STRING), null, null, table }

//#define EXT_IA5STRING(nid) { nid, 0, &ASN1_IA5STRING_it, 0, 0, 0, 0, cast(.X509V3_EXT_I2S)(i2s_ASN1_IA5STRING), cast(.X509V3_EXT_S2I)(s2i_ASN1_IA5STRING), 0, 0, 0, 0, null }

//#define EXT_END { -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }

/* X509_PURPOSE stuff */

enum EXFLAG_BCONS = 0x0001;
enum EXFLAG_KUSAGE = 0x0002;
enum EXFLAG_XKUSAGE = 0x0004;
enum EXFLAG_NSCERT = 0x0008;

enum EXFLAG_CA = 0x0010;

/**
 * Self issued.
 */
enum EXFLAG_SI = 0x0020;

enum EXFLAG_V1 = 0x0040;
enum EXFLAG_INVALID = 0x0080;
enum EXFLAG_SET = 0x0100;
enum EXFLAG_CRITICAL = 0x0200;
enum EXFLAG_PROXY = 0x0400;
enum EXFLAG_INVALID_POLICY = 0x0800;
enum EXFLAG_FRESHEST = 0x1000;

/**
 * Self signed.
 */
enum EXFLAG_SS = 0x2000;

enum KU_DIGITAL_SIGNATURE = 0x0080;
enum KU_NON_REPUDIATION = 0x0040;
enum KU_KEY_ENCIPHERMENT = 0x0020;
enum KU_DATA_ENCIPHERMENT = 0x0010;
enum KU_KEY_AGREEMENT = 0x0008;
enum KU_KEY_CERT_SIGN = 0x0004;
enum KU_CRL_SIGN = 0x0002;
enum KU_ENCIPHER_ONLY = 0x0001;
enum KU_DECIPHER_ONLY = 0x8000;

enum NS_SSL_CLIENT = 0x80;
enum NS_SSL_SERVER = 0x40;
enum NS_SMIME = 0x20;
enum NS_OBJSIGN = 0x10;
enum NS_SSL_CA = 0x04;
enum NS_SMIME_CA = 0x02;
enum NS_OBJSIGN_CA = 0x01;
enum NS_ANY_CA = .NS_SSL_CA | .NS_SMIME_CA | .NS_OBJSIGN_CA;

enum XKU_SSL_SERVER = 0x01;
enum XKU_SSL_CLIENT = 0x02;
enum XKU_SMIME = 0x04;
enum XKU_CODE_SIGN = 0x08;
enum XKU_SGC = 0x10;
enum XKU_OCSP_SIGN = 0x20;
enum XKU_TIMESTAMP = 0x40;
enum XKU_DVCS = 0x80;

enum X509_PURPOSE_DYNAMIC = 0x01;
enum X509_PURPOSE_DYNAMIC_NAME = 0x02;

struct x509_purpose_st
{
	int purpose;

	/**
	 * Default trust ID
	 */
	int trust;

	int flags;
	int function(const .x509_purpose_st*, const (libressl_d.openssl.ossl_typ.X509)*, int) check_purpose;
	char* name;
	char* sname;
	void* usr_data;
}

alias X509_PURPOSE = .x509_purpose_st;

enum X509_PURPOSE_SSL_CLIENT = 1;
enum X509_PURPOSE_SSL_SERVER = 2;
enum X509_PURPOSE_NS_SSL_SERVER = 3;
enum X509_PURPOSE_SMIME_SIGN = 4;
enum X509_PURPOSE_SMIME_ENCRYPT = 5;
enum X509_PURPOSE_CRL_SIGN = 6;
enum X509_PURPOSE_ANY = 7;
enum X509_PURPOSE_OCSP_HELPER = 8;
enum X509_PURPOSE_TIMESTAMP_SIGN = 9;

enum X509_PURPOSE_MIN = 1;
enum X509_PURPOSE_MAX = 9;

/* Flags for X509V3_EXT_print() */

enum X509V3_EXT_UNKNOWN_MASK = 0x0FL << 16;

/**
 * Return error for unknown extensions
 */
enum X509V3_EXT_DEFAULT = 0;

/**
 * Print error for unknown extensions
 */
enum X509V3_EXT_ERROR_UNKNOWN = 1L << 16;

/**
 * ASN1 parse unknown extensions
 */
enum X509V3_EXT_PARSE_UNKNOWN = 2L << 16;

/**
 * BIO_dump unknown extensions
 */
enum X509V3_EXT_DUMP_UNKNOWN = 3L << 16;

/* Flags for X509V3_add1_i2d */

enum X509V3_ADD_OP_MASK = 0x0FL;
enum X509V3_ADD_DEFAULT = 0L;
enum X509V3_ADD_APPEND = 1L;
enum X509V3_ADD_REPLACE = 2L;
enum X509V3_ADD_REPLACE_EXISTING = 3L;
enum X509V3_ADD_KEEP_EXISTING = 4L;
enum X509V3_ADD_DELETE = 5L;
enum X509V3_ADD_SILENT = 0x10;

//DECLARE_STACK_OF(X509_PURPOSE)
struct stack_st_X509_PURPOSE
{
	libressl_d.openssl.stack._STACK stack;
}

.BASIC_CONSTRAINTS* BASIC_CONSTRAINTS_new();
void BASIC_CONSTRAINTS_free(.BASIC_CONSTRAINTS* a);
.BASIC_CONSTRAINTS* d2i_BASIC_CONSTRAINTS(.BASIC_CONSTRAINTS** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_BASIC_CONSTRAINTS(.BASIC_CONSTRAINTS* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM BASIC_CONSTRAINTS_it;

.SXNET* SXNET_new();
void SXNET_free(.SXNET* a);
.SXNET* d2i_SXNET(.SXNET** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_SXNET(.SXNET* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM SXNET_it;
.SXNETID* SXNETID_new();
void SXNETID_free(.SXNETID* a);
.SXNETID* d2i_SXNETID(.SXNETID** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_SXNETID(.SXNETID* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM SXNETID_it;

int SXNET_add_id_asc(.SXNET** psx, const (char)* zone, const (char)* user, int userlen);
int SXNET_add_id_ulong(.SXNET** psx, core.stdc.config.c_ulong lzone, const (char)* user, int userlen);
int SXNET_add_id_INTEGER(.SXNET** psx, libressl_d.openssl.ossl_typ.ASN1_INTEGER* izone, const (char)* user, int userlen);

libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* SXNET_get_id_asc(.SXNET* sx, const (char)* zone);
libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* SXNET_get_id_ulong(.SXNET* sx, core.stdc.config.c_ulong lzone);
libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* SXNET_get_id_INTEGER(.SXNET* sx, libressl_d.openssl.ossl_typ.ASN1_INTEGER* zone);

libressl_d.openssl.ossl_typ.AUTHORITY_KEYID* AUTHORITY_KEYID_new();
void AUTHORITY_KEYID_free(libressl_d.openssl.ossl_typ.AUTHORITY_KEYID* a);
libressl_d.openssl.ossl_typ.AUTHORITY_KEYID* d2i_AUTHORITY_KEYID(libressl_d.openssl.ossl_typ.AUTHORITY_KEYID** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_AUTHORITY_KEYID(libressl_d.openssl.ossl_typ.AUTHORITY_KEYID* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM AUTHORITY_KEYID_it;

.PKEY_USAGE_PERIOD* PKEY_USAGE_PERIOD_new();
void PKEY_USAGE_PERIOD_free(.PKEY_USAGE_PERIOD* a);
.PKEY_USAGE_PERIOD* d2i_PKEY_USAGE_PERIOD(.PKEY_USAGE_PERIOD** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKEY_USAGE_PERIOD(.PKEY_USAGE_PERIOD* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM PKEY_USAGE_PERIOD_it;

.GENERAL_NAME* GENERAL_NAME_new();
void GENERAL_NAME_free(.GENERAL_NAME* a);
.GENERAL_NAME* d2i_GENERAL_NAME(.GENERAL_NAME** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_GENERAL_NAME(.GENERAL_NAME* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM GENERAL_NAME_it;
.GENERAL_NAME* GENERAL_NAME_dup(.GENERAL_NAME* a);
int GENERAL_NAME_cmp(.GENERAL_NAME* a, .GENERAL_NAME* b);

libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* v2i_ASN1_BIT_STRING(.X509V3_EXT_METHOD* method, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, libressl_d.openssl.conf.stack_st_CONF_VALUE* nval);
libressl_d.openssl.conf.stack_st_CONF_VALUE* i2v_ASN1_BIT_STRING(.X509V3_EXT_METHOD* method, libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* bits, libressl_d.openssl.conf.stack_st_CONF_VALUE* extlist);

libressl_d.openssl.conf.stack_st_CONF_VALUE* i2v_GENERAL_NAME(.X509V3_EXT_METHOD* method, .GENERAL_NAME* gen, libressl_d.openssl.conf.stack_st_CONF_VALUE* ret);
int GENERAL_NAME_print(libressl_d.openssl.bio.BIO* out_, .GENERAL_NAME* gen);

.GENERAL_NAMES* GENERAL_NAMES_new();
void GENERAL_NAMES_free(.GENERAL_NAMES* a);
.GENERAL_NAMES* d2i_GENERAL_NAMES(.GENERAL_NAMES** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_GENERAL_NAMES(.GENERAL_NAMES* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM GENERAL_NAMES_it;

libressl_d.openssl.conf.stack_st_CONF_VALUE* i2v_GENERAL_NAMES(.X509V3_EXT_METHOD* method, .GENERAL_NAMES* gen, libressl_d.openssl.conf.stack_st_CONF_VALUE* extlist);
.GENERAL_NAMES* v2i_GENERAL_NAMES(const (.X509V3_EXT_METHOD)* method, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, libressl_d.openssl.conf.stack_st_CONF_VALUE* nval);

.OTHERNAME* OTHERNAME_new();
void OTHERNAME_free(.OTHERNAME* a);
.OTHERNAME* d2i_OTHERNAME(.OTHERNAME** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OTHERNAME(.OTHERNAME* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM OTHERNAME_it;
.EDIPARTYNAME* EDIPARTYNAME_new();
void EDIPARTYNAME_free(.EDIPARTYNAME* a);
.EDIPARTYNAME* d2i_EDIPARTYNAME(.EDIPARTYNAME** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_EDIPARTYNAME(.EDIPARTYNAME* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM EDIPARTYNAME_it;
int OTHERNAME_cmp(.OTHERNAME* a, .OTHERNAME* b);
void GENERAL_NAME_set0_value(.GENERAL_NAME* a, int type, void* value);
void* GENERAL_NAME_get0_value(.GENERAL_NAME* a, int* ptype);
int GENERAL_NAME_set0_othername(.GENERAL_NAME* gen, libressl_d.openssl.asn1.ASN1_OBJECT* oid, libressl_d.openssl.asn1.ASN1_TYPE* value);
int GENERAL_NAME_get0_otherName(.GENERAL_NAME* gen, libressl_d.openssl.asn1.ASN1_OBJECT** poid, libressl_d.openssl.asn1.ASN1_TYPE** pvalue);

char* i2s_ASN1_OCTET_STRING(.X509V3_EXT_METHOD* method, const (libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING)* ia5);
libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* s2i_ASN1_OCTET_STRING(.X509V3_EXT_METHOD* method, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, const (char)* str);

.EXTENDED_KEY_USAGE* EXTENDED_KEY_USAGE_new();
void EXTENDED_KEY_USAGE_free(.EXTENDED_KEY_USAGE* a);
.EXTENDED_KEY_USAGE* d2i_EXTENDED_KEY_USAGE(.EXTENDED_KEY_USAGE** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_EXTENDED_KEY_USAGE(.EXTENDED_KEY_USAGE* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM EXTENDED_KEY_USAGE_it;
int i2a_ACCESS_DESCRIPTION(libressl_d.openssl.bio.BIO* bp, const (.ACCESS_DESCRIPTION)* a);

.CERTIFICATEPOLICIES* CERTIFICATEPOLICIES_new();
void CERTIFICATEPOLICIES_free(.CERTIFICATEPOLICIES* a);
.CERTIFICATEPOLICIES* d2i_CERTIFICATEPOLICIES(.CERTIFICATEPOLICIES** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_CERTIFICATEPOLICIES(.CERTIFICATEPOLICIES* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM CERTIFICATEPOLICIES_it;
.POLICYINFO* POLICYINFO_new();
void POLICYINFO_free(.POLICYINFO* a);
.POLICYINFO* d2i_POLICYINFO(.POLICYINFO** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_POLICYINFO(.POLICYINFO* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM POLICYINFO_it;
.POLICYQUALINFO* POLICYQUALINFO_new();
void POLICYQUALINFO_free(.POLICYQUALINFO* a);
.POLICYQUALINFO* d2i_POLICYQUALINFO(.POLICYQUALINFO** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_POLICYQUALINFO(.POLICYQUALINFO* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM POLICYQUALINFO_it;
.USERNOTICE* USERNOTICE_new();
void USERNOTICE_free(.USERNOTICE* a);
.USERNOTICE* d2i_USERNOTICE(.USERNOTICE** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_USERNOTICE(.USERNOTICE* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM USERNOTICE_it;
.NOTICEREF* NOTICEREF_new();
void NOTICEREF_free(.NOTICEREF* a);
.NOTICEREF* d2i_NOTICEREF(.NOTICEREF** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_NOTICEREF(.NOTICEREF* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM NOTICEREF_it;

.CRL_DIST_POINTS* CRL_DIST_POINTS_new();
void CRL_DIST_POINTS_free(.CRL_DIST_POINTS* a);
.CRL_DIST_POINTS* d2i_CRL_DIST_POINTS(.CRL_DIST_POINTS** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_CRL_DIST_POINTS(.CRL_DIST_POINTS* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM CRL_DIST_POINTS_it;
libressl_d.openssl.ossl_typ.DIST_POINT* DIST_POINT_new();
void DIST_POINT_free(libressl_d.openssl.ossl_typ.DIST_POINT* a);
libressl_d.openssl.ossl_typ.DIST_POINT* d2i_DIST_POINT(libressl_d.openssl.ossl_typ.DIST_POINT** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_DIST_POINT(libressl_d.openssl.ossl_typ.DIST_POINT* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM DIST_POINT_it;
.DIST_POINT_NAME* DIST_POINT_NAME_new();
void DIST_POINT_NAME_free(.DIST_POINT_NAME* a);
.DIST_POINT_NAME* d2i_DIST_POINT_NAME(.DIST_POINT_NAME** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_DIST_POINT_NAME(.DIST_POINT_NAME* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM DIST_POINT_NAME_it;
libressl_d.openssl.ossl_typ.ISSUING_DIST_POINT* ISSUING_DIST_POINT_new();
void ISSUING_DIST_POINT_free(libressl_d.openssl.ossl_typ.ISSUING_DIST_POINT* a);
libressl_d.openssl.ossl_typ.ISSUING_DIST_POINT* d2i_ISSUING_DIST_POINT(libressl_d.openssl.ossl_typ.ISSUING_DIST_POINT** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ISSUING_DIST_POINT(libressl_d.openssl.ossl_typ.ISSUING_DIST_POINT* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ISSUING_DIST_POINT_it;

int DIST_POINT_set_dpname(.DIST_POINT_NAME* dpn, libressl_d.openssl.ossl_typ.X509_NAME* iname);

int NAME_CONSTRAINTS_check(libressl_d.openssl.ossl_typ.X509* x, libressl_d.openssl.ossl_typ.NAME_CONSTRAINTS* nc);

.ACCESS_DESCRIPTION* ACCESS_DESCRIPTION_new();
void ACCESS_DESCRIPTION_free(.ACCESS_DESCRIPTION* a);
.ACCESS_DESCRIPTION* d2i_ACCESS_DESCRIPTION(.ACCESS_DESCRIPTION** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ACCESS_DESCRIPTION(.ACCESS_DESCRIPTION* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ACCESS_DESCRIPTION_it;
.AUTHORITY_INFO_ACCESS* AUTHORITY_INFO_ACCESS_new();
void AUTHORITY_INFO_ACCESS_free(.AUTHORITY_INFO_ACCESS* a);
.AUTHORITY_INFO_ACCESS* d2i_AUTHORITY_INFO_ACCESS(.AUTHORITY_INFO_ACCESS** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_AUTHORITY_INFO_ACCESS(.AUTHORITY_INFO_ACCESS* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM AUTHORITY_INFO_ACCESS_it;

extern const libressl_d.openssl.ossl_typ.ASN1_ITEM POLICY_MAPPING_it;
.POLICY_MAPPING* POLICY_MAPPING_new();
void POLICY_MAPPING_free(.POLICY_MAPPING* a);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM POLICY_MAPPINGS_it;

extern const libressl_d.openssl.ossl_typ.ASN1_ITEM GENERAL_SUBTREE_it;
.GENERAL_SUBTREE* GENERAL_SUBTREE_new();
void GENERAL_SUBTREE_free(.GENERAL_SUBTREE* a);

extern const libressl_d.openssl.ossl_typ.ASN1_ITEM NAME_CONSTRAINTS_it;
libressl_d.openssl.ossl_typ.NAME_CONSTRAINTS* NAME_CONSTRAINTS_new();
void NAME_CONSTRAINTS_free(libressl_d.openssl.ossl_typ.NAME_CONSTRAINTS* a);

.POLICY_CONSTRAINTS* POLICY_CONSTRAINTS_new();
void POLICY_CONSTRAINTS_free(.POLICY_CONSTRAINTS* a);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM POLICY_CONSTRAINTS_it;

.GENERAL_NAME* a2i_GENERAL_NAME(.GENERAL_NAME* out_, const (.X509V3_EXT_METHOD)* method, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, int gen_type, const (char)* value, int is_nc);

static assert(libressl_d.openssl.conf.HEADER_CONF_H);
.GENERAL_NAME* v2i_GENERAL_NAME(const (.X509V3_EXT_METHOD)* method, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, libressl_d.openssl.conf.CONF_VALUE* cnf);
.GENERAL_NAME* v2i_GENERAL_NAME_ex(.GENERAL_NAME* out_, const (.X509V3_EXT_METHOD)* method, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, libressl_d.openssl.conf.CONF_VALUE* cnf, int is_nc);
void X509V3_conf_free(libressl_d.openssl.conf.CONF_VALUE* val);

libressl_d.openssl.x509.X509_EXTENSION* X509V3_EXT_nconf_nid(libressl_d.openssl.ossl_typ.CONF* conf, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, int ext_nid, const (char)* value);
libressl_d.openssl.x509.X509_EXTENSION* X509V3_EXT_nconf(libressl_d.openssl.ossl_typ.CONF* conf, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, const (char)* name, const (char)* value);
int X509V3_EXT_add_nconf_sk(libressl_d.openssl.ossl_typ.CONF* conf, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, const (char)* section, libressl_d.openssl.x509.stack_st_X509_EXTENSION** sk);
int X509V3_EXT_add_nconf(libressl_d.openssl.ossl_typ.CONF* conf, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, const (char)* section, libressl_d.openssl.ossl_typ.X509* cert);
int X509V3_EXT_REQ_add_nconf(libressl_d.openssl.ossl_typ.CONF* conf, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, const (char)* section, libressl_d.openssl.x509.X509_REQ* req);
int X509V3_EXT_CRL_add_nconf(libressl_d.openssl.ossl_typ.CONF* conf, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, const (char)* section, libressl_d.openssl.ossl_typ.X509_CRL* crl);

libressl_d.openssl.x509.X509_EXTENSION* X509V3_EXT_conf_nid(libressl_d.openssl.conf.lhash_st_CONF_VALUE* conf, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, int ext_nid, const (char)* value);
libressl_d.openssl.x509.X509_EXTENSION* X509V3_EXT_conf(libressl_d.openssl.conf.lhash_st_CONF_VALUE* conf, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, const (char)* name, const (char)* value);
int X509V3_EXT_add_conf(libressl_d.openssl.conf.lhash_st_CONF_VALUE* conf, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, const (char)* section, libressl_d.openssl.ossl_typ.X509* cert);
int X509V3_EXT_REQ_add_conf(libressl_d.openssl.conf.lhash_st_CONF_VALUE* conf, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, const (char)* section, libressl_d.openssl.x509.X509_REQ* req);
int X509V3_EXT_CRL_add_conf(libressl_d.openssl.conf.lhash_st_CONF_VALUE* conf, libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, const (char)* section, libressl_d.openssl.ossl_typ.X509_CRL* crl);

int X509V3_add_value_bool_nf(const (char)* name, int asn1_bool, libressl_d.openssl.conf.stack_st_CONF_VALUE** extlist);
int X509V3_get_value_bool(const (libressl_d.openssl.conf.CONF_VALUE)* value, int* asn1_bool);
int X509V3_get_value_int(const (libressl_d.openssl.conf.CONF_VALUE)* value, libressl_d.openssl.ossl_typ.ASN1_INTEGER** aint);
void X509V3_set_nconf(libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, libressl_d.openssl.ossl_typ.CONF* conf);
void X509V3_set_conf_lhash(libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, libressl_d.openssl.conf.lhash_st_CONF_VALUE* lhash);

char* X509V3_get_string(libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, const (char)* name, const (char)* section);
libressl_d.openssl.conf.stack_st_CONF_VALUE* X509V3_get_section(libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, const (char)* section);
void X509V3_string_free(libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, char* str);
void X509V3_section_free(libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, libressl_d.openssl.conf.stack_st_CONF_VALUE* section);
void X509V3_set_ctx(libressl_d.openssl.ossl_typ.X509V3_CTX* ctx, libressl_d.openssl.ossl_typ.X509* issuer, libressl_d.openssl.ossl_typ.X509* subject, libressl_d.openssl.x509.X509_REQ* req, libressl_d.openssl.ossl_typ.X509_CRL* crl, int flags);

int X509V3_add_value(const (char)* name, const (char)* value, libressl_d.openssl.conf.stack_st_CONF_VALUE** extlist);
int X509V3_add_value_uchar(const (char)* name, const (ubyte)* value, libressl_d.openssl.conf.stack_st_CONF_VALUE** extlist);
int X509V3_add_value_bool(const (char)* name, int asn1_bool, libressl_d.openssl.conf.stack_st_CONF_VALUE** extlist);
int X509V3_add_value_int(const (char)* name, const (libressl_d.openssl.ossl_typ.ASN1_INTEGER)* aint, libressl_d.openssl.conf.stack_st_CONF_VALUE** extlist);
char* i2s_ASN1_INTEGER(.X509V3_EXT_METHOD* meth, const (libressl_d.openssl.ossl_typ.ASN1_INTEGER)* aint);
libressl_d.openssl.ossl_typ.ASN1_INTEGER* s2i_ASN1_INTEGER(.X509V3_EXT_METHOD* meth, const (char)* value);
char* i2s_ASN1_ENUMERATED(.X509V3_EXT_METHOD* meth, const (libressl_d.openssl.ossl_typ.ASN1_ENUMERATED)* aint);
char* i2s_ASN1_ENUMERATED_TABLE(.X509V3_EXT_METHOD* meth, const (libressl_d.openssl.ossl_typ.ASN1_ENUMERATED)* aint);
int X509V3_EXT_add(.X509V3_EXT_METHOD* ext);
int X509V3_EXT_add_list(.X509V3_EXT_METHOD* extlist);
int X509V3_EXT_add_alias(int nid_to, int nid_from);
void X509V3_EXT_cleanup();

const (.X509V3_EXT_METHOD)* X509V3_EXT_get(libressl_d.openssl.x509.X509_EXTENSION* ext);
const (.X509V3_EXT_METHOD)* X509V3_EXT_get_nid(int nid);
int X509V3_add_standard_extensions();
libressl_d.openssl.conf.stack_st_CONF_VALUE* X509V3_parse_list(const (char)* line);
void* X509V3_EXT_d2i(libressl_d.openssl.x509.X509_EXTENSION* ext);
void* X509V3_get_d2i(const (libressl_d.openssl.x509.stack_st_X509_EXTENSION)* x, int nid, int* crit, int* idx);

libressl_d.openssl.x509.X509_EXTENSION* X509V3_EXT_i2d(int ext_nid, int crit, void* ext_struc);
int X509V3_add1_i2d(libressl_d.openssl.x509.stack_st_X509_EXTENSION** x, int nid, void* value, int crit, core.stdc.config.c_ulong flags);

char* hex_to_string(const (ubyte)* buffer, core.stdc.config.c_long len);
ubyte* string_to_hex(const (char)* str, core.stdc.config.c_long* len);
int name_cmp(const (char)* name, const (char)* cmp);

void X509V3_EXT_val_prn(libressl_d.openssl.bio.BIO* out_, libressl_d.openssl.conf.stack_st_CONF_VALUE* val, int indent, int ml);
int X509V3_EXT_print(libressl_d.openssl.bio.BIO* out_, libressl_d.openssl.x509.X509_EXTENSION* ext, core.stdc.config.c_ulong flag, int indent);
int X509V3_EXT_print_fp(libressl_d.compat.stdio.FILE* out_, libressl_d.openssl.x509.X509_EXTENSION* ext, int flag, int indent);

int X509V3_extensions_print(libressl_d.openssl.bio.BIO* out_, const (char)* title, const (libressl_d.openssl.x509.stack_st_X509_EXTENSION)* exts, core.stdc.config.c_ulong flag, int indent);

int X509_check_ca(libressl_d.openssl.ossl_typ.X509* x);
int X509_check_purpose(libressl_d.openssl.ossl_typ.X509* x, int id, int ca);
int X509_supported_extension(libressl_d.openssl.x509.X509_EXTENSION* ex);
int X509_PURPOSE_set(int* p, int purpose);
int X509_check_issued(libressl_d.openssl.ossl_typ.X509* issuer, libressl_d.openssl.ossl_typ.X509* subject);
int X509_check_akid(libressl_d.openssl.ossl_typ.X509* issuer, libressl_d.openssl.ossl_typ.AUTHORITY_KEYID* akid);
int X509_PURPOSE_get_count();
.X509_PURPOSE* X509_PURPOSE_get0(int idx);
int X509_PURPOSE_get_by_sname(const (char)* sname);
int X509_PURPOSE_get_by_id(int id);
int X509_PURPOSE_add(int id, int trust, int flags, int function(const (.X509_PURPOSE)*, const (libressl_d.openssl.ossl_typ.X509)*, int) ck, const (char)* name, const (char)* sname, void* arg);
char* X509_PURPOSE_get0_name(const (.X509_PURPOSE)* xp);
char* X509_PURPOSE_get0_sname(const (.X509_PURPOSE)* xp);
int X509_PURPOSE_get_trust(const (.X509_PURPOSE)* xp);
void X509_PURPOSE_cleanup();
int X509_PURPOSE_get_id(const (.X509_PURPOSE)*);

libressl_d.openssl.safestack.stack_st_OPENSSL_STRING* X509_get1_email(libressl_d.openssl.ossl_typ.X509* x);
libressl_d.openssl.safestack.stack_st_OPENSSL_STRING* X509_REQ_get1_email(libressl_d.openssl.x509.X509_REQ* x);
void X509_email_free(libressl_d.openssl.safestack.stack_st_OPENSSL_STRING* sk);
libressl_d.openssl.safestack.stack_st_OPENSSL_STRING* X509_get1_ocsp(libressl_d.openssl.ossl_typ.X509* x);

/* Flags for X509_check_* functions */
/**
 * Always check subject name for host match even if subject alt names present
 */
enum X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT = 0x01;

/**
 * Disable wildcard matching for dnsName fields and common name.
 */
enum X509_CHECK_FLAG_NO_WILDCARDS = 0x02;

/**
 * Wildcards must not match a partial label.
 */
enum X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS = 0x04;

/**
 * Allow (non-partial) wildcards to match multiple labels.
 */
enum X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS = 0x08;

/**
 * Constraint verifier subdomain patterns to match a single labels.
 */
enum X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS = 0x10;

/**
 * Disable checking the CN for a hostname, to support modern validation
 */
enum X509_CHECK_FLAG_NEVER_CHECK_SUBJECT = 0x20;

/**
 * Match reference identifiers starting with "." to any sub-domain.
 * This is a non-public flag, turned on implicitly when the subject
 * reference identity is a DNS name.
 */
enum _X509_CHECK_FLAG_DOT_SUBDOMAINS = 0x8000;

int X509_check_host(libressl_d.openssl.ossl_typ.X509* x, const (char)* chk, size_t chklen, uint flags, char** peername);
int X509_check_email(libressl_d.openssl.ossl_typ.X509* x, const (char)* chk, size_t chklen, uint flags);
int X509_check_ip(libressl_d.openssl.ossl_typ.X509* x, const (ubyte)* chk, size_t chklen, uint flags);
int X509_check_ip_asc(libressl_d.openssl.ossl_typ.X509* x, const (char)* ipasc, uint flags);

libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* a2i_IPADDRESS(const (char)* ipasc);
libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* a2i_IPADDRESS_NC(const (char)* ipasc);
int a2i_ipadd(ubyte* ipout, const (char)* ipasc);
int X509V3_NAME_from_section(libressl_d.openssl.ossl_typ.X509_NAME* nm, libressl_d.openssl.conf.stack_st_CONF_VALUE* dn_sk, core.stdc.config.c_ulong chtype);

void X509_POLICY_NODE_print(libressl_d.openssl.bio.BIO* out_, libressl_d.openssl.ossl_typ.X509_POLICY_NODE* node, int indent);

//DECLARE_STACK_OF(X509_POLICY_NODE)
struct stack_st_X509_POLICY_NODE
{
	libressl_d.openssl.stack._STACK stack;
}

version (LIBRESSL_INTERNAL) {
	version (OPENSSL_NO_RFC3779) {
	} else {
		struct ASRange_st
		{
			libressl_d.openssl.ossl_typ.ASN1_INTEGER* min;
			libressl_d.openssl.ossl_typ.ASN1_INTEGER* max;
		}

		alias ASRange = .ASRange_st;

		enum ASIdOrRange_id = 0;
		enum ASIdOrRange_range = 1;

		struct ASIdOrRange_st
		{
			int type;

			union u_
			{
				libressl_d.openssl.ossl_typ.ASN1_INTEGER* id;
				.ASRange* range;
			}

			u_ u;
		}

		alias ASIdOrRange = .ASIdOrRange_st;

		//DECLARE_STACK_OF(ASIdOrRange)
		struct stack_st_ASIdOrRange
		{
			libressl_d.openssl.stack._STACK stack;
		}

		alias ASIdOrRanges = .stack_st_ASIdOrRange;

		enum ASIdentifierChoice_inherit = 0;
		enum ASIdentifierChoice_asIdsOrRanges = 1;

		struct ASIdentifierChoice_st
		{
			int type;

			union u_
			{
				libressl_d.openssl.ossl_typ.ASN1_NULL* inherit;
				.ASIdOrRanges* asIdsOrRanges;
			}

			u_ u;
		}

		alias ASIdentifierChoice = .ASIdentifierChoice_st;

		struct ASIdentifiers_st
		{
			.ASIdentifierChoice* asnum;
			.ASIdentifierChoice* rdi;
		}

		alias ASIdentifiers = .ASIdentifiers_st;

		.ASRange* ASRange_new();
		void ASRange_free(.ASRange* a);
		.ASRange* d2i_ASRange(.ASRange** a, const (ubyte)** in_, core.stdc.config.c_long len);
		int i2d_ASRange(.ASRange* a, ubyte** out_);
		//extern const ASN1_ITEM ASRange_it;

		.ASIdOrRange* ASIdOrRange_new();
		void ASIdOrRange_free(.ASIdOrRange* a);
		.ASIdOrRange* d2i_ASIdOrRange(.ASIdOrRange** a, const (ubyte)** in_, core.stdc.config.c_long len);
		int i2d_ASIdOrRange(.ASIdOrRange* a, ubyte** out_);
		//extern const ASN1_ITEM ASIdOrRange_it;

		.ASIdentifierChoice* ASIdentifierChoice_new();
		void ASIdentifierChoice_free(.ASIdentifierChoice* a);
		.ASIdentifierChoice* d2i_ASIdentifierChoice(.ASIdentifierChoice** a, const (ubyte)** in_, core.stdc.config.c_long len);
		int i2d_ASIdentifierChoice(.ASIdentifierChoice* a, ubyte** out_);
		//extern const ASN1_ITEM ASIdentifierChoice_it;

		.ASIdentifiers* ASIdentifiers_new();
		void ASIdentifiers_free(.ASIdentifiers* a);
		.ASIdentifiers* d2i_ASIdentifiers(.ASIdentifiers** a, const (ubyte)** in_, core.stdc.config.c_long len);
		int i2d_ASIdentifiers(.ASIdentifiers* a, ubyte** out_);
		//extern const ASN1_ITEM ASIdentifiers_it;

		struct IPAddressRange_st
		{
			libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* min;
			libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* max;
		}

		alias IPAddressRange = .IPAddressRange_st;

		enum IPAddressOrRange_addressPrefix = 0;
		enum IPAddressOrRange_addressRange = 1;

		struct IPAddressOrRange_st
		{
			int type;

			union u_
			{
				libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* addressPrefix;
				.IPAddressRange* addressRange;
			}

			u_ u;
		}

		alias IPAddressOrRange = .IPAddressOrRange_st;

		//DECLARE_STACK_OF(IPAddressOrRange)
		struct stack_st_IPAddressOrRange
		{
			libressl_d.openssl.stack._STACK stack;
		}

		alias IPAddressOrRanges = .stack_st_IPAddressOrRange;

		enum IPAddressChoice_inherit = 0;
		enum IPAddressChoice_addressesOrRanges = 1;

		struct IPAddressChoice_st
		{
			int type;

			union u_
			{
				libressl_d.openssl.ossl_typ.ASN1_NULL* inherit;
				.IPAddressOrRanges* addressesOrRanges;
			}

			u_ u;
		}

		alias IPAddressChoice = .IPAddressChoice_st;

		struct IPAddressFamily_st
		{
			libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* addressFamily;
			.IPAddressChoice* ipAddressChoice;
		}

		alias IPAddressFamily = .IPAddressFamily_st;

		//DECLARE_STACK_OF(IPAddressFamily)
		struct stack_st_IPAddressFamily
		{
			libressl_d.openssl.stack._STACK stack;
		}

		alias IPAddrBlocks = .stack_st_IPAddressFamily;

		.IPAddressRange* IPAddressRange_new();
		void IPAddressRange_free(.IPAddressRange* a);
		.IPAddressRange* d2i_IPAddressRange(.IPAddressRange** a, const (ubyte)** in_, core.stdc.config.c_long len);
		int i2d_IPAddressRange(.IPAddressRange* a, ubyte** out_);
		//extern const ASN1_ITEM IPAddressRange_it;

		.IPAddressOrRange* IPAddressOrRange_new();
		void IPAddressOrRange_free(.IPAddressOrRange* a);
		.IPAddressOrRange* d2i_IPAddressOrRange(.IPAddressOrRange** a, const (ubyte)** in_, core.stdc.config.c_long len);
		int i2d_IPAddressOrRange(.IPAddressOrRange* a, ubyte** out_);
		//extern const ASN1_ITEM IPAddressOrRange_it;

		.IPAddressChoice* IPAddressChoice_new();
		void IPAddressChoice_free(.IPAddressChoice* a);
		.IPAddressChoice* d2i_IPAddressChoice(.IPAddressChoice** a, const (ubyte)** in_, core.stdc.config.c_long len);
		int i2d_IPAddressChoice(.IPAddressChoice* a, ubyte** out_);
		//extern const ASN1_ITEM IPAddressChoice_it;

		.IPAddressFamily* IPAddressFamily_new();
		void IPAddressFamily_free(.IPAddressFamily* a);
		.IPAddressFamily* d2i_IPAddressFamily(.IPAddressFamily** a, const (ubyte)** in_, core.stdc.config.c_long len);
		int i2d_IPAddressFamily(.IPAddressFamily* a, ubyte** out_);
		//extern const ASN1_ITEM IPAddressFamily_it;

		/*
		 * API tag for elements of the ASIdentifer SEQUENCE.
		 */
		enum V3_ASID_ASNUM = 0;
		enum V3_ASID_RDI = 1;

		/*
		 * AFI values, assigned by IANA.  It'd be nice to make the AFI
		 * handling code totally generic, but there are too many little things
		 * that would need to be defined for other address families for it to
		 * be worth the trouble.
		 */
		enum IANA_AFI_IPV4 = 1;
		enum IANA_AFI_IPV6 = 2;

		/*
		 * Utilities to construct and extract values from RFC3779 extensions,
		 * since some of the encodings (particularly for IP address prefixes
		 * and ranges) are a bit tedious to work with directly.
		 */
		int X509v3_asid_add_inherit(.ASIdentifiers* asid, int which);
		int X509v3_asid_add_id_or_range(.ASIdentifiers* asid, int which, libressl_d.openssl.ossl_typ.ASN1_INTEGER* min, libressl_d.openssl.ossl_typ.ASN1_INTEGER* max);
		int X509v3_addr_add_inherit(.IPAddrBlocks* addr, const uint afi, const (uint)* safi);
		int X509v3_addr_add_prefix(.IPAddrBlocks* addr, const uint afi, const (uint)* safi, ubyte* a, const int prefixlen);
		int X509v3_addr_add_range(.IPAddrBlocks* addr, const uint afi, const (uint)* safi, ubyte* min, ubyte* max);
		uint X509v3_addr_get_afi(const (.IPAddressFamily)* f);
		int X509v3_addr_get_range(.IPAddressOrRange* aor, const uint afi, ubyte* min, ubyte* max, const int length);

		/*
		 * Canonical forms.
		 */
		int X509v3_asid_is_canonical(.ASIdentifiers* asid);
		int X509v3_addr_is_canonical(.IPAddrBlocks* addr);
		int X509v3_asid_canonize(.ASIdentifiers* asid);
		int X509v3_addr_canonize(.IPAddrBlocks* addr);

		/*
		 * Tests for inheritance and containment.
		 */
		int X509v3_asid_inherits(.ASIdentifiers* asid);
		int X509v3_addr_inherits(.IPAddrBlocks* addr);
		int X509v3_asid_subset(.ASIdentifiers* a, .ASIdentifiers* b);
		int X509v3_addr_subset(.IPAddrBlocks* a, .IPAddrBlocks* b);

		/*
		 * Check whether RFC 3779 extensions nest properly in chains.
		 */
		int X509v3_asid_validate_path(libressl_d.openssl.ossl_typ.X509_STORE_CTX*);
		int X509v3_addr_validate_path(libressl_d.openssl.ossl_typ.X509_STORE_CTX*);
		int X509v3_asid_validate_resource_set(libressl_d.openssl.x509.stack_st_X509* chain, .ASIdentifiers* ext, int allow_inheritance);
		int X509v3_addr_validate_resource_set(libressl_d.openssl.x509.stack_st_X509* chain, .IPAddrBlocks* ext, int allow_inheritance);
	}
}

/* BEGIN ERROR CODES */
/**
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_X509V3_strings();

/* Error codes for the X509V3 functions. */

/* Function codes. */
enum X509V3_F_A2I_GENERAL_NAME = 164;
enum X509V3_F_ASIDENTIFIERCHOICE_CANONIZE = 161;
enum X509V3_F_ASIDENTIFIERCHOICE_IS_CANONICAL = 162;
enum X509V3_F_COPY_EMAIL = 122;
enum X509V3_F_COPY_ISSUER = 123;
enum X509V3_F_DO_DIRNAME = 144;
enum X509V3_F_DO_EXT_CONF = 124;
enum X509V3_F_DO_EXT_I2D = 135;
enum X509V3_F_DO_EXT_NCONF = 151;
enum X509V3_F_DO_I2V_NAME_CONSTRAINTS = 148;
enum X509V3_F_GNAMES_FROM_SECTNAME = 156;
enum X509V3_F_HEX_TO_STRING = 111;
enum X509V3_F_I2S_ASN1_ENUMERATED = 121;
enum X509V3_F_I2S_ASN1_IA5STRING = 149;
enum X509V3_F_I2S_ASN1_INTEGER = 120;
enum X509V3_F_I2V_AUTHORITY_INFO_ACCESS = 138;
enum X509V3_F_NOTICE_SECTION = 132;
enum X509V3_F_NREF_NOS = 133;
enum X509V3_F_POLICY_SECTION = 131;
enum X509V3_F_PROCESS_PCI_VALUE = 150;
enum X509V3_F_R2I_CERTPOL = 130;
enum X509V3_F_R2I_PCI = 155;
enum X509V3_F_S2I_ASN1_IA5STRING = 100;
enum X509V3_F_S2I_ASN1_INTEGER = 108;
enum X509V3_F_S2I_ASN1_OCTET_STRING = 112;
enum X509V3_F_S2I_ASN1_SKEY_ID = 114;
enum X509V3_F_S2I_SKEY_ID = 115;
enum X509V3_F_SET_DIST_POINT_NAME = 158;
enum X509V3_F_STRING_TO_HEX = 113;
enum X509V3_F_SXNET_ADD_ID_ASC = 125;
enum X509V3_F_SXNET_ADD_ID_INTEGER = 126;
enum X509V3_F_SXNET_ADD_ID_ULONG = 127;
enum X509V3_F_SXNET_GET_ID_ASC = 128;
enum X509V3_F_SXNET_GET_ID_ULONG = 129;
enum X509V3_F_V2I_ASIDENTIFIERS = 163;
enum X509V3_F_V2I_ASN1_BIT_STRING = 101;
enum X509V3_F_V2I_AUTHORITY_INFO_ACCESS = 139;
enum X509V3_F_V2I_AUTHORITY_KEYID = 119;
enum X509V3_F_V2I_BASIC_CONSTRAINTS = 102;
enum X509V3_F_V2I_CRLD = 134;
enum X509V3_F_V2I_EXTENDED_KEY_USAGE = 103;
enum X509V3_F_V2I_GENERAL_NAMES = 118;
enum X509V3_F_V2I_GENERAL_NAME_EX = 117;
enum X509V3_F_V2I_IDP = 157;
enum X509V3_F_V2I_IPADDRBLOCKS = 159;
enum X509V3_F_V2I_ISSUER_ALT = 153;
enum X509V3_F_V2I_NAME_CONSTRAINTS = 147;
enum X509V3_F_V2I_POLICY_CONSTRAINTS = 146;
enum X509V3_F_V2I_POLICY_MAPPINGS = 145;
enum X509V3_F_V2I_SUBJECT_ALT = 154;
enum X509V3_F_V3_ADDR_VALIDATE_PATH_INTERNAL = 160;
enum X509V3_F_V3_GENERIC_EXTENSION = 116;
enum X509V3_F_X509V3_ADD1_I2D = 140;
enum X509V3_F_X509V3_ADD_VALUE = 105;
enum X509V3_F_X509V3_EXT_ADD = 104;
enum X509V3_F_X509V3_EXT_ADD_ALIAS = 106;
enum X509V3_F_X509V3_EXT_CONF = 107;
enum X509V3_F_X509V3_EXT_I2D = 136;
enum X509V3_F_X509V3_EXT_NCONF = 152;
enum X509V3_F_X509V3_GET_SECTION = 142;
enum X509V3_F_X509V3_GET_STRING = 143;
enum X509V3_F_X509V3_GET_VALUE_BOOL = 110;
enum X509V3_F_X509V3_PARSE_LIST = 109;
enum X509V3_F_X509_PURPOSE_ADD = 137;
enum X509V3_F_X509_PURPOSE_SET = 141;

/* Reason codes. */
enum X509V3_R_BAD_IP_ADDRESS = 118;
enum X509V3_R_BAD_OBJECT = 119;
enum X509V3_R_BN_DEC2BN_ERROR = 100;
enum X509V3_R_BN_TO_ASN1_INTEGER_ERROR = 101;
enum X509V3_R_DIRNAME_ERROR = 149;
enum X509V3_R_DISTPOINT_ALREADY_SET = 160;
enum X509V3_R_DUPLICATE_ZONE_ID = 133;
enum X509V3_R_ERROR_CONVERTING_ZONE = 131;
enum X509V3_R_ERROR_CREATING_EXTENSION = 144;
enum X509V3_R_ERROR_IN_EXTENSION = 128;
enum X509V3_R_EXPECTED_A_SECTION_NAME = 137;
enum X509V3_R_EXTENSION_EXISTS = 145;
enum X509V3_R_EXTENSION_NAME_ERROR = 115;
enum X509V3_R_EXTENSION_NOT_FOUND = 102;
enum X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED = 103;
enum X509V3_R_EXTENSION_VALUE_ERROR = 116;
enum X509V3_R_ILLEGAL_EMPTY_EXTENSION = 151;
enum X509V3_R_ILLEGAL_HEX_DIGIT = 113;
enum X509V3_R_INCORRECT_POLICY_SYNTAX_TAG = 152;
enum X509V3_R_INVALID_MULTIPLE_RDNS = 161;
enum X509V3_R_INVALID_ASNUMBER = 162;
enum X509V3_R_INVALID_ASRANGE = 163;
enum X509V3_R_INVALID_BOOLEAN_STRING = 104;
enum X509V3_R_INVALID_EXTENSION_STRING = 105;
enum X509V3_R_INVALID_INHERITANCE = 165;
enum X509V3_R_INVALID_IPADDRESS = 166;
enum X509V3_R_INVALID_NAME = 106;
enum X509V3_R_INVALID_NULL_ARGUMENT = 107;
enum X509V3_R_INVALID_NULL_NAME = 108;
enum X509V3_R_INVALID_NULL_VALUE = 109;
enum X509V3_R_INVALID_NUMBER = 140;
enum X509V3_R_INVALID_NUMBERS = 141;
enum X509V3_R_INVALID_OBJECT_IDENTIFIER = 110;
enum X509V3_R_INVALID_OPTION = 138;
enum X509V3_R_INVALID_POLICY_IDENTIFIER = 134;
enum X509V3_R_INVALID_PROXY_POLICY_SETTING = 153;
enum X509V3_R_INVALID_PURPOSE = 146;
enum X509V3_R_INVALID_SAFI = 164;
enum X509V3_R_INVALID_SECTION = 135;
enum X509V3_R_INVALID_SYNTAX = 143;
enum X509V3_R_ISSUER_DECODE_ERROR = 126;
enum X509V3_R_MISSING_VALUE = 124;
enum X509V3_R_NEED_ORGANIZATION_AND_NUMBERS = 142;
enum X509V3_R_NO_CONFIG_DATABASE = 136;
enum X509V3_R_NO_ISSUER_CERTIFICATE = 121;
enum X509V3_R_NO_ISSUER_DETAILS = 127;
enum X509V3_R_NO_POLICY_IDENTIFIER = 139;
enum X509V3_R_NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED = 154;
enum X509V3_R_NO_PUBLIC_KEY = 114;
enum X509V3_R_NO_SUBJECT_DETAILS = 125;
enum X509V3_R_ODD_NUMBER_OF_DIGITS = 112;
enum X509V3_R_OPERATION_NOT_DEFINED = 148;
enum X509V3_R_OTHERNAME_ERROR = 147;
enum X509V3_R_POLICY_LANGUAGE_ALREADY_DEFINED = 155;
enum X509V3_R_POLICY_PATH_LENGTH = 156;
enum X509V3_R_POLICY_PATH_LENGTH_ALREADY_DEFINED = 157;
enum X509V3_R_POLICY_SYNTAX_NOT_CURRENTLY_SUPPORTED = 158;
enum X509V3_R_POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY = 159;
enum X509V3_R_SECTION_NOT_FOUND = 150;
enum X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS = 122;
enum X509V3_R_UNABLE_TO_GET_ISSUER_KEYID = 123;
enum X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT = 111;
enum X509V3_R_UNKNOWN_EXTENSION = 129;
enum X509V3_R_UNKNOWN_EXTENSION_NAME = 130;
enum X509V3_R_UNKNOWN_OPTION = 120;
enum X509V3_R_UNSUPPORTED_OPTION = 117;
enum X509V3_R_UNSUPPORTED_TYPE = 167;
enum X509V3_R_USER_TOO_LONG = 132;
