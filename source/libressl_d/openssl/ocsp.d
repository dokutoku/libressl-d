/* $OpenBSD: ocsp.h,v 1.20 2022/07/12 14:42:49 kn Exp $ */
/* Written by Tom Titchener <Tom_Titchener@groove.net> for the OpenSSL
 * project.
 */

/*
 * History:
 * This file was transfered to Richard Levitte from CertCo by Kathy
 * Weinhold in mid-spring 2000 to be included in OpenSSL or released
 * as a patch kit.
 */

/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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
module libressl_d.openssl.ocsp;


private static import core.stdc.config;
private static import libressl_d.openssl.asn1;
private static import libressl_d.openssl.pem;
private static import libressl_d.openssl.stack;
public import libressl_d.openssl.ossl_typ;
public import libressl_d.openssl.safestack;
public import libressl_d.openssl.x509;
public import libressl_d.openssl.x509v3;

extern (C):
nothrow @nogc:

/*
 *   CRLReason ::= ENUMERATED {
 *        unspecified             (0),
 *        keyCompromise           (1),
 *        cACompromise            (2),
 *        affiliationChanged      (3),
 *        superseded              (4),
 *        cessationOfOperation    (5),
 *        certificateHold         (6),
 *        removeFromCRL           (8) }
 */
enum OCSP_REVOKED_STATUS_NOSTATUS = -1;
enum OCSP_REVOKED_STATUS_UNSPECIFIED = 0;
enum OCSP_REVOKED_STATUS_KEYCOMPROMISE = 1;
enum OCSP_REVOKED_STATUS_CACOMPROMISE = 2;
enum OCSP_REVOKED_STATUS_AFFILIATIONCHANGED = 3;
enum OCSP_REVOKED_STATUS_SUPERSEDED = 4;
enum OCSP_REVOKED_STATUS_CESSATIONOFOPERATION = 5;
enum OCSP_REVOKED_STATUS_CERTIFICATEHOLD = 6;
enum OCSP_REVOKED_STATUS_REMOVEFROMCRL = 8;

/* Various flags and values */

enum OCSP_DEFAULT_NONCE_LENGTH = 16;

enum OCSP_NOCERTS = 0x01;
enum OCSP_NOINTERN = 0x02;
enum OCSP_NOSIGS = 0x04;
enum OCSP_NOCHAIN = 0x08;
enum OCSP_NOVERIFY = 0x10;
enum OCSP_NOEXPLICIT = 0x20;
enum OCSP_NOCASIGN = 0x40;
enum OCSP_NODELEGATED = 0x80;
enum OCSP_NOCHECKS = 0x0100;
enum OCSP_TRUSTOTHER = 0x0200;
enum OCSP_RESPID_KEY = 0x0400;
enum OCSP_NOTIME = 0x0800;

struct ocsp_cert_id_st;
alias OCSP_CERTID = .ocsp_cert_id_st;

//DECLARE_STACK_OF(OCSP_CERTID)
struct stack_st_OCSP_CERTID
{
	libressl_d.openssl.stack._STACK stack;
}

struct ocsp_one_request_st;
alias OCSP_ONEREQ = .ocsp_one_request_st;

//DECLARE_STACK_OF(OCSP_ONEREQ)
struct stack_st_OCSP_ONEREQ
{
	libressl_d.openssl.stack._STACK stack;
}

struct ocsp_req_info_st;
alias OCSP_REQINFO = .ocsp_req_info_st;

struct ocsp_signature_st;
alias OCSP_SIGNATURE = .ocsp_signature_st;

struct ocsp_request_st;
alias OCSP_REQUEST = .ocsp_request_st;

/*
 * OCSPResponseStatus ::= ENUMERATED {
 *       successful            (0),      --Response has valid confirmations
 *       malformedRequest      (1),      --Illegal confirmation request
 *       internalError         (2),      --Internal error in issuer
 *       tryLater              (3),      --Try again later
 *                                       --(4) is not used
 *       sigRequired           (5),      --Must sign the request
 *       unauthorized          (6)       --Request unauthorized
 *   }
 */
enum OCSP_RESPONSE_STATUS_SUCCESSFUL = 0;
enum OCSP_RESPONSE_STATUS_MALFORMEDREQUEST = 1;
enum OCSP_RESPONSE_STATUS_INTERNALERROR = 2;
enum OCSP_RESPONSE_STATUS_TRYLATER = 3;
enum OCSP_RESPONSE_STATUS_SIGREQUIRED = 5;
enum OCSP_RESPONSE_STATUS_UNAUTHORIZED = 6;

struct ocsp_resp_bytes_st;
alias OCSP_RESPBYTES = .ocsp_resp_bytes_st;

enum V_OCSP_RESPID_NAME = 0;
enum V_OCSP_RESPID_KEY = 1;

//DECLARE_STACK_OF(OCSP_RESPID)
struct stack_st_OCSP_RESPID
{
	libressl_d.openssl.stack._STACK stack;
}

libressl_d.openssl.ossl_typ.OCSP_RESPID* OCSP_RESPID_new();
void OCSP_RESPID_free(libressl_d.openssl.ossl_typ.OCSP_RESPID* a);
libressl_d.openssl.ossl_typ.OCSP_RESPID* d2i_OCSP_RESPID(libressl_d.openssl.ossl_typ.OCSP_RESPID** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_RESPID(libressl_d.openssl.ossl_typ.OCSP_RESPID* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_RESPID_it;

/*
 * KeyHash ::= OCTET STRING --SHA-1 hash of responder's public key
 *                            --(excluding the tag and length fields)
 */

struct ocsp_revoked_info_st;
alias OCSP_REVOKEDINFO = .ocsp_revoked_info_st;

enum V_OCSP_CERTSTATUS_GOOD = 0;
enum V_OCSP_CERTSTATUS_REVOKED = 1;
enum V_OCSP_CERTSTATUS_UNKNOWN = 2;

struct ocsp_cert_status_st;
alias OCSP_CERTSTATUS = .ocsp_cert_status_st;

struct ocsp_single_response_st;
alias OCSP_SINGLERESP = .ocsp_single_response_st;

//DECLARE_STACK_OF(OCSP_SINGLERESP)
struct stack_st_OCSP_SINGLERESP
{
	libressl_d.openssl.stack._STACK stack;
}

struct ocsp_response_data_st;
alias OCSP_RESPDATA = .ocsp_response_data_st;

struct ocsp_basic_response_st;
alias OCSP_BASICRESP = .ocsp_basic_response_st;

struct ocsp_crl_id_st;
alias OCSP_CRLID = .ocsp_crl_id_st;

struct ocsp_service_locator_st;
alias OCSP_SERVICELOC = .ocsp_service_locator_st;

enum PEM_STRING_OCSP_REQUEST = "OCSP REQUEST";
enum PEM_STRING_OCSP_RESPONSE = "OCSP RESPONSE";

//#define PEM_read_bio_OCSP_REQUEST(bp, x, cb) cast(.OCSP_REQUEST*)(libressl_d.openssl.pem.PEM_ASN1_read_bio((char* (*) ()) .d2i_OCSP_REQUEST, .PEM_STRING_OCSP_REQUEST, bp, cast(char**)(x), cb, null))

//#define PEM_read_bio_OCSP_RESPONSE(bp, x, cb) cast(libressl_d.openssl.ossl_typ.OCSP_RESPONSE*)(libressl_d.openssl.pem.PEM_ASN1_read_bio((char* (*) ()) .d2i_OCSP_RESPONSE, .PEM_STRING_OCSP_RESPONSE, bp, cast(char**)(x), cb, null))

//#define PEM_write_bio_OCSP_REQUEST(bp, o) libressl_d.openssl.pem.PEM_ASN1_write_bio((int (*)()) .i2d_OCSP_REQUEST, .PEM_STRING_OCSP_REQUEST, bp, cast(char*)(o), null, null, 0, null, null)

//#define PEM_write_bio_OCSP_RESPONSE(bp, o) libressl_d.openssl.pem.PEM_ASN1_write_bio((int (*)()) .i2d_OCSP_RESPONSE, .PEM_STRING_OCSP_RESPONSE, bp, cast(char*)(o), null, null, 0, null, null)

//#define ASN1_BIT_STRING_digest(data, type, md, len) libressl_d.openssl.x509.ASN1_item_digest(&ASN1_BIT_STRING_it, type, data, md, len)

//#define OCSP_CERTSTATUS_dup(cs) libressl_d.openssl.asn1.ASN1_item_dup(&OCSP_CERTSTATUS_it, cs)

.OCSP_CERTID* OCSP_CERTID_dup(.OCSP_CERTID* id);

libressl_d.openssl.ossl_typ.OCSP_RESPONSE* OCSP_sendreq_bio(libressl_d.openssl.ossl_typ.BIO* b, const (char)* path, .OCSP_REQUEST* req);
libressl_d.openssl.ossl_typ.OCSP_REQ_CTX* OCSP_sendreq_new(libressl_d.openssl.ossl_typ.BIO* io, const (char)* path, .OCSP_REQUEST* req, int maxline);
int OCSP_sendreq_nbio(libressl_d.openssl.ossl_typ.OCSP_RESPONSE** presp, libressl_d.openssl.ossl_typ.OCSP_REQ_CTX* rctx);
void OCSP_REQ_CTX_free(libressl_d.openssl.ossl_typ.OCSP_REQ_CTX* rctx);
int OCSP_REQ_CTX_set1_req(libressl_d.openssl.ossl_typ.OCSP_REQ_CTX* rctx, .OCSP_REQUEST* req);
int OCSP_REQ_CTX_add1_header(libressl_d.openssl.ossl_typ.OCSP_REQ_CTX* rctx, const (char)* name, const (char)* value);

.OCSP_CERTID* OCSP_cert_to_id(const (libressl_d.openssl.ossl_typ.EVP_MD)* dgst, const (libressl_d.openssl.ossl_typ.X509)* subject, const (libressl_d.openssl.ossl_typ.X509)* issuer);

.OCSP_CERTID* OCSP_cert_id_new(const (libressl_d.openssl.ossl_typ.EVP_MD)* dgst, const (libressl_d.openssl.ossl_typ.X509_NAME)* issuerName, const (libressl_d.openssl.ossl_typ.ASN1_BIT_STRING)* issuerKey, const (libressl_d.openssl.ossl_typ.ASN1_INTEGER)* serialNumber);

.OCSP_ONEREQ* OCSP_request_add0_id(.OCSP_REQUEST* req, .OCSP_CERTID* cid);

int OCSP_request_add1_nonce(.OCSP_REQUEST* req, ubyte* val, int len);
int OCSP_basic_add1_nonce(.OCSP_BASICRESP* resp, ubyte* val, int len);
int OCSP_check_nonce(.OCSP_REQUEST* req, .OCSP_BASICRESP* bs);
int OCSP_copy_nonce(.OCSP_BASICRESP* resp, .OCSP_REQUEST* req);

int OCSP_request_set1_name(.OCSP_REQUEST* req, libressl_d.openssl.ossl_typ.X509_NAME* nm);
int OCSP_request_add1_cert(.OCSP_REQUEST* req, libressl_d.openssl.ossl_typ.X509* cert);

int OCSP_request_sign(.OCSP_REQUEST* req, libressl_d.openssl.ossl_typ.X509* signer, libressl_d.openssl.ossl_typ.EVP_PKEY* key, const (libressl_d.openssl.ossl_typ.EVP_MD)* dgst, libressl_d.openssl.x509.stack_st_X509* certs, core.stdc.config.c_ulong flags);

int OCSP_response_status(libressl_d.openssl.ossl_typ.OCSP_RESPONSE* resp);
.OCSP_BASICRESP* OCSP_response_get1_basic(libressl_d.openssl.ossl_typ.OCSP_RESPONSE* resp);

const (libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING)* OCSP_resp_get0_signature(const (.OCSP_BASICRESP)* bs);
const (libressl_d.openssl.ossl_typ.X509_ALGOR)* OCSP_resp_get0_tbs_sigalg(const (.OCSP_BASICRESP)* bs);
const (.OCSP_RESPDATA)* OCSP_resp_get0_respdata(const (.OCSP_BASICRESP)* bs);
int OCSP_resp_get0_signer(.OCSP_BASICRESP* bs, libressl_d.openssl.ossl_typ.X509** signer, libressl_d.openssl.x509.stack_st_X509* extra_certs);

int OCSP_resp_count(.OCSP_BASICRESP* bs);
.OCSP_SINGLERESP* OCSP_resp_get0(.OCSP_BASICRESP* bs, int idx);
const (libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME)* OCSP_resp_get0_produced_at(const (.OCSP_BASICRESP)* bs);
const (libressl_d.openssl.x509.stack_st_X509)* OCSP_resp_get0_certs(const (.OCSP_BASICRESP)* bs);
int OCSP_resp_get0_id(const (.OCSP_BASICRESP)* bs, const (libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING)** pid, const (libressl_d.openssl.ossl_typ.X509_NAME)** pname);

int OCSP_resp_find(.OCSP_BASICRESP* bs, .OCSP_CERTID* id, int last);
int OCSP_single_get0_status(.OCSP_SINGLERESP* single, int* reason, libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME** revtime, libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME** thisupd, libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME** nextupd);
int OCSP_resp_find_status(.OCSP_BASICRESP* bs, .OCSP_CERTID* id, int* status, int* reason, libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME** revtime, libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME** thisupd, libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME** nextupd);
int OCSP_check_validity(libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME* thisupd, libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME* nextupd, core.stdc.config.c_long sec, core.stdc.config.c_long maxsec);

int OCSP_request_verify(.OCSP_REQUEST* req, libressl_d.openssl.x509.stack_st_X509* certs, libressl_d.openssl.ossl_typ.X509_STORE* store, core.stdc.config.c_ulong flags);

int OCSP_parse_url(const (char)* url, char** phost, char** pport, char** ppath, int* pssl);

int OCSP_id_issuer_cmp(.OCSP_CERTID* a, .OCSP_CERTID* b);
int OCSP_id_cmp(.OCSP_CERTID* a, .OCSP_CERTID* b);

int OCSP_request_onereq_count(.OCSP_REQUEST* req);
.OCSP_ONEREQ* OCSP_request_onereq_get0(.OCSP_REQUEST* req, int i);
.OCSP_CERTID* OCSP_onereq_get0_id(.OCSP_ONEREQ* one);
int OCSP_id_get0_info(libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING** piNameHash, libressl_d.openssl.ossl_typ.ASN1_OBJECT** pmd, libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING** pikeyHash, libressl_d.openssl.ossl_typ.ASN1_INTEGER** pserial, .OCSP_CERTID* cid);
int OCSP_request_is_signed(.OCSP_REQUEST* req);
libressl_d.openssl.ossl_typ.OCSP_RESPONSE* OCSP_response_create(int status, .OCSP_BASICRESP* bs);
.OCSP_SINGLERESP* OCSP_basic_add1_status(.OCSP_BASICRESP* rsp, .OCSP_CERTID* cid, int status, int reason, libressl_d.openssl.ossl_typ.ASN1_TIME* revtime, libressl_d.openssl.ossl_typ.ASN1_TIME* thisupd, libressl_d.openssl.ossl_typ.ASN1_TIME* nextupd);
int OCSP_basic_add1_cert(.OCSP_BASICRESP* resp, libressl_d.openssl.ossl_typ.X509* cert);
int OCSP_basic_sign(.OCSP_BASICRESP* brsp, libressl_d.openssl.ossl_typ.X509* signer, libressl_d.openssl.ossl_typ.EVP_PKEY* key, const (libressl_d.openssl.ossl_typ.EVP_MD)* dgst, libressl_d.openssl.x509.stack_st_X509* certs, core.stdc.config.c_ulong flags);

libressl_d.openssl.x509.X509_EXTENSION* OCSP_crlID_new(const (char)* url, core.stdc.config.c_long* n, char* tim);

libressl_d.openssl.x509.X509_EXTENSION* OCSP_accept_responses_new(char** oids);

libressl_d.openssl.x509.X509_EXTENSION* OCSP_archive_cutoff_new(char* tim);

libressl_d.openssl.x509.X509_EXTENSION* OCSP_url_svcloc_new(libressl_d.openssl.ossl_typ.X509_NAME* issuer, const (char)** urls);

int OCSP_REQUEST_get_ext_count(.OCSP_REQUEST* x);
int OCSP_REQUEST_get_ext_by_NID(.OCSP_REQUEST* x, int nid, int lastpos);
int OCSP_REQUEST_get_ext_by_OBJ(.OCSP_REQUEST* x, const (libressl_d.openssl.ossl_typ.ASN1_OBJECT)* obj, int lastpos);
int OCSP_REQUEST_get_ext_by_critical(.OCSP_REQUEST* x, int crit, int lastpos);
libressl_d.openssl.x509.X509_EXTENSION* OCSP_REQUEST_get_ext(.OCSP_REQUEST* x, int loc);
libressl_d.openssl.x509.X509_EXTENSION* OCSP_REQUEST_delete_ext(.OCSP_REQUEST* x, int loc);
void* OCSP_REQUEST_get1_ext_d2i(.OCSP_REQUEST* x, int nid, int* crit, int* idx);
int OCSP_REQUEST_add1_ext_i2d(.OCSP_REQUEST* x, int nid, void* value, int crit, core.stdc.config.c_ulong flags);
int OCSP_REQUEST_add_ext(.OCSP_REQUEST* x, libressl_d.openssl.x509.X509_EXTENSION* ex, int loc);

int OCSP_ONEREQ_get_ext_count(.OCSP_ONEREQ* x);
int OCSP_ONEREQ_get_ext_by_NID(.OCSP_ONEREQ* x, int nid, int lastpos);
int OCSP_ONEREQ_get_ext_by_OBJ(.OCSP_ONEREQ* x, const (libressl_d.openssl.ossl_typ.ASN1_OBJECT)* obj, int lastpos);
int OCSP_ONEREQ_get_ext_by_critical(.OCSP_ONEREQ* x, int crit, int lastpos);
libressl_d.openssl.x509.X509_EXTENSION* OCSP_ONEREQ_get_ext(.OCSP_ONEREQ* x, int loc);
libressl_d.openssl.x509.X509_EXTENSION* OCSP_ONEREQ_delete_ext(.OCSP_ONEREQ* x, int loc);
void* OCSP_ONEREQ_get1_ext_d2i(.OCSP_ONEREQ* x, int nid, int* crit, int* idx);
int OCSP_ONEREQ_add1_ext_i2d(.OCSP_ONEREQ* x, int nid, void* value, int crit, core.stdc.config.c_ulong flags);
int OCSP_ONEREQ_add_ext(.OCSP_ONEREQ* x, libressl_d.openssl.x509.X509_EXTENSION* ex, int loc);

int OCSP_BASICRESP_get_ext_count(.OCSP_BASICRESP* x);
int OCSP_BASICRESP_get_ext_by_NID(.OCSP_BASICRESP* x, int nid, int lastpos);
int OCSP_BASICRESP_get_ext_by_OBJ(.OCSP_BASICRESP* x, const (libressl_d.openssl.ossl_typ.ASN1_OBJECT)* obj, int lastpos);
int OCSP_BASICRESP_get_ext_by_critical(.OCSP_BASICRESP* x, int crit, int lastpos);
libressl_d.openssl.x509.X509_EXTENSION* OCSP_BASICRESP_get_ext(.OCSP_BASICRESP* x, int loc);
libressl_d.openssl.x509.X509_EXTENSION* OCSP_BASICRESP_delete_ext(.OCSP_BASICRESP* x, int loc);
void* OCSP_BASICRESP_get1_ext_d2i(.OCSP_BASICRESP* x, int nid, int* crit, int* idx);
int OCSP_BASICRESP_add1_ext_i2d(.OCSP_BASICRESP* x, int nid, void* value, int crit, core.stdc.config.c_ulong flags);
int OCSP_BASICRESP_add_ext(.OCSP_BASICRESP* x, libressl_d.openssl.x509.X509_EXTENSION* ex, int loc);

int OCSP_SINGLERESP_get_ext_count(.OCSP_SINGLERESP* x);
int OCSP_SINGLERESP_get_ext_by_NID(.OCSP_SINGLERESP* x, int nid, int lastpos);
int OCSP_SINGLERESP_get_ext_by_OBJ(.OCSP_SINGLERESP* x, const (libressl_d.openssl.ossl_typ.ASN1_OBJECT)* obj, int lastpos);
int OCSP_SINGLERESP_get_ext_by_critical(.OCSP_SINGLERESP* x, int crit, int lastpos);
libressl_d.openssl.x509.X509_EXTENSION* OCSP_SINGLERESP_get_ext(.OCSP_SINGLERESP* x, int loc);
libressl_d.openssl.x509.X509_EXTENSION* OCSP_SINGLERESP_delete_ext(.OCSP_SINGLERESP* x, int loc);
void* OCSP_SINGLERESP_get1_ext_d2i(.OCSP_SINGLERESP* x, int nid, int* crit, int* idx);
int OCSP_SINGLERESP_add1_ext_i2d(.OCSP_SINGLERESP* x, int nid, void* value, int crit, core.stdc.config.c_ulong flags);
int OCSP_SINGLERESP_add_ext(.OCSP_SINGLERESP* x, libressl_d.openssl.x509.X509_EXTENSION* ex, int loc);
const (.OCSP_CERTID)* OCSP_SINGLERESP_get0_id(const (.OCSP_SINGLERESP)* x);

.OCSP_SINGLERESP* OCSP_SINGLERESP_new();
void OCSP_SINGLERESP_free(.OCSP_SINGLERESP* a);
.OCSP_SINGLERESP* d2i_OCSP_SINGLERESP(.OCSP_SINGLERESP** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_SINGLERESP(.OCSP_SINGLERESP* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_SINGLERESP_it;
.OCSP_CERTSTATUS* OCSP_CERTSTATUS_new();
void OCSP_CERTSTATUS_free(.OCSP_CERTSTATUS* a);
.OCSP_CERTSTATUS* d2i_OCSP_CERTSTATUS(.OCSP_CERTSTATUS** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_CERTSTATUS(.OCSP_CERTSTATUS* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_CERTSTATUS_it;
.OCSP_REVOKEDINFO* OCSP_REVOKEDINFO_new();
void OCSP_REVOKEDINFO_free(.OCSP_REVOKEDINFO* a);
.OCSP_REVOKEDINFO* d2i_OCSP_REVOKEDINFO(.OCSP_REVOKEDINFO** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_REVOKEDINFO(.OCSP_REVOKEDINFO* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_REVOKEDINFO_it;
.OCSP_BASICRESP* OCSP_BASICRESP_new();
void OCSP_BASICRESP_free(.OCSP_BASICRESP* a);
.OCSP_BASICRESP* d2i_OCSP_BASICRESP(.OCSP_BASICRESP** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_BASICRESP(.OCSP_BASICRESP* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_BASICRESP_it;
.OCSP_RESPDATA* OCSP_RESPDATA_new();
void OCSP_RESPDATA_free(.OCSP_RESPDATA* a);
.OCSP_RESPDATA* d2i_OCSP_RESPDATA(.OCSP_RESPDATA** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_RESPDATA(.OCSP_RESPDATA* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_RESPDATA_it;
libressl_d.openssl.ossl_typ.OCSP_RESPID* OCSP_RESPID_new();
void OCSP_RESPID_free(libressl_d.openssl.ossl_typ.OCSP_RESPID* a);
libressl_d.openssl.ossl_typ.OCSP_RESPID* d2i_OCSP_RESPID(libressl_d.openssl.ossl_typ.OCSP_RESPID** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_RESPID(libressl_d.openssl.ossl_typ.OCSP_RESPID* a, ubyte** out_);

version (none) {
	extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_RESPID_it;
}

libressl_d.openssl.ossl_typ.OCSP_RESPONSE* OCSP_RESPONSE_new();
void OCSP_RESPONSE_free(libressl_d.openssl.ossl_typ.OCSP_RESPONSE* a);
libressl_d.openssl.ossl_typ.OCSP_RESPONSE* d2i_OCSP_RESPONSE(libressl_d.openssl.ossl_typ.OCSP_RESPONSE** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_RESPONSE(libressl_d.openssl.ossl_typ.OCSP_RESPONSE* a, ubyte** out_);
libressl_d.openssl.ossl_typ.OCSP_RESPONSE* d2i_OCSP_RESPONSE_bio(libressl_d.openssl.ossl_typ.BIO* bp, libressl_d.openssl.ossl_typ.OCSP_RESPONSE** a);
int i2d_OCSP_RESPONSE_bio(libressl_d.openssl.ossl_typ.BIO* bp, libressl_d.openssl.ossl_typ.OCSP_RESPONSE* a);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_RESPONSE_it;
.OCSP_RESPBYTES* OCSP_RESPBYTES_new();
void OCSP_RESPBYTES_free(.OCSP_RESPBYTES* a);
.OCSP_RESPBYTES* d2i_OCSP_RESPBYTES(.OCSP_RESPBYTES** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_RESPBYTES(.OCSP_RESPBYTES* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_RESPBYTES_it;
.OCSP_ONEREQ* OCSP_ONEREQ_new();
void OCSP_ONEREQ_free(.OCSP_ONEREQ* a);
.OCSP_ONEREQ* d2i_OCSP_ONEREQ(.OCSP_ONEREQ** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_ONEREQ(.OCSP_ONEREQ* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_ONEREQ_it;
.OCSP_CERTID* OCSP_CERTID_new();
void OCSP_CERTID_free(.OCSP_CERTID* a);
.OCSP_CERTID* d2i_OCSP_CERTID(.OCSP_CERTID** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_CERTID(.OCSP_CERTID* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_CERTID_it;
.OCSP_REQUEST* OCSP_REQUEST_new();
void OCSP_REQUEST_free(.OCSP_REQUEST* a);
.OCSP_REQUEST* d2i_OCSP_REQUEST(.OCSP_REQUEST** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_REQUEST(.OCSP_REQUEST* a, ubyte** out_);
.OCSP_REQUEST* d2i_OCSP_REQUEST_bio(libressl_d.openssl.ossl_typ.BIO* bp, .OCSP_REQUEST** a);
int i2d_OCSP_REQUEST_bio(libressl_d.openssl.ossl_typ.BIO* bp, .OCSP_REQUEST* a);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_REQUEST_it;
.OCSP_SIGNATURE* OCSP_SIGNATURE_new();
void OCSP_SIGNATURE_free(.OCSP_SIGNATURE* a);
.OCSP_SIGNATURE* d2i_OCSP_SIGNATURE(.OCSP_SIGNATURE** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_SIGNATURE(.OCSP_SIGNATURE* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_SIGNATURE_it;
.OCSP_REQINFO* OCSP_REQINFO_new();
void OCSP_REQINFO_free(.OCSP_REQINFO* a);
.OCSP_REQINFO* d2i_OCSP_REQINFO(.OCSP_REQINFO** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_REQINFO(.OCSP_REQINFO* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_REQINFO_it;
.OCSP_CRLID* OCSP_CRLID_new();
void OCSP_CRLID_free(.OCSP_CRLID* a);
.OCSP_CRLID* d2i_OCSP_CRLID(.OCSP_CRLID** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_CRLID(.OCSP_CRLID* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_CRLID_it;
.OCSP_SERVICELOC* OCSP_SERVICELOC_new();
void OCSP_SERVICELOC_free(.OCSP_SERVICELOC* a);
.OCSP_SERVICELOC* d2i_OCSP_SERVICELOC(.OCSP_SERVICELOC** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_OCSP_SERVICELOC(.OCSP_SERVICELOC* a, ubyte** out_);
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM OCSP_SERVICELOC_it;

const (char)* OCSP_response_status_str(core.stdc.config.c_long s);
const (char)* OCSP_cert_status_str(core.stdc.config.c_long s);
const (char)* OCSP_crl_reason_str(core.stdc.config.c_long s);

int OCSP_REQUEST_print(libressl_d.openssl.ossl_typ.BIO* bp, .OCSP_REQUEST* a, core.stdc.config.c_ulong flags);
int OCSP_RESPONSE_print(libressl_d.openssl.ossl_typ.BIO* bp, libressl_d.openssl.ossl_typ.OCSP_RESPONSE* o, core.stdc.config.c_ulong flags);

int OCSP_basic_verify(.OCSP_BASICRESP* bs, libressl_d.openssl.x509.stack_st_X509* certs, libressl_d.openssl.ossl_typ.X509_STORE* st, core.stdc.config.c_ulong flags);

void ERR_load_OCSP_strings();

/* Error codes for the OCSP functions. */

/* Function codes. */
enum OCSP_F_ASN1_STRING_ENCODE = 100;
enum OCSP_F_D2I_OCSP_NONCE = 102;
enum OCSP_F_OCSP_BASIC_ADD1_STATUS = 103;
enum OCSP_F_OCSP_BASIC_SIGN = 104;
enum OCSP_F_OCSP_BASIC_VERIFY = 105;
enum OCSP_F_OCSP_CERT_ID_NEW = 101;
enum OCSP_F_OCSP_CHECK_DELEGATED = 106;
enum OCSP_F_OCSP_CHECK_IDS = 107;
enum OCSP_F_OCSP_CHECK_ISSUER = 108;
enum OCSP_F_OCSP_CHECK_VALIDITY = 115;
enum OCSP_F_OCSP_MATCH_ISSUERID = 109;
enum OCSP_F_OCSP_PARSE_URL = 114;
enum OCSP_F_OCSP_REQUEST_SIGN = 110;
enum OCSP_F_OCSP_REQUEST_VERIFY = 116;
enum OCSP_F_OCSP_RESPONSE_GET1_BASIC = 111;
enum OCSP_F_OCSP_SENDREQ_BIO = 112;
enum OCSP_F_OCSP_SENDREQ_NBIO = 117;
enum OCSP_F_PARSE_HTTP_LINE1 = 118;
enum OCSP_F_REQUEST_VERIFY = 113;

/* Reason codes. */
enum OCSP_R_BAD_DATA = 100;
enum OCSP_R_CERTIFICATE_VERIFY_ERROR = 101;
enum OCSP_R_DIGEST_ERR = 102;
enum OCSP_R_ERROR_IN_NEXTUPDATE_FIELD = 122;
enum OCSP_R_ERROR_IN_THISUPDATE_FIELD = 123;
enum OCSP_R_ERROR_PARSING_URL = 121;
enum OCSP_R_MISSING_OCSPSIGNING_USAGE = 103;
enum OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE = 124;
enum OCSP_R_NOT_BASIC_RESPONSE = 104;
enum OCSP_R_NO_CERTIFICATES_IN_CHAIN = 105;
enum OCSP_R_NO_CONTENT = 106;
enum OCSP_R_NO_PUBLIC_KEY = 107;
enum OCSP_R_NO_RESPONSE_DATA = 108;
enum OCSP_R_NO_REVOKED_TIME = 109;
enum OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 110;
enum OCSP_R_REQUEST_NOT_SIGNED = 128;
enum OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA = 111;
enum OCSP_R_ROOT_CA_NOT_TRUSTED = 112;
enum OCSP_R_SERVER_READ_ERROR = 113;
enum OCSP_R_SERVER_RESPONSE_ERROR = 114;
enum OCSP_R_SERVER_RESPONSE_PARSE_ERROR = 115;
enum OCSP_R_SERVER_WRITE_ERROR = 116;
enum OCSP_R_SIGNATURE_FAILURE = 117;
enum OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND = 118;
enum OCSP_R_STATUS_EXPIRED = 125;
enum OCSP_R_STATUS_NOT_YET_VALID = 126;
enum OCSP_R_STATUS_TOO_OLD = 127;
enum OCSP_R_UNKNOWN_MESSAGE_DIGEST = 119;
enum OCSP_R_UNKNOWN_NID = 120;
enum OCSP_R_UNSUPPORTED_REQUESTORNAME_TYPE = 129;
