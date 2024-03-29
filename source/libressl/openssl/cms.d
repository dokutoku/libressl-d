/* $OpenBSD: cms.h,v 1.15 2019/08/11 10:15:30 jsing Exp $ */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */
module libressl.openssl.cms;


private static import core.stdc.config;
private static import libressl.compat.stdio;
private static import libressl.compat.sys.types;
private static import libressl.openssl.asn1;
private static import libressl.openssl.ossl_typ;
private static import libressl.openssl.pem;
private static import libressl.openssl.stack;
private static import libressl.openssl.x509v3;
public import libressl.openssl.opensslconf;

version (OPENSSL_NO_CMS) {
} else {
	public import libressl.openssl.x509;
	public import libressl.openssl.x509v3;

	extern (C):
	nothrow @nogc:

	struct CMS_ContentInfo_st;
	struct CMS_SignerInfo_st;
	struct CMS_CertificateChoices;
	struct CMS_RevocationInfoChoice_st;
	struct CMS_RecipientInfo_st;
	struct CMS_ReceiptRequest_st;
	struct CMS_Receipt_st;
	struct CMS_RecipientEncryptedKey_st;
	struct CMS_OtherKeyAttribute_st;

	alias CMS_ContentInfo = .CMS_ContentInfo_st;
	alias CMS_SignerInfo = .CMS_SignerInfo_st;
	alias CMS_RevocationInfoChoice = .CMS_RevocationInfoChoice_st;
	alias CMS_RecipientInfo = .CMS_RecipientInfo_st;
	alias CMS_ReceiptRequest = .CMS_ReceiptRequest_st;
	alias CMS_Receipt = .CMS_Receipt_st;
	alias CMS_RecipientEncryptedKey = .CMS_RecipientEncryptedKey_st;
	alias CMS_OtherKeyAttribute = .CMS_OtherKeyAttribute_st;

	//DECLARE_STACK_OF(CMS_SignerInfo)
	struct stack_st_CMS_SignerInfo
	{
		libressl.openssl.stack._STACK stack;
	}

	//DECLARE_STACK_OF(CMS_RecipientEncryptedKey)
	struct stack_st_CMS_RecipientEncryptedKey
	{
		libressl.openssl.stack._STACK stack;
	}

	//DECLARE_STACK_OF(CMS_RecipientInfo)
	struct stack_st_CMS_RecipientInfo
	{
		libressl.openssl.stack._STACK stack;
	}

	//DECLARE_STACK_OF(CMS_RevocationInfoChoice)
	struct stack_st_CMS_RevocationInfoChoice
	{
		libressl.openssl.stack._STACK stack;
	}

	.CMS_ContentInfo* CMS_ContentInfo_new();
	void CMS_ContentInfo_free(.CMS_ContentInfo* a);
	.CMS_ContentInfo* d2i_CMS_ContentInfo(.CMS_ContentInfo** a, const (ubyte)** in_, core.stdc.config.c_long len);
	int i2d_CMS_ContentInfo(.CMS_ContentInfo* a, ubyte** out_);
	extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM CMS_ContentInfo_it;
	.CMS_ReceiptRequest* CMS_ReceiptRequest_new();
	void CMS_ReceiptRequest_free(.CMS_ReceiptRequest* a);
	.CMS_ReceiptRequest* d2i_CMS_ReceiptRequest(.CMS_ReceiptRequest** a, const (ubyte)** in_, core.stdc.config.c_long len);
	int i2d_CMS_ReceiptRequest(.CMS_ReceiptRequest* a, ubyte** out_);
	extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM CMS_ReceiptRequest_it;
	int CMS_ContentInfo_print_ctx(libressl.openssl.ossl_typ.BIO* out_, .CMS_ContentInfo* x, int indent, const (libressl.openssl.ossl_typ.ASN1_PCTX)* pctx);

	enum CMS_SIGNERINFO_ISSUER_SERIAL = 0;
	enum CMS_SIGNERINFO_KEYIDENTIFIER = 1;

	enum CMS_RECIPINFO_NONE = -1;
	enum CMS_RECIPINFO_TRANS = 0;
	enum CMS_RECIPINFO_AGREE = 1;
	enum CMS_RECIPINFO_KEK = 2;
	enum CMS_RECIPINFO_PASS = 3;
	enum CMS_RECIPINFO_OTHER = 4;

	/* S/MIME related flags */

	enum CMS_TEXT = 0x01;
	enum CMS_NOCERTS = 0x02;
	enum CMS_NO_CONTENT_VERIFY = 0x04;
	enum CMS_NO_ATTR_VERIFY = 0x08;
	enum CMS_NOSIGS = .CMS_NO_CONTENT_VERIFY | .CMS_NO_ATTR_VERIFY;
	enum CMS_NOINTERN = 0x10;
	enum CMS_NO_SIGNER_CERT_VERIFY = 0x20;
	enum CMS_NOVERIFY = 0x20;
	enum CMS_DETACHED = 0x40;
	enum CMS_BINARY = 0x80;
	enum CMS_NOATTR = 0x0100;
	enum CMS_NOSMIMECAP = 0x0200;
	enum CMS_NOOLDMIMETYPE = 0x0400;
	enum CMS_CRLFEOL = 0x0800;
	enum CMS_STREAM = 0x1000;
	enum CMS_NOCRL = 0x2000;
	enum CMS_PARTIAL = 0x4000;
	enum CMS_REUSE_DIGEST = 0x8000;
	enum CMS_USE_KEYID = 0x010000;
	enum CMS_DEBUG_DECRYPT = 0x020000;
	enum CMS_KEY_PARAM = 0x040000;
	enum CMS_ASCIICRLF = 0x080000;

	const (libressl.openssl.ossl_typ.ASN1_OBJECT)* CMS_get0_type(const (.CMS_ContentInfo)* cms);

	libressl.openssl.ossl_typ.BIO* CMS_dataInit(.CMS_ContentInfo* cms, libressl.openssl.ossl_typ.BIO* icont);
	int CMS_dataFinal(.CMS_ContentInfo* cms, libressl.openssl.ossl_typ.BIO* bio);

	libressl.openssl.ossl_typ.ASN1_OCTET_STRING** CMS_get0_content(.CMS_ContentInfo* cms);
	int CMS_is_detached(.CMS_ContentInfo* cms);
	int CMS_set_detached(.CMS_ContentInfo* cms, int detached);

	static assert(libressl.openssl.pem.HEADER_PEM_H);
	.CMS_ContentInfo* PEM_read_bio_CMS(libressl.openssl.ossl_typ.BIO* bp, .CMS_ContentInfo** x, libressl.openssl.pem.pem_password_cb cb, void* u);
	.CMS_ContentInfo* PEM_read_CMS(libressl.compat.stdio.FILE* fp, .CMS_ContentInfo** x, libressl.openssl.pem.pem_password_cb cb, void* u);
	int PEM_write_bio_CMS(libressl.openssl.ossl_typ.BIO* bp, const (.CMS_ContentInfo)* x);
	int PEM_write_CMS(libressl.compat.stdio.FILE* fp, const (.CMS_ContentInfo)* x);

	int CMS_stream(ubyte*** boundary, .CMS_ContentInfo* cms);
	.CMS_ContentInfo* d2i_CMS_bio(libressl.openssl.ossl_typ.BIO* bp, .CMS_ContentInfo** cms);
	int i2d_CMS_bio(libressl.openssl.ossl_typ.BIO* bp, .CMS_ContentInfo* cms);

	libressl.openssl.ossl_typ.BIO* BIO_new_CMS(libressl.openssl.ossl_typ.BIO* out_, .CMS_ContentInfo* cms);
	int i2d_CMS_bio_stream(libressl.openssl.ossl_typ.BIO* out_, .CMS_ContentInfo* cms, libressl.openssl.ossl_typ.BIO* in_, int flags);
	int PEM_write_bio_CMS_stream(libressl.openssl.ossl_typ.BIO* out_, .CMS_ContentInfo* cms, libressl.openssl.ossl_typ.BIO* in_, int flags);
	.CMS_ContentInfo* SMIME_read_CMS(libressl.openssl.ossl_typ.BIO* bio, libressl.openssl.ossl_typ.BIO** bcont);
	int SMIME_write_CMS(libressl.openssl.ossl_typ.BIO* bio, .CMS_ContentInfo* cms, libressl.openssl.ossl_typ.BIO* data, int flags);

	int CMS_final(.CMS_ContentInfo* cms, libressl.openssl.ossl_typ.BIO* data, libressl.openssl.ossl_typ.BIO* dcont, uint flags);

	.CMS_ContentInfo* CMS_sign(libressl.openssl.ossl_typ.X509* signcert, libressl.openssl.ossl_typ.EVP_PKEY* pkey, libressl.openssl.x509.stack_st_X509* certs, libressl.openssl.ossl_typ.BIO* data, uint flags);

	.CMS_ContentInfo* CMS_sign_receipt(.CMS_SignerInfo* si, libressl.openssl.ossl_typ.X509* signcert, libressl.openssl.ossl_typ.EVP_PKEY* pkey, libressl.openssl.x509.stack_st_X509* certs, uint flags);

	int CMS_data(.CMS_ContentInfo* cms, libressl.openssl.ossl_typ.BIO* out_, uint flags);
	.CMS_ContentInfo* CMS_data_create(libressl.openssl.ossl_typ.BIO* in_, uint flags);

	int CMS_digest_verify(.CMS_ContentInfo* cms, libressl.openssl.ossl_typ.BIO* dcont, libressl.openssl.ossl_typ.BIO* out_, uint flags);
	.CMS_ContentInfo* CMS_digest_create(libressl.openssl.ossl_typ.BIO* in_, const (libressl.openssl.ossl_typ.EVP_MD)* md, uint flags);

	int CMS_EncryptedData_decrypt(.CMS_ContentInfo* cms, const (ubyte)* key, size_t keylen, libressl.openssl.ossl_typ.BIO* dcont, libressl.openssl.ossl_typ.BIO* out_, uint flags);

	.CMS_ContentInfo* CMS_EncryptedData_encrypt(libressl.openssl.ossl_typ.BIO* in_, const (libressl.openssl.ossl_typ.EVP_CIPHER)* cipher, const (ubyte)* key, size_t keylen, uint flags);

	int CMS_EncryptedData_set1_key(.CMS_ContentInfo* cms, const (libressl.openssl.ossl_typ.EVP_CIPHER)* ciph, const (ubyte)* key, size_t keylen);

	int CMS_verify(.CMS_ContentInfo* cms, libressl.openssl.x509.stack_st_X509* certs, libressl.openssl.ossl_typ.X509_STORE* store, libressl.openssl.ossl_typ.BIO* dcont, libressl.openssl.ossl_typ.BIO* out_, uint flags);

	int CMS_verify_receipt(.CMS_ContentInfo* rcms, .CMS_ContentInfo* ocms, libressl.openssl.x509.stack_st_X509* certs, libressl.openssl.ossl_typ.X509_STORE* store, uint flags);

	libressl.openssl.x509.stack_st_X509* CMS_get0_signers(.CMS_ContentInfo* cms);

	.CMS_ContentInfo* CMS_encrypt(libressl.openssl.x509.stack_st_X509* certs, libressl.openssl.ossl_typ.BIO* in_, const (libressl.openssl.ossl_typ.EVP_CIPHER)* cipher, uint flags);

	int CMS_decrypt(.CMS_ContentInfo* cms, libressl.openssl.ossl_typ.EVP_PKEY* pkey, libressl.openssl.ossl_typ.X509* cert, libressl.openssl.ossl_typ.BIO* dcont, libressl.openssl.ossl_typ.BIO* out_, uint flags);

	int CMS_decrypt_set1_pkey(.CMS_ContentInfo* cms, libressl.openssl.ossl_typ.EVP_PKEY* pk, libressl.openssl.ossl_typ.X509* cert);
	int CMS_decrypt_set1_key(.CMS_ContentInfo* cms, ubyte* key, size_t keylen, const (ubyte)* id, size_t idlen);
	int CMS_decrypt_set1_password(.CMS_ContentInfo* cms, ubyte* pass, libressl.compat.sys.types.ssize_t passlen);

	.stack_st_CMS_RecipientInfo* CMS_get0_RecipientInfos(.CMS_ContentInfo* cms);
	int CMS_RecipientInfo_type(.CMS_RecipientInfo* ri);
	libressl.openssl.ossl_typ.EVP_PKEY_CTX* CMS_RecipientInfo_get0_pkey_ctx(.CMS_RecipientInfo* ri);
	.CMS_ContentInfo* CMS_EnvelopedData_create(const (libressl.openssl.ossl_typ.EVP_CIPHER)* cipher);
	.CMS_RecipientInfo* CMS_add1_recipient_cert(.CMS_ContentInfo* cms, libressl.openssl.ossl_typ.X509* recip, uint flags);
	int CMS_RecipientInfo_set0_pkey(.CMS_RecipientInfo* ri, libressl.openssl.ossl_typ.EVP_PKEY* pkey);
	int CMS_RecipientInfo_ktri_cert_cmp(.CMS_RecipientInfo* ri, libressl.openssl.ossl_typ.X509* cert);
	int CMS_RecipientInfo_ktri_get0_algs(.CMS_RecipientInfo* ri, libressl.openssl.ossl_typ.EVP_PKEY** pk, libressl.openssl.ossl_typ.X509** recip, libressl.openssl.ossl_typ.X509_ALGOR** palg);
	int CMS_RecipientInfo_ktri_get0_signer_id(.CMS_RecipientInfo* ri, libressl.openssl.ossl_typ.ASN1_OCTET_STRING** keyid, libressl.openssl.ossl_typ.X509_NAME** issuer, libressl.openssl.ossl_typ.ASN1_INTEGER** sno);

	.CMS_RecipientInfo* CMS_add0_recipient_key(.CMS_ContentInfo* cms, int nid, ubyte* key, size_t keylen, ubyte* id, size_t idlen, libressl.openssl.ossl_typ.ASN1_GENERALIZEDTIME* date, libressl.openssl.ossl_typ.ASN1_OBJECT* otherTypeId, libressl.openssl.asn1.ASN1_TYPE* otherType);

	int CMS_RecipientInfo_kekri_get0_id(.CMS_RecipientInfo* ri, libressl.openssl.ossl_typ.X509_ALGOR** palg, libressl.openssl.ossl_typ.ASN1_OCTET_STRING** pid, libressl.openssl.ossl_typ.ASN1_GENERALIZEDTIME** pdate, libressl.openssl.ossl_typ.ASN1_OBJECT** potherid, libressl.openssl.asn1.ASN1_TYPE** pothertype);

	int CMS_RecipientInfo_set0_key(.CMS_RecipientInfo* ri, ubyte* key, size_t keylen);

	int CMS_RecipientInfo_kekri_id_cmp(.CMS_RecipientInfo* ri, const (ubyte)* id, size_t idlen);

	int CMS_RecipientInfo_set0_password(.CMS_RecipientInfo* ri, ubyte* pass, libressl.compat.sys.types.ssize_t passlen);

	.CMS_RecipientInfo* CMS_add0_recipient_password(.CMS_ContentInfo* cms, int iter, int wrap_nid, int pbe_nid, ubyte* pass, libressl.compat.sys.types.ssize_t passlen, const (libressl.openssl.ossl_typ.EVP_CIPHER)* kekciph);

	int CMS_RecipientInfo_decrypt(.CMS_ContentInfo* cms, .CMS_RecipientInfo* ri);
	int CMS_RecipientInfo_encrypt(.CMS_ContentInfo* cms, .CMS_RecipientInfo* ri);

	int CMS_uncompress(.CMS_ContentInfo* cms, libressl.openssl.ossl_typ.BIO* dcont, libressl.openssl.ossl_typ.BIO* out_, uint flags);
	.CMS_ContentInfo* CMS_compress(libressl.openssl.ossl_typ.BIO* in_, int comp_nid, uint flags);

	int CMS_set1_eContentType(.CMS_ContentInfo* cms, const (libressl.openssl.ossl_typ.ASN1_OBJECT)* oid);
	const (libressl.openssl.ossl_typ.ASN1_OBJECT)* CMS_get0_eContentType(.CMS_ContentInfo* cms);

	.CMS_CertificateChoices* CMS_add0_CertificateChoices(.CMS_ContentInfo* cms);
	int CMS_add0_cert(.CMS_ContentInfo* cms, libressl.openssl.ossl_typ.X509* cert);
	int CMS_add1_cert(.CMS_ContentInfo* cms, libressl.openssl.ossl_typ.X509* cert);
	libressl.openssl.x509.stack_st_X509* CMS_get1_certs(.CMS_ContentInfo* cms);

	.CMS_RevocationInfoChoice* CMS_add0_RevocationInfoChoice(.CMS_ContentInfo* cms);
	int CMS_add0_crl(.CMS_ContentInfo* cms, libressl.openssl.ossl_typ.X509_CRL* crl);
	int CMS_add1_crl(.CMS_ContentInfo* cms, libressl.openssl.ossl_typ.X509_CRL* crl);
	libressl.openssl.x509.stack_st_X509_CRL* CMS_get1_crls(.CMS_ContentInfo* cms);

	int CMS_SignedData_init(.CMS_ContentInfo* cms);
	.CMS_SignerInfo* CMS_add1_signer(.CMS_ContentInfo* cms, libressl.openssl.ossl_typ.X509* signer, libressl.openssl.ossl_typ.EVP_PKEY* pk, const (libressl.openssl.ossl_typ.EVP_MD)* md, uint flags);
	libressl.openssl.ossl_typ.EVP_PKEY_CTX* CMS_SignerInfo_get0_pkey_ctx(.CMS_SignerInfo* si);
	libressl.openssl.ossl_typ.EVP_MD_CTX* CMS_SignerInfo_get0_md_ctx(.CMS_SignerInfo* si);
	.stack_st_CMS_SignerInfo* CMS_get0_SignerInfos(.CMS_ContentInfo* cms);

	void CMS_SignerInfo_set1_signer_cert(.CMS_SignerInfo* si, libressl.openssl.ossl_typ.X509* signer);
	int CMS_SignerInfo_get0_signer_id(.CMS_SignerInfo* si, libressl.openssl.ossl_typ.ASN1_OCTET_STRING** keyid, libressl.openssl.ossl_typ.X509_NAME** issuer, libressl.openssl.ossl_typ.ASN1_INTEGER** sno);
	int CMS_SignerInfo_cert_cmp(.CMS_SignerInfo* si, libressl.openssl.ossl_typ.X509* cert);
	int CMS_set1_signers_certs(.CMS_ContentInfo* cms, libressl.openssl.x509.stack_st_X509* certs, uint flags);
	void CMS_SignerInfo_get0_algs(.CMS_SignerInfo* si, libressl.openssl.ossl_typ.EVP_PKEY** pk, libressl.openssl.ossl_typ.X509** signer, libressl.openssl.ossl_typ.X509_ALGOR** pdig, libressl.openssl.ossl_typ.X509_ALGOR** psig);
	libressl.openssl.ossl_typ.ASN1_OCTET_STRING* CMS_SignerInfo_get0_signature(.CMS_SignerInfo* si);
	int CMS_SignerInfo_sign(.CMS_SignerInfo* si);
	int CMS_SignerInfo_verify(.CMS_SignerInfo* si);
	int CMS_SignerInfo_verify_content(.CMS_SignerInfo* si, libressl.openssl.ossl_typ.BIO* chain);

	int CMS_add_smimecap(.CMS_SignerInfo* si, libressl.openssl.asn1.stack_st_X509_ALGOR* algs);
	int CMS_add_simple_smimecap(libressl.openssl.asn1.stack_st_X509_ALGOR** algs, int algnid, int keysize);
	int CMS_add_standard_smimecap(libressl.openssl.asn1.stack_st_X509_ALGOR** smcap);

	int CMS_signed_get_attr_count(const (.CMS_SignerInfo)* si);
	int CMS_signed_get_attr_by_NID(const (.CMS_SignerInfo)* si, int nid, int lastpos);
	int CMS_signed_get_attr_by_OBJ(const (.CMS_SignerInfo)* si, const (libressl.openssl.ossl_typ.ASN1_OBJECT)* obj, int lastpos);
	libressl.openssl.x509.X509_ATTRIBUTE* CMS_signed_get_attr(const (.CMS_SignerInfo)* si, int loc);
	libressl.openssl.x509.X509_ATTRIBUTE* CMS_signed_delete_attr(.CMS_SignerInfo* si, int loc);
	int CMS_signed_add1_attr(.CMS_SignerInfo* si, libressl.openssl.x509.X509_ATTRIBUTE* attr);
	int CMS_signed_add1_attr_by_OBJ(.CMS_SignerInfo* si, const (libressl.openssl.ossl_typ.ASN1_OBJECT)* obj, int type, const (void)* bytes, int len);
	int CMS_signed_add1_attr_by_NID(.CMS_SignerInfo* si, int nid, int type, const (void)* bytes, int len);
	int CMS_signed_add1_attr_by_txt(.CMS_SignerInfo* si, const (char)* attrname, int type, const (void)* bytes, int len);
	void* CMS_signed_get0_data_by_OBJ(.CMS_SignerInfo* si, const (libressl.openssl.ossl_typ.ASN1_OBJECT)* oid, int lastpos, int type);

	int CMS_unsigned_get_attr_count(const (.CMS_SignerInfo)* si);
	int CMS_unsigned_get_attr_by_NID(const (.CMS_SignerInfo)* si, int nid, int lastpos);
	int CMS_unsigned_get_attr_by_OBJ(const (.CMS_SignerInfo)* si, const (libressl.openssl.ossl_typ.ASN1_OBJECT)* obj, int lastpos);
	libressl.openssl.x509.X509_ATTRIBUTE* CMS_unsigned_get_attr(const (.CMS_SignerInfo)* si, int loc);
	libressl.openssl.x509.X509_ATTRIBUTE* CMS_unsigned_delete_attr(.CMS_SignerInfo* si, int loc);
	int CMS_unsigned_add1_attr(.CMS_SignerInfo* si, libressl.openssl.x509.X509_ATTRIBUTE* attr);
	int CMS_unsigned_add1_attr_by_OBJ(.CMS_SignerInfo* si, const (libressl.openssl.ossl_typ.ASN1_OBJECT)* obj, int type, const (void)* bytes, int len);
	int CMS_unsigned_add1_attr_by_NID(.CMS_SignerInfo* si, int nid, int type, const (void)* bytes, int len);
	int CMS_unsigned_add1_attr_by_txt(.CMS_SignerInfo* si, const (char)* attrname, int type, const (void)* bytes, int len);
	void* CMS_unsigned_get0_data_by_OBJ(.CMS_SignerInfo* si, libressl.openssl.ossl_typ.ASN1_OBJECT* oid, int lastpos, int type);

	static assert(libressl.openssl.x509v3.HEADER_X509V3_H);
	alias stack_st_GENERAL_NAMES = libressl.openssl.x509v3.stack_st_GENERAL_NAMES;
	int CMS_get1_ReceiptRequest(.CMS_SignerInfo* si, .CMS_ReceiptRequest** prr);
	.CMS_ReceiptRequest* CMS_ReceiptRequest_create0(ubyte* id, int idlen, int allorfirst, libressl.openssl.x509v3.stack_st_GENERAL_NAMES* receiptList, libressl.openssl.x509v3.stack_st_GENERAL_NAMES* receiptsTo);
	int CMS_add1_ReceiptRequest(.CMS_SignerInfo* si, .CMS_ReceiptRequest* rr);
	void CMS_ReceiptRequest_get0_values(.CMS_ReceiptRequest* rr, libressl.openssl.ossl_typ.ASN1_STRING** pcid, int* pallorfirst, libressl.openssl.x509v3.stack_st_GENERAL_NAMES** plist, libressl.openssl.x509v3.stack_st_GENERAL_NAMES** prto);

	int CMS_RecipientInfo_kari_get0_alg(.CMS_RecipientInfo* ri, libressl.openssl.ossl_typ.X509_ALGOR** palg, libressl.openssl.ossl_typ.ASN1_OCTET_STRING** pukm);
	.stack_st_CMS_RecipientEncryptedKey* CMS_RecipientInfo_kari_get0_reks(.CMS_RecipientInfo* ri);

	int CMS_RecipientInfo_kari_get0_orig_id(.CMS_RecipientInfo* ri, libressl.openssl.ossl_typ.X509_ALGOR** pubalg, libressl.openssl.ossl_typ.ASN1_BIT_STRING** pubkey, libressl.openssl.ossl_typ.ASN1_OCTET_STRING** keyid, libressl.openssl.ossl_typ.X509_NAME** issuer, libressl.openssl.ossl_typ.ASN1_INTEGER** sno);

	int CMS_RecipientInfo_kari_orig_id_cmp(.CMS_RecipientInfo* ri, libressl.openssl.ossl_typ.X509* cert);

	int CMS_RecipientEncryptedKey_get0_id(.CMS_RecipientEncryptedKey* rek, libressl.openssl.ossl_typ.ASN1_OCTET_STRING** keyid, libressl.openssl.ossl_typ.ASN1_GENERALIZEDTIME** tm, .CMS_OtherKeyAttribute** other, libressl.openssl.ossl_typ.X509_NAME** issuer, libressl.openssl.ossl_typ.ASN1_INTEGER** sno);
	int CMS_RecipientEncryptedKey_cert_cmp(.CMS_RecipientEncryptedKey* rek, libressl.openssl.ossl_typ.X509* cert);
	int CMS_RecipientInfo_kari_set0_pkey(.CMS_RecipientInfo* ri, libressl.openssl.ossl_typ.EVP_PKEY* pk);
	libressl.openssl.ossl_typ.EVP_CIPHER_CTX* CMS_RecipientInfo_kari_get0_ctx(.CMS_RecipientInfo* ri);
	int CMS_RecipientInfo_kari_decrypt(.CMS_ContentInfo* cms, .CMS_RecipientInfo* ri, .CMS_RecipientEncryptedKey* rek);

	int CMS_SharedInfo_encode(ubyte** pder, libressl.openssl.ossl_typ.X509_ALGOR* kekalg, libressl.openssl.ossl_typ.ASN1_OCTET_STRING* ukm, int keylen);

	/* Backward compatibility for spelling errors. */
	alias CMS_R_UNKNOWN_DIGEST_ALGORITM = .CMS_R_UNKNOWN_DIGEST_ALGORITHM;
	alias CMS_R_UNSUPPORTED_RECPIENTINFO_TYPE = .CMS_R_UNSUPPORTED_RECIPIENTINFO_TYPE;

	int ERR_load_CMS_strings();

	/*
	 * CMS function codes.
	 */
	enum CMS_F_CHECK_CONTENT = 99;
	enum CMS_F_CMS_ADD0_CERT = 164;
	enum CMS_F_CMS_ADD0_RECIPIENT_KEY = 100;
	enum CMS_F_CMS_ADD0_RECIPIENT_PASSWORD = 165;
	enum CMS_F_CMS_ADD1_RECEIPTREQUEST = 158;
	enum CMS_F_CMS_ADD1_RECIPIENT_CERT = 101;
	enum CMS_F_CMS_ADD1_SIGNER = 102;
	enum CMS_F_CMS_ADD1_SIGNINGTIME = 103;
	enum CMS_F_CMS_COMPRESS = 104;
	enum CMS_F_CMS_COMPRESSEDDATA_CREATE = 105;
	enum CMS_F_CMS_COMPRESSEDDATA_INIT_BIO = 106;
	enum CMS_F_CMS_COPY_CONTENT = 107;
	enum CMS_F_CMS_COPY_MESSAGEDIGEST = 108;
	enum CMS_F_CMS_DATA = 109;
	enum CMS_F_CMS_DATAFINAL = 110;
	enum CMS_F_CMS_DATAINIT = 111;
	enum CMS_F_CMS_DECRYPT = 112;
	enum CMS_F_CMS_DECRYPT_SET1_KEY = 113;
	enum CMS_F_CMS_DECRYPT_SET1_PASSWORD = 166;
	enum CMS_F_CMS_DECRYPT_SET1_PKEY = 114;
	enum CMS_F_CMS_DIGESTALGORITHM_FIND_CTX = 115;
	enum CMS_F_CMS_DIGESTALGORITHM_INIT_BIO = 116;
	enum CMS_F_CMS_DIGESTEDDATA_DO_FINAL = 117;
	enum CMS_F_CMS_DIGEST_VERIFY = 118;
	enum CMS_F_CMS_ENCODE_RECEIPT = 161;
	enum CMS_F_CMS_ENCRYPT = 119;
	enum CMS_F_CMS_ENCRYPTEDCONTENT_INIT = 179;
	enum CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO = 120;
	enum CMS_F_CMS_ENCRYPTEDDATA_DECRYPT = 121;
	enum CMS_F_CMS_ENCRYPTEDDATA_ENCRYPT = 122;
	enum CMS_F_CMS_ENCRYPTEDDATA_SET1_KEY = 123;
	enum CMS_F_CMS_ENVELOPEDDATA_CREATE = 124;
	enum CMS_F_CMS_ENVELOPEDDATA_INIT_BIO = 125;
	enum CMS_F_CMS_ENVELOPED_DATA_INIT = 126;
	enum CMS_F_CMS_ENV_ASN1_CTRL = 171;
	enum CMS_F_CMS_FINAL = 127;
	enum CMS_F_CMS_GET0_CERTIFICATE_CHOICES = 128;
	enum CMS_F_CMS_GET0_CONTENT = 129;
	enum CMS_F_CMS_GET0_ECONTENT_TYPE = 130;
	enum CMS_F_CMS_GET0_ENVELOPED = 131;
	enum CMS_F_CMS_GET0_REVOCATION_CHOICES = 132;
	enum CMS_F_CMS_GET0_SIGNED = 133;
	enum CMS_F_CMS_MSGSIGDIGEST_ADD1 = 162;
	enum CMS_F_CMS_RECEIPTREQUEST_CREATE0 = 159;
	enum CMS_F_CMS_RECEIPT_VERIFY = 160;
	enum CMS_F_CMS_RECIPIENTINFO_DECRYPT = 134;
	enum CMS_F_CMS_RECIPIENTINFO_ENCRYPT = 169;
	enum CMS_F_CMS_RECIPIENTINFO_KARI_ENCRYPT = 178;
	enum CMS_F_CMS_RECIPIENTINFO_KARI_GET0_ALG = 175;
	enum CMS_F_CMS_RECIPIENTINFO_KARI_GET0_ORIG_ID = 173;
	enum CMS_F_CMS_RECIPIENTINFO_KARI_GET0_REKS = 172;
	enum CMS_F_CMS_RECIPIENTINFO_KARI_ORIG_ID_CMP = 174;
	enum CMS_F_CMS_RECIPIENTINFO_KEKRI_DECRYPT = 135;
	enum CMS_F_CMS_RECIPIENTINFO_KEKRI_ENCRYPT = 136;
	enum CMS_F_CMS_RECIPIENTINFO_KEKRI_GET0_ID = 137;
	enum CMS_F_CMS_RECIPIENTINFO_KEKRI_ID_CMP = 138;
	enum CMS_F_CMS_RECIPIENTINFO_KTRI_CERT_CMP = 139;
	enum CMS_F_CMS_RECIPIENTINFO_KTRI_DECRYPT = 140;
	enum CMS_F_CMS_RECIPIENTINFO_KTRI_ENCRYPT = 141;
	enum CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_ALGS = 142;
	enum CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_SIGNER_ID = 143;
	enum CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT = 167;
	enum CMS_F_CMS_RECIPIENTINFO_SET0_KEY = 144;
	enum CMS_F_CMS_RECIPIENTINFO_SET0_PASSWORD = 168;
	enum CMS_F_CMS_RECIPIENTINFO_SET0_PKEY = 145;
	enum CMS_F_CMS_SD_ASN1_CTRL = 170;
	enum CMS_F_CMS_SET1_IAS = 176;
	enum CMS_F_CMS_SET1_KEYID = 177;
	enum CMS_F_CMS_SET1_SIGNERIDENTIFIER = 146;
	enum CMS_F_CMS_SET_DETACHED = 147;
	enum CMS_F_CMS_SIGN = 148;
	enum CMS_F_CMS_SIGNED_DATA_INIT = 149;
	enum CMS_F_CMS_SIGNERINFO_CONTENT_SIGN = 150;
	enum CMS_F_CMS_SIGNERINFO_SIGN = 151;
	enum CMS_F_CMS_SIGNERINFO_VERIFY = 152;
	enum CMS_F_CMS_SIGNERINFO_VERIFY_CERT = 153;
	enum CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT = 154;
	enum CMS_F_CMS_SIGN_RECEIPT = 163;
	enum CMS_F_CMS_STREAM = 155;
	enum CMS_F_CMS_UNCOMPRESS = 156;
	enum CMS_F_CMS_VERIFY = 157;
	enum CMS_F_KEK_UNWRAP_KEY = 180;

	/*
	 * CMS reason codes.
	 */
	enum CMS_R_ADD_SIGNER_ERROR = 99;
	enum CMS_R_CERTIFICATE_ALREADY_PRESENT = 175;
	enum CMS_R_CERTIFICATE_HAS_NO_KEYID = 160;
	enum CMS_R_CERTIFICATE_VERIFY_ERROR = 100;
	enum CMS_R_CIPHER_INITIALISATION_ERROR = 101;
	enum CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR = 102;
	enum CMS_R_CMS_DATAFINAL_ERROR = 103;
	enum CMS_R_CMS_LIB = 104;
	enum CMS_R_CONTENTIDENTIFIER_MISMATCH = 170;
	enum CMS_R_CONTENT_NOT_FOUND = 105;
	enum CMS_R_CONTENT_TYPE_MISMATCH = 171;
	enum CMS_R_CONTENT_TYPE_NOT_COMPRESSED_DATA = 106;
	enum CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA = 107;
	enum CMS_R_CONTENT_TYPE_NOT_SIGNED_DATA = 108;
	enum CMS_R_CONTENT_VERIFY_ERROR = 109;
	enum CMS_R_CTRL_ERROR = 110;
	enum CMS_R_CTRL_FAILURE = 111;
	enum CMS_R_DECRYPT_ERROR = 112;
	enum CMS_R_ERROR_GETTING_PUBLIC_KEY = 113;
	enum CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE = 114;
	enum CMS_R_ERROR_SETTING_KEY = 115;
	enum CMS_R_ERROR_SETTING_RECIPIENTINFO = 116;
	enum CMS_R_INVALID_ENCRYPTED_KEY_LENGTH = 117;
	enum CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER = 176;
	enum CMS_R_INVALID_KEY_LENGTH = 118;
	enum CMS_R_MD_BIO_INIT_ERROR = 119;
	enum CMS_R_MESSAGEDIGEST_ATTRIBUTE_WRONG_LENGTH = 120;
	enum CMS_R_MESSAGEDIGEST_WRONG_LENGTH = 121;
	enum CMS_R_MSGSIGDIGEST_ERROR = 172;
	enum CMS_R_MSGSIGDIGEST_VERIFICATION_FAILURE = 162;
	enum CMS_R_MSGSIGDIGEST_WRONG_LENGTH = 163;
	enum CMS_R_NEED_ONE_SIGNER = 164;
	enum CMS_R_NOT_A_SIGNED_RECEIPT = 165;
	enum CMS_R_NOT_ENCRYPTED_DATA = 122;
	enum CMS_R_NOT_KEK = 123;
	enum CMS_R_NOT_KEY_AGREEMENT = 181;
	enum CMS_R_NOT_KEY_TRANSPORT = 124;
	enum CMS_R_NOT_PWRI = 177;
	enum CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE = 125;
	enum CMS_R_NO_CIPHER = 126;
	enum CMS_R_NO_CONTENT = 127;
	enum CMS_R_NO_CONTENT_TYPE = 173;
	enum CMS_R_NO_DEFAULT_DIGEST = 128;
	enum CMS_R_NO_DIGEST_SET = 129;
	enum CMS_R_NO_KEY = 130;
	enum CMS_R_NO_KEY_OR_CERT = 174;
	enum CMS_R_NO_MATCHING_DIGEST = 131;
	enum CMS_R_NO_MATCHING_RECIPIENT = 132;
	enum CMS_R_NO_MATCHING_SIGNATURE = 166;
	enum CMS_R_NO_MSGSIGDIGEST = 167;
	enum CMS_R_NO_PASSWORD = 178;
	enum CMS_R_NO_PRIVATE_KEY = 133;
	enum CMS_R_NO_PUBLIC_KEY = 134;
	enum CMS_R_NO_RECEIPT_REQUEST = 168;
	enum CMS_R_NO_SIGNERS = 135;
	enum CMS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 136;
	enum CMS_R_RECEIPT_DECODE_ERROR = 169;
	enum CMS_R_RECIPIENT_ERROR = 137;
	enum CMS_R_SIGNER_CERTIFICATE_NOT_FOUND = 138;
	enum CMS_R_SIGNFINAL_ERROR = 139;
	enum CMS_R_SMIME_TEXT_ERROR = 140;
	enum CMS_R_STORE_INIT_ERROR = 141;
	enum CMS_R_TYPE_NOT_COMPRESSED_DATA = 142;
	enum CMS_R_TYPE_NOT_DATA = 143;
	enum CMS_R_TYPE_NOT_DIGESTED_DATA = 144;
	enum CMS_R_TYPE_NOT_ENCRYPTED_DATA = 145;
	enum CMS_R_TYPE_NOT_ENVELOPED_DATA = 146;
	enum CMS_R_UNABLE_TO_FINALIZE_CONTEXT = 147;
	enum CMS_R_UNKNOWN_CIPHER = 148;
	enum CMS_R_UNKNOWN_DIGEST_ALGORITHM = 149;
	enum CMS_R_UNKNOWN_ID = 150;
	enum CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM = 151;
	enum CMS_R_UNSUPPORTED_CONTENT_TYPE = 152;
	enum CMS_R_UNSUPPORTED_KEK_ALGORITHM = 153;
	enum CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM = 179;
	enum CMS_R_UNSUPPORTED_RECIPIENTINFO_TYPE = 155;
	enum CMS_R_UNSUPPORTED_RECIPIENT_TYPE = 154;
	enum CMS_R_UNSUPPORTED_TYPE = 156;
	enum CMS_R_UNWRAP_ERROR = 157;
	enum CMS_R_UNWRAP_FAILURE = 180;
	enum CMS_R_VERIFICATION_FAILURE = 158;
	enum CMS_R_WRAP_ERROR = 159;
}
