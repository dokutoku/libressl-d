/* $OpenBSD: pkcs12.h,v 1.27 2022/09/11 17:30:13 tb Exp $ */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
module libressl.openssl.pkcs12;


private static import core.stdc.config;
private static import libressl.compat.stdio;
private static import libressl.openssl.asn1;
private static import libressl.openssl.evp;
private static import libressl.openssl.ossl_typ;
private static import libressl.openssl.pkcs7;
private static import libressl.openssl.stack;
public import libressl.openssl.bio;
public import libressl.openssl.x509;

extern (C):
nothrow @nogc:

enum PKCS12_KEY_ID = 1;
enum PKCS12_IV_ID = 2;
enum PKCS12_MAC_ID = 3;

/* Default iteration count */
//#if !defined(PKCS12_DEFAULT_ITER)
	alias PKCS12_DEFAULT_ITER = libressl.openssl.evp.PKCS5_DEFAULT_ITER;
//#endif

enum PKCS12_MAC_KEY_LENGTH = 20;

enum PKCS12_SALT_LEN = 8;

/* Uncomment out next line for unicode password and names, otherwise ASCII */

/* version = PBE_UNICODE; */

version (PBE_UNICODE) {
	alias PKCS12_key_gen = .PKCS12_key_gen_uni;
	alias PKCS12_add_friendlyname = .PKCS12_add_friendlyname_uni;
} else {
	alias PKCS12_key_gen = .PKCS12_key_gen_asc;
	alias PKCS12_add_friendlyname = .PKCS12_add_friendlyname_asc;
}

/* MS key usage constants */

enum KEY_EX = 0x10;
enum KEY_SIG = 0x80;

struct PKCS12_MAC_DATA_st;
alias PKCS12_MAC_DATA = .PKCS12_MAC_DATA_st;

struct PKCS12_st;
alias PKCS12 = .PKCS12_st;

struct PKCS12_SAFEBAG_st;
alias PKCS12_SAFEBAG = .PKCS12_SAFEBAG_st;

//DECLARE_STACK_OF(PKCS12_SAFEBAG)
struct stack_st_PKCS12_SAFEBAG
{
	libressl.openssl.stack._STACK stack;
}

mixin (libressl.openssl.ossl_typ.DECLARE_PKCS12_STACK_OF!("PKCS12_SAFEBAG"));

struct pkcs12_bag_st;
alias PKCS12_BAGS = .pkcs12_bag_st;

enum PKCS12_ERROR = 0;
enum PKCS12_OK = 1;

version (LIBRESSL_INTERNAL) {
} else {
	/* Compatibility macros */

	alias M_PKCS12_x5092certbag = .PKCS12_x5092certbag;
	alias M_PKCS12_x509crl2certbag = .PKCS12_x509crl2certbag;

	alias M_PKCS12_certbag2x509 = .PKCS12_certbag2x509;
	alias M_PKCS12_certbag2x509crl = .PKCS12_certbag2x509crl;

	alias M_PKCS12_unpack_p7data = .PKCS12_unpack_p7data;
	alias M_PKCS12_pack_authsafes = .PKCS12_pack_authsafes;
	alias M_PKCS12_unpack_authsafes = .PKCS12_unpack_authsafes;
	alias M_PKCS12_unpack_p7encdata = .PKCS12_unpack_p7encdata;

	alias M_PKCS12_decrypt_skey = .PKCS12_decrypt_skey;
	alias M_PKCS8_decrypt = .PKCS8_decrypt;
}

alias M_PKCS12_bag_type = .PKCS12_bag_type;
alias M_PKCS12_cert_bag_type = .PKCS12_cert_bag_type;
alias M_PKCS12_crl_bag_type = .PKCS12_cert_bag_type;

alias PKCS12_bag_type = .PKCS12_SAFEBAG_get_nid;
alias PKCS12_cert_bag_type = .PKCS12_SAFEBAG_get_bag_nid;

alias PKCS12_certbag2x509 = .PKCS12_SAFEBAG_get1_cert;
alias PKCS12_certbag2x509crl = .PKCS12_SAFEBAG_get1_crl;

alias PKCS12_x5092certbag = .PKCS12_SAFEBAG_create_cert;
alias PKCS12_x509crl2certbag = .PKCS12_SAFEBAG_create_crl;
alias PKCS12_MAKE_KEYBAG = .PKCS12_SAFEBAG_create0_p8inf;
alias PKCS12_MAKE_SHKEYBAG = .PKCS12_SAFEBAG_create_pkcs8_encrypt;

const (libressl.openssl.asn1.ASN1_TYPE)* PKCS12_SAFEBAG_get0_attr(const (.PKCS12_SAFEBAG)* bag, int attr_nid);
const (libressl.openssl.x509.stack_st_X509_ATTRIBUTE)* PKCS12_SAFEBAG_get0_attrs(const (.PKCS12_SAFEBAG)* bag);
int PKCS12_SAFEBAG_get_nid(const (.PKCS12_SAFEBAG)* bag);
int PKCS12_SAFEBAG_get_bag_nid(const (.PKCS12_SAFEBAG)* bag);

libressl.openssl.ossl_typ.X509* PKCS12_SAFEBAG_get1_cert(const (.PKCS12_SAFEBAG)* bag);
libressl.openssl.ossl_typ.X509_CRL* PKCS12_SAFEBAG_get1_crl(const (.PKCS12_SAFEBAG)* bag);

libressl.openssl.asn1.ASN1_TYPE* PKCS8_get_attr(libressl.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* p8, int attr_nid);
int PKCS12_mac_present(const (.PKCS12)* p12);
void PKCS12_get0_mac(const (libressl.openssl.ossl_typ.ASN1_OCTET_STRING)** pmac, const (libressl.openssl.ossl_typ.X509_ALGOR)** pmacalg, const (libressl.openssl.ossl_typ.ASN1_OCTET_STRING)** psalt, const (libressl.openssl.ossl_typ.ASN1_INTEGER)** piter, const (.PKCS12)* p12);

.PKCS12_SAFEBAG* PKCS12_SAFEBAG_create_cert(libressl.openssl.ossl_typ.X509* x509);
.PKCS12_SAFEBAG* PKCS12_SAFEBAG_create_crl(libressl.openssl.ossl_typ.X509_CRL* crl);
.PKCS12_SAFEBAG* PKCS12_SAFEBAG_create0_p8inf(libressl.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* p8);
.PKCS12_SAFEBAG* PKCS12_SAFEBAG_create0_pkcs8(libressl.openssl.x509.X509_SIG* p8);
.PKCS12_SAFEBAG* PKCS12_SAFEBAG_create_pkcs8_encrypt(int pbe_nid, const (char)* pass, int passlen, ubyte* salt, int saltlen, int iter, libressl.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* p8);

const (libressl.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO)* PKCS12_SAFEBAG_get0_p8inf(const (.PKCS12_SAFEBAG)* bag);
const (libressl.openssl.x509.X509_SIG)* PKCS12_SAFEBAG_get0_pkcs8(const (.PKCS12_SAFEBAG)* bag);
const (.stack_st_PKCS12_SAFEBAG)* PKCS12_SAFEBAG_get0_safes(const (.PKCS12_SAFEBAG)* bag);
const (libressl.openssl.ossl_typ.ASN1_OBJECT)* PKCS12_SAFEBAG_get0_type(const (.PKCS12_SAFEBAG)* bag);

.PKCS12_SAFEBAG* PKCS12_item_pack_safebag(void* obj, const (libressl.openssl.ossl_typ.ASN1_ITEM)* it, int nid1, int nid2);
libressl.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* PKCS8_decrypt(const (libressl.openssl.x509.X509_SIG)* p8, const (char)* pass, int passlen);
libressl.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* PKCS12_decrypt_skey(const (.PKCS12_SAFEBAG)* bag, const (char)* pass, int passlen);
libressl.openssl.x509.X509_SIG* PKCS8_encrypt(int pbe_nid, const (libressl.openssl.ossl_typ.EVP_CIPHER)* cipher, const (char)* pass, int passlen, ubyte* salt, int saltlen, int iter, libressl.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* p8);
libressl.openssl.pkcs7.PKCS7* PKCS12_pack_p7data(.stack_st_PKCS12_SAFEBAG * sk);
.stack_st_PKCS12_SAFEBAG* PKCS12_unpack_p7data(libressl.openssl.pkcs7.PKCS7* p7);
libressl.openssl.pkcs7.PKCS7* PKCS12_pack_p7encdata(int pbe_nid, const (char)* pass, int passlen, ubyte* salt, int saltlen, int iter, .stack_st_PKCS12_SAFEBAG * bags);
.stack_st_PKCS12_SAFEBAG* PKCS12_unpack_p7encdata(libressl.openssl.pkcs7.PKCS7* p7, const (char)* pass, int passlen);

int PKCS12_pack_authsafes(.PKCS12* p12, libressl.openssl.pkcs7.stack_st_PKCS7* safes);
libressl.openssl.pkcs7.stack_st_PKCS7* PKCS12_unpack_authsafes(const (.PKCS12)* p12);

int PKCS12_add_localkeyid(.PKCS12_SAFEBAG* bag, ubyte* name, int namelen);
int PKCS12_add_friendlyname_asc(.PKCS12_SAFEBAG* bag, const (char)* name, int namelen);
int PKCS12_add_CSPName_asc(.PKCS12_SAFEBAG* bag, const (char)* name, int namelen);
int PKCS12_add_friendlyname_uni(.PKCS12_SAFEBAG* bag, const (ubyte)* name, int namelen);
int PKCS8_add_keyusage(libressl.openssl.ossl_typ.PKCS8_PRIV_KEY_INFO* p8, int usage);
libressl.openssl.asn1.ASN1_TYPE* PKCS12_get_attr_gen(const (libressl.openssl.x509.stack_st_X509_ATTRIBUTE)* attrs, int attr_nid);
char* PKCS12_get_friendlyname(.PKCS12_SAFEBAG* bag);
ubyte* PKCS12_pbe_crypt(const (libressl.openssl.ossl_typ.X509_ALGOR)* algor, const (char)* pass, int passlen, const (ubyte)* in_, int inlen, ubyte** data, int* datalen, int en_de);
void* PKCS12_item_decrypt_d2i(const (libressl.openssl.ossl_typ.X509_ALGOR)* algor, const (libressl.openssl.ossl_typ.ASN1_ITEM)* it, const (char)* pass, int passlen, const (libressl.openssl.ossl_typ.ASN1_OCTET_STRING)* oct, int zbuf);
libressl.openssl.ossl_typ.ASN1_OCTET_STRING* PKCS12_item_i2d_encrypt(libressl.openssl.ossl_typ.X509_ALGOR* algor, const (libressl.openssl.ossl_typ.ASN1_ITEM)* it, const (char)* pass, int passlen, void* obj, int zbuf);
.PKCS12* PKCS12_init(int mode);
int PKCS12_key_gen_asc(const (char)* pass, int passlen, ubyte* salt, int saltlen, int id, int iter, int n, ubyte* out_, const (libressl.openssl.ossl_typ.EVP_MD)* md_type);
int PKCS12_key_gen_uni(ubyte* pass, int passlen, ubyte* salt, int saltlen, int id, int iter, int n, ubyte* out_, const (libressl.openssl.ossl_typ.EVP_MD)* md_type);
int PKCS12_PBE_keyivgen(libressl.openssl.ossl_typ.EVP_CIPHER_CTX* ctx, const (char)* pass, int passlen, libressl.openssl.asn1.ASN1_TYPE* param, const (libressl.openssl.ossl_typ.EVP_CIPHER)* cipher, const (libressl.openssl.ossl_typ.EVP_MD)* md_type, int en_de);
int PKCS12_gen_mac(.PKCS12* p12, const (char)* pass, int passlen, ubyte* mac, uint* maclen);
int PKCS12_verify_mac(.PKCS12* p12, const (char)* pass, int passlen);
int PKCS12_set_mac(.PKCS12* p12, const (char)* pass, int passlen, ubyte* salt, int saltlen, int iter, const (libressl.openssl.ossl_typ.EVP_MD)* md_type);
int PKCS12_setup_mac(.PKCS12* p12, int iter, ubyte* salt, int saltlen, const (libressl.openssl.ossl_typ.EVP_MD)* md_type);
ubyte* OPENSSL_asc2uni(const (char)* asc, int asclen, ubyte** uni, int* unilen);
char* OPENSSL_uni2asc(const (ubyte)* uni, int unilen);

.PKCS12* PKCS12_new();
void PKCS12_free(.PKCS12* a);
.PKCS12* d2i_PKCS12(.PKCS12** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKCS12(.PKCS12* a, ubyte** out_);
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS12_it;
.PKCS12_MAC_DATA* PKCS12_MAC_DATA_new();
void PKCS12_MAC_DATA_free(.PKCS12_MAC_DATA* a);
.PKCS12_MAC_DATA* d2i_PKCS12_MAC_DATA(.PKCS12_MAC_DATA** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKCS12_MAC_DATA(.PKCS12_MAC_DATA* a, ubyte** out_);
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS12_MAC_DATA_it;
.PKCS12_SAFEBAG* PKCS12_SAFEBAG_new();
void PKCS12_SAFEBAG_free(.PKCS12_SAFEBAG* a);
.PKCS12_SAFEBAG* d2i_PKCS12_SAFEBAG(.PKCS12_SAFEBAG** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKCS12_SAFEBAG(.PKCS12_SAFEBAG* a, ubyte** out_);
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS12_SAFEBAG_it;
.PKCS12_BAGS* PKCS12_BAGS_new();
void PKCS12_BAGS_free(.PKCS12_BAGS* a);
.PKCS12_BAGS* d2i_PKCS12_BAGS(.PKCS12_BAGS** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_PKCS12_BAGS(.PKCS12_BAGS* a, ubyte** out_);
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS12_BAGS_it;

extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS12_SAFEBAGS_it;
extern __gshared const libressl.openssl.ossl_typ.ASN1_ITEM PKCS12_AUTHSAFES_it;

void PKCS12_PBE_add();
int PKCS12_parse(.PKCS12* p12, const (char)* pass, libressl.openssl.ossl_typ.EVP_PKEY** pkey, libressl.openssl.ossl_typ.X509** cert, libressl.openssl.x509.stack_st_X509** ca);
.PKCS12* PKCS12_create(const (char)* pass, const (char)* name, libressl.openssl.ossl_typ.EVP_PKEY* pkey, libressl.openssl.ossl_typ.X509* cert, libressl.openssl.x509.stack_st_X509* ca, int nid_key, int nid_cert, int iter, int mac_iter, int keytype);

.PKCS12_SAFEBAG* PKCS12_add_cert(.stack_st_PKCS12_SAFEBAG** pbags, libressl.openssl.ossl_typ.X509* cert);
.PKCS12_SAFEBAG* PKCS12_add_key(.stack_st_PKCS12_SAFEBAG** pbags, libressl.openssl.ossl_typ.EVP_PKEY* key, int key_usage, int iter, int key_nid, const (char)* pass);
int PKCS12_add_safe(libressl.openssl.pkcs7.stack_st_PKCS7** psafes, .stack_st_PKCS12_SAFEBAG * bags, int safe_nid, int iter, const (char)* pass);
.PKCS12* PKCS12_add_safes(libressl.openssl.pkcs7.stack_st_PKCS7* safes, int p7_nid);

int i2d_PKCS12_bio(libressl.openssl.ossl_typ.BIO* bp, .PKCS12* p12);
int i2d_PKCS12_fp(libressl.compat.stdio.FILE* fp, .PKCS12* p12);
.PKCS12* d2i_PKCS12_bio(libressl.openssl.ossl_typ.BIO* bp, .PKCS12** p12);
.PKCS12* d2i_PKCS12_fp(libressl.compat.stdio.FILE* fp, .PKCS12** p12);
int PKCS12_newpass(.PKCS12* p12, const (char)* oldpass, const (char)* newpass);

void ERR_load_PKCS12_strings();

/* Error codes for the PKCS12 functions. */

/* Function codes. */
enum PKCS12_F_PARSE_BAG = 129;
enum PKCS12_F_PARSE_BAGS = 103;
enum PKCS12_F_PKCS12_ADD_FRIENDLYNAME = 100;
enum PKCS12_F_PKCS12_ADD_FRIENDLYNAME_ASC = 127;
enum PKCS12_F_PKCS12_ADD_FRIENDLYNAME_UNI = 102;
enum PKCS12_F_PKCS12_ADD_LOCALKEYID = 104;
enum PKCS12_F_PKCS12_CREATE = 105;
enum PKCS12_F_PKCS12_GEN_MAC = 107;
enum PKCS12_F_PKCS12_INIT = 109;
enum PKCS12_F_PKCS12_ITEM_DECRYPT_D2I = 106;
enum PKCS12_F_PKCS12_ITEM_I2D_ENCRYPT = 108;
enum PKCS12_F_PKCS12_ITEM_PACK_SAFEBAG = 117;
enum PKCS12_F_PKCS12_KEY_GEN_ASC = 110;
enum PKCS12_F_PKCS12_KEY_GEN_UNI = 111;
enum PKCS12_F_PKCS12_MAKE_KEYBAG = 112;
enum PKCS12_F_PKCS12_MAKE_SHKEYBAG = 113;
enum PKCS12_F_PKCS12_NEWPASS = 128;
enum PKCS12_F_PKCS12_PACK_P7DATA = 114;
enum PKCS12_F_PKCS12_PACK_P7ENCDATA = 115;
enum PKCS12_F_PKCS12_PARSE = 118;
enum PKCS12_F_PKCS12_PBE_CRYPT = 119;
enum PKCS12_F_PKCS12_PBE_KEYIVGEN = 120;
enum PKCS12_F_PKCS12_SETUP_MAC = 122;
enum PKCS12_F_PKCS12_SET_MAC = 123;
enum PKCS12_F_PKCS12_UNPACK_AUTHSAFES = 130;
enum PKCS12_F_PKCS12_UNPACK_P7DATA = 131;
enum PKCS12_F_PKCS12_VERIFY_MAC = 126;
enum PKCS12_F_PKCS8_ADD_KEYUSAGE = 124;
enum PKCS12_F_PKCS8_ENCRYPT = 125;

/* Reason codes. */
enum PKCS12_R_CANT_PACK_STRUCTURE = 100;
enum PKCS12_R_CONTENT_TYPE_NOT_DATA = 121;
enum PKCS12_R_DECODE_ERROR = 101;
enum PKCS12_R_ENCODE_ERROR = 102;
enum PKCS12_R_ENCRYPT_ERROR = 103;
enum PKCS12_R_ERROR_SETTING_ENCRYPTED_DATA_TYPE = 120;
enum PKCS12_R_INVALID_NULL_ARGUMENT = 104;
enum PKCS12_R_INVALID_NULL_PKCS12_POINTER = 105;
enum PKCS12_R_IV_GEN_ERROR = 106;
enum PKCS12_R_KEY_GEN_ERROR = 107;
enum PKCS12_R_MAC_ABSENT = 108;
enum PKCS12_R_MAC_GENERATION_ERROR = 109;
enum PKCS12_R_MAC_SETUP_ERROR = 110;
enum PKCS12_R_MAC_STRING_SET_ERROR = 111;
enum PKCS12_R_MAC_VERIFY_ERROR = 112;
enum PKCS12_R_MAC_VERIFY_FAILURE = 113;
enum PKCS12_R_PARSE_ERROR = 114;
enum PKCS12_R_PKCS12_ALGOR_CIPHERINIT_ERROR = 115;
enum PKCS12_R_PKCS12_CIPHERFINAL_ERROR = 116;
enum PKCS12_R_PKCS12_PBE_CRYPT_ERROR = 117;
enum PKCS12_R_UNKNOWN_DIGEST_ALGORITHM = 118;
enum PKCS12_R_UNSUPPORTED_PKCS12_MODE = 119;
