/* $OpenBSD: objects.h,v 1.21 2022/11/13 14:03:13 tb Exp $ */
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
module libressl.openssl.objects;


private static import core.stdc.config;
private static import libressl.openssl.ossl_typ;
public import libressl.openssl.asn1;
public import libressl.openssl.bio;
public import libressl.openssl.obj_mac;

enum SN_ED25519 = libressl.openssl.obj_mac.SN_Ed25519;
enum NID_ED25519 = libressl.openssl.obj_mac.NID_Ed25519;
//enum OBJ_ED25519 = libressl.openssl.obj_mac.OBJ_Ed25519;

enum OBJ_NAME_TYPE_UNDEF = 0x00;
enum OBJ_NAME_TYPE_MD_METH = 0x01;
enum OBJ_NAME_TYPE_CIPHER_METH = 0x02;
enum OBJ_NAME_TYPE_PKEY_METH = 0x03;
enum OBJ_NAME_TYPE_COMP_METH = 0x04;
enum OBJ_NAME_TYPE_NUM = 0x05;

enum OBJ_NAME_ALIAS = 0x8000;

enum OBJ_BSEARCH_VALUE_ON_NOMATCH = 0x01;
enum OBJ_BSEARCH_FIRST_VALUE_ON_MATCH = 0x02;

extern (C):
nothrow @nogc:

struct obj_name_st
{
	int type;
	int alias_;
	const (char)* name;
	const (char)* data;
}

alias OBJ_NAME = .obj_name_st;

alias OBJ_create_and_add_object = .OBJ_create;

int OBJ_NAME_init();

int OBJ_NAME_new_index(core.stdc.config.c_ulong function(const (char)*) nothrow @nogc hash_func, int function(const (char)*, const (char)*) nothrow @nogc cmp_func, void function(const (char)*, int, const (char)*) nothrow @nogc free_func);
const (char)* OBJ_NAME_get(const (char)* name, int type);
int OBJ_NAME_add(const (char)* name, int type, const (char)* data);
int OBJ_NAME_remove(const (char)* name, int type);

/**
 * -1 for everything
 */
void OBJ_NAME_cleanup(int type);

void OBJ_NAME_do_all(int type, void function(const (.OBJ_NAME)*, void* arg) nothrow @nogc fn, void* arg);
void OBJ_NAME_do_all_sorted(int type, void function(const (.OBJ_NAME)*, void* arg) nothrow @nogc fn, void* arg);
libressl.openssl.ossl_typ.ASN1_OBJECT* OBJ_dup(const (libressl.openssl.ossl_typ.ASN1_OBJECT)* o);
libressl.openssl.ossl_typ.ASN1_OBJECT* OBJ_nid2obj(int n);
const (char)* OBJ_nid2ln(int n);
const (char)* OBJ_nid2sn(int n);
int OBJ_obj2nid(const (libressl.openssl.ossl_typ.ASN1_OBJECT)* o);
libressl.openssl.ossl_typ.ASN1_OBJECT* OBJ_txt2obj(const (char)* s, int no_name);
int OBJ_obj2txt(char* buf, int buf_len, const (libressl.openssl.ossl_typ.ASN1_OBJECT)* a, int no_name);
int OBJ_txt2nid(const (char)* s);
int OBJ_ln2nid(const (char)* s);
int OBJ_sn2nid(const (char)* s);
int OBJ_cmp(const (libressl.openssl.ossl_typ.ASN1_OBJECT)* a, const (libressl.openssl.ossl_typ.ASN1_OBJECT)* b);

version (LIBRESSL_INTERNAL) {
	const (void)* OBJ_bsearch_(const (void)* key, const (void)* base, int num, int size, int function(const (void)*, const (void)*) nothrow @nogc cmp);
	const (void)* OBJ_bsearch_ex_(const (void)* key, const (void)* base, int num, int size, int function(const (void)*, const (void)*) nothrow @nogc cmp, int flags);
}

int OBJ_new_nid(int num);
int OBJ_add_object(const (libressl.openssl.ossl_typ.ASN1_OBJECT)* obj);
int OBJ_create(const (char)* oid, const (char)* sn, const (char)* ln);
void OBJ_cleanup();
int OBJ_create_objects(libressl.openssl.ossl_typ.BIO* in_);

size_t OBJ_length(const (libressl.openssl.ossl_typ.ASN1_OBJECT)* obj);
const (ubyte)* OBJ_get0_data(const (libressl.openssl.ossl_typ.ASN1_OBJECT)* obj);

int OBJ_find_sigid_algs(int signid, int* pdig_nid, int* ppkey_nid);
int OBJ_find_sigid_by_algs(int* psignid, int dig_nid, int pkey_nid);
int OBJ_add_sigid(int signid, int dig_id, int pkey_id);
void OBJ_sigid_free();

version (LIBRESSL_CRYPTO_INTERNAL) {
	extern __gshared int obj_cleanup_defer;
	void check_defer(int nid);
}

void ERR_load_OBJ_strings();

/* Error codes for the OBJ functions. */

/* Function codes. */
enum OBJ_F_OBJ_ADD_OBJECT = 105;
enum OBJ_F_OBJ_CREATE = 100;
enum OBJ_F_OBJ_DUP = 101;
enum OBJ_F_OBJ_NAME_NEW_INDEX = 106;
enum OBJ_F_OBJ_NID2LN = 102;
enum OBJ_F_OBJ_NID2OBJ = 103;
enum OBJ_F_OBJ_NID2SN = 104;

/* Reason codes. */
enum OBJ_R_MALLOC_FAILURE = 100;
enum OBJ_R_UNKNOWN_NID = 101;
