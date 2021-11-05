/* $OpenBSD: txt_db.h,v 1.9 2014/07/10 22:45:58 jsing Exp $ */
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
module libressl_d.openssl.txt_db;


private static import core.stdc.config;
private static import libressl_d.openssl.safestack;
public import libressl_d.openssl.lhash;
public import libressl_d.openssl.opensslconf;
public import libressl_d.openssl.stack;

version (OPENSSL_NO_BIO) {
} else {
	public import libressl_d.openssl.bio;
}

enum DB_ERROR_OK = 0;
enum DB_ERROR_MALLOC = 1;
enum DB_ERROR_INDEX_CLASH = 2;
enum DB_ERROR_INDEX_OUT_OF_RANGE = 3;
enum DB_ERROR_NO_INDEX = 4;
enum DB_ERROR_INSERT_INDEX_CLASH = 5;

extern (C):
nothrow @nogc:

alias OPENSSL_PSTRING = libressl_d.openssl.safestack.OPENSSL_STRING*;

//DECLARE_SPECIAL_STACK_OF(OPENSSL_PSTRING, OPENSSL_STRING)
struct stack_st_OPENSSL_PSTRING
{
	libressl_d.openssl.stack._STACK stack;
}

package alias lhash_st_OPENSSL_STRING = void;

struct txt_db_st
{
	int num_fields;
	.stack_st_OPENSSL_PSTRING* data;
	lhash_st_OPENSSL_STRING** index;
	int function(libressl_d.openssl.safestack.OPENSSL_STRING*)* qual;
	core.stdc.config.c_long error;
	core.stdc.config.c_long arg1;
	core.stdc.config.c_long arg2;
	libressl_d.openssl.safestack.OPENSSL_STRING* arg_row;
}

alias TXT_DB = .txt_db_st;

version (OPENSSL_NO_BIO) {
	.TXT_DB* TXT_DB_read(char* in_, int num);
	core.stdc.config.c_long TXT_DB_write(char* out_, .TXT_DB* db);
} else {
	.TXT_DB* TXT_DB_read(libressl_d.openssl.bio.BIO* in_, int num);
	core.stdc.config.c_long TXT_DB_write(libressl_d.openssl.bio.BIO* out_, .TXT_DB* db);
}

int TXT_DB_create_index(.TXT_DB* db, int field, int function(libressl_d.openssl.safestack.OPENSSL_STRING*) qual, libressl_d.openssl.lhash.LHASH_HASH_FN_TYPE hash, libressl_d.openssl.lhash.LHASH_COMP_FN_TYPE cmp);
void TXT_DB_free(.TXT_DB* db);
libressl_d.openssl.safestack.OPENSSL_STRING* TXT_DB_get_by_index(.TXT_DB* db, int idx, libressl_d.openssl.safestack.OPENSSL_STRING* value);
int TXT_DB_insert(.TXT_DB* db, libressl_d.openssl.safestack.OPENSSL_STRING* value);
