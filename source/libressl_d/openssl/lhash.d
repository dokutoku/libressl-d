/* $OpenBSD: lhash.h,v 1.12 2014/06/12 15:49:29 deraadt Exp $ */
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

/*
 * Header for dynamic hash table routines
 * Author - Eric Young
 */
module libressl_d.openssl.lhash;


private static import core.stdc.config;
private static import libressl_d.openssl.asn1;
private static import libressl_d.openssl.ossl_typ;
public import libressl_d.compat.stdio;
public import libressl_d.openssl.opensslconf;

version (OPENSSL_NO_BIO) {
} else {
	public import libressl_d.openssl.bio;
}

extern (C):
nothrow @nogc:

struct lhash_node_st
{
	void* data;
	.lhash_node_st* next;

	version (OPENSSL_NO_HASH_COMP) {
	} else {
		core.stdc.config.c_ulong hash;
	}
}

alias LHASH_NODE = .lhash_node_st;

alias LHASH_COMP_FN_TYPE = extern (C) nothrow @nogc int function(const (void)*, const (void)*);
alias LHASH_HASH_FN_TYPE = extern (C) nothrow @nogc core.stdc.config.c_ulong function(const (void)*);
alias LHASH_DOALL_FN_TYPE = extern (C) nothrow @nogc void function(void*);
alias LHASH_DOALL_ARG_FN_TYPE = extern (C) nothrow @nogc void function(void*, void*);

/*
 * Macros for declaring and implementing type-safe wrappers for LHASH callbacks.
 * This way, callbacks can be provided to LHASH structures without function
 * pointer casting and the macro-defined callbacks provide per-variable casting
 * before deferring to the underlying type-specific callbacks. NB: It is
 * possible to place a "static" in front of both the DECLARE and IMPLEMENT
 * macros if the functions are strictly internal.
 */

/* First: "hash" functions */
//#define DECLARE_LHASH_HASH_FN(name, o_type) core.stdc.config.c_ulong name##_LHASH_HASH(const (void)*);
//#define IMPLEMENT_LHASH_HASH_FN(name, o_type) core.stdc.config.c_ulong name##_LHASH_HASH(const (void)* arg) { const (o_type)* a = arg; return name##_hash(a); }
//#define LHASH_HASH_FN(name) name##_LHASH_HASH

/* Second: "compare" functions */
//#define DECLARE_LHASH_COMP_FN(name, o_type) int name##_LHASH_COMP(const (void)*, const (void)*);
//#define IMPLEMENT_LHASH_COMP_FN(name, o_type) int name##_LHASH_COMP(const (void)* arg1, const (void)* arg2) { const (o_type)* a = arg1; const (o_type)* b = arg2; return name##_cmp(a, b); }
//#define LHASH_COMP_FN(name) name##_LHASH_COMP

/* Third: "doall" functions */
//#define DECLARE_LHASH_DOALL_FN(name, o_type) void name##_LHASH_DOALL(void*);
//#define IMPLEMENT_LHASH_DOALL_FN(name, o_type) void name##_LHASH_DOALL(void* arg) { o_type* a = arg; name##_doall(a); }
//#define LHASH_DOALL_FN(name) name##_LHASH_DOALL

/* Fourth: "doall_arg" functions */
//#define DECLARE_LHASH_DOALL_ARG_FN(name, o_type, a_type) void name##_LHASH_DOALL_ARG(void*, void*);
//#define IMPLEMENT_LHASH_DOALL_ARG_FN(name, o_type, a_type) void name##_LHASH_DOALL_ARG(void* arg1, void* arg2) { o_type* a = arg1; a_type* b = arg2; name##_doall_arg(a, b); }
//#define LHASH_DOALL_ARG_FN(name) name##_LHASH_DOALL_ARG

struct lhash_st
{
	.LHASH_NODE** b;
	.LHASH_COMP_FN_TYPE comp;
	.LHASH_HASH_FN_TYPE hash;
	uint num_nodes;
	uint num_alloc_nodes;
	uint p;
	uint pmax;

	/**
	 * load times 256
	 */
	core.stdc.config.c_ulong up_load;

	///Ditto
	core.stdc.config.c_ulong down_load;

	core.stdc.config.c_ulong num_items;

	core.stdc.config.c_ulong num_expands;
	core.stdc.config.c_ulong num_expand_reallocs;
	core.stdc.config.c_ulong num_contracts;
	core.stdc.config.c_ulong num_contract_reallocs;
	core.stdc.config.c_ulong num_hash_calls;
	core.stdc.config.c_ulong num_comp_calls;
	core.stdc.config.c_ulong num_insert;
	core.stdc.config.c_ulong num_replace;
	core.stdc.config.c_ulong num_delete;
	core.stdc.config.c_ulong num_no_delete;
	core.stdc.config.c_ulong num_retrieve;
	core.stdc.config.c_ulong num_retrieve_miss;
	core.stdc.config.c_ulong num_hash_comps;

	int error;
}

/**
 * Do not use _LHASH directly, use LHASH_OF
 * and friends
 */
alias _LHASH = .lhash_st;

enum LH_LOAD_MULT = 256;

/*
 * Indicates a malloc() error in the last call, this is only bad
 * in lh_insert().
 */
pragma(inline, true)
pure nothrow @trusted @nogc @live
int lh_error(scope const ._LHASH* lh)

	in
	{
		assert(lh != null);
	}

	do
	{
		return lh.error;
	}

._LHASH* lh_new(.LHASH_HASH_FN_TYPE h, .LHASH_COMP_FN_TYPE c);
void lh_free(._LHASH* lh);
void* lh_insert(._LHASH* lh, void* data);
void* lh_delete(._LHASH* lh, const (void)* data);
void* lh_retrieve(._LHASH* lh, const (void)* data);
void lh_doall(._LHASH* lh, .LHASH_DOALL_FN_TYPE func);
void lh_doall_arg(._LHASH* lh, .LHASH_DOALL_ARG_FN_TYPE func, void* arg);
core.stdc.config.c_ulong lh_strhash(const (char)* c);
core.stdc.config.c_ulong lh_num_items(const (._LHASH)* lh);

void lh_stats(const (._LHASH)* lh, libressl_d.compat.stdio.FILE* out_);
void lh_node_stats(const (._LHASH)* lh, libressl_d.compat.stdio.FILE* out_);
void lh_node_usage_stats(const (._LHASH)* lh, libressl_d.compat.stdio.FILE* out_);

version (OPENSSL_NO_BIO) {
} else {
	void lh_stats_bio(const (._LHASH)* lh, libressl_d.openssl.ossl_typ.BIO* out_);
	void lh_node_stats_bio(const (._LHASH)* lh, libressl_d.openssl.ossl_typ.BIO* out_);
	void lh_node_usage_stats_bio(const (._LHASH)* lh, libressl_d.openssl.ossl_typ.BIO* out_);
}

/* Type checking... */

//#define LHASH_OF(type) struct lhash_st_##type

//#define DECLARE_LHASH_OF(type) LHASH_OF(type) { int dummy; }

//#define CHECKED_LHASH_OF(type, lh) ((._LHASH*) libressl_d.openssl.asn1.CHECKED_PTR_OF(LHASH_OF(type), lh))

/* Define wrapper functions. */
//#define LHM_lh_new(type, name) ((LHASH_OF(type)*) .lh_new(.LHASH_HASH_FN(name), .LHASH_COMP_FN(name)))
//#define LHM_lh_error(type, lh) .lh_error(CHECKED_LHASH_OF(type, lh))
//#define LHM_lh_insert(type, lh, inst) ((type*) .lh_insert(CHECKED_LHASH_OF(type, lh), libressl_d.openssl.asn1.CHECKED_PTR_OF(type, inst)))
//#define LHM_lh_retrieve(type, lh, inst) ((type*) .lh_retrieve(CHECKED_LHASH_OF(type, lh), libressl_d.openssl.asn1.CHECKED_PTR_OF(type, inst)))
//#define LHM_lh_delete(type, lh, inst) ((type*) .lh_delete(CHECKED_LHASH_OF(type, lh), libressl_d.openssl.asn1.CHECKED_PTR_OF(type, inst)))
//#define LHM_lh_doall(type, lh, fn) .lh_doall(CHECKED_LHASH_OF(type, lh), fn)
//#define LHM_lh_doall_arg(type, lh, fn, arg_type, arg) .lh_doall_arg(CHECKED_LHASH_OF(type, lh), fn, libressl_d.openssl.asn1.CHECKED_PTR_OF(arg_type, arg))
//#define LHM_lh_num_items(type, lh) .lh_num_items(CHECKED_LHASH_OF(type, lh))
//#define LHM_lh_down_load(type, lh) (CHECKED_LHASH_OF(type, lh).down_load)
//#define LHM_lh_node_stats_bio(type, lh, out_) .lh_node_stats_bio(CHECKED_LHASH_OF(type, lh), out_)
//#define LHM_lh_node_usage_stats_bio(type, lh, out_) .lh_node_usage_stats_bio(CHECKED_LHASH_OF(type, lh), out_)
//#define LHM_lh_stats_bio(type, lh, out_) .lh_stats_bio(CHECKED_LHASH_OF(type, lh), out_)
//#define LHM_lh_free(type, lh) lh_free(CHECKED_LHASH_OF(type, lh))

//DECLARE_LHASH_OF(OPENSSL_STRING)
struct lhash_st_OPENSSL_STRING
{
	int dummy;
}

//DECLARE_LHASH_OF(OPENSSL_CSTRING)
struct lhash_st_OPENSSL_CSTRING
{
	int dummy;
}
