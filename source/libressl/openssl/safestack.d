/* $OpenBSD: safestack.h,v 1.22 2022/07/16 19:11:51 kn Exp $ */
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
module libressl.openssl.safestack;


private static import libressl.openssl.lhash;
private static import libressl.openssl.txt_db;
private import libressl.openssl.asn1;
private import libressl.openssl.asn1t;
private import libressl.openssl.bio;
private import libressl.openssl.cms;
private import libressl.openssl.conf;
private import libressl.openssl.crypto;
private import libressl.openssl.ct;
private import libressl.openssl.err;
private import libressl.openssl.objects;
private import libressl.openssl.ocsp;
private import libressl.openssl.ossl_typ;
private import libressl.openssl.pkcs12;
private import libressl.openssl.pkcs7;
private import libressl.openssl.ssl;
private import libressl.openssl.ts;
private import libressl.openssl.ui;
private import libressl.openssl.x509;
private import libressl.openssl.x509v3;
public import libressl.openssl.stack;

extern (C):
nothrow @nogc:

version (all) {
	alias CHECKED_PTR_OF = libressl.openssl.asn1.CHECKED_PTR_OF;
}

/*
 * In C++ we get problems because an explicit cast is needed from (void *)
 * we use CHECKED_STACK_OF to ensure the correct type is passed in the macros
 * below.
 */

pragma(inline, true)
pure nothrow @trusted @nogc @live
libressl.openssl.stack._STACK* CHECKED_STACK_OF(string type, P)(return scope P* p)

	do
	{
		return cast(libressl.openssl.stack._STACK*)((true) ? (p) : (cast(mixin (libressl.openssl.safestack.STACK_OF!(type) ~ "*"))(0)));
	}

private alias CHECKED_SK_FREE_FUNC_temp = /* Temporary type */ extern (C) nothrow @nogc void function(void*);
private alias CHECKED_SK_CMP_FUNC_temp = /* Temporary type */ extern (C) nothrow @nogc int function(const (void)*, const (void)*);

version (none) {
	pragma(inline, true)
	pure nothrow @trusted @nogc @live
	auto CHECKED_SK_FREE_FUNC(TYPE, P)(return scope P* p)

		do
		{
			return cast(.CHECKED_SK_FREE_FUNC_temp)(((true) ? (p) : (cast(void function(TYPE*))(0))));
		}

	pragma(inline, true)
	pure nothrow @trusted @nogc @live
	auto CHECKED_SK_FREE_FUNC2(TYPE, P)(return scope P* p)

		do
		{
			return cast(.CHECKED_SK_FREE_FUNC_temp)(((true) ? (p) : (cast(void function(TYPE))(0))));
		}

	pragma(inline, true)
	pure nothrow @trusted @nogc @live
	auto CHECKED_SK_CMP_FUNC(string type, P)(return scope P* p)

		do
		{
			return cast(.CHECKED_SK_CMP_FUNC_temp)(((true) ? (p) : (cast(int function(mixin ("const " ~ type ~ "**"), mixin ("const " ~ type ~ "**")))(0))));
		}
} else {
	pragma(inline, true)
	pure nothrow @trusted @nogc @live
	auto CHECKED_SK_FREE_FUNC(TYPE, P)(return scope P* p)

		do
		{
			return cast(.CHECKED_SK_FREE_FUNC_temp)(p);
		}

	pragma(inline, true)
	pure nothrow @trusted @nogc @live
	auto CHECKED_SK_FREE_FUNC2(TYPE, P)(return scope P* p)

		do
		{
			return cast(.CHECKED_SK_FREE_FUNC_temp)(p);
		}

	pragma(inline, true)
	pure nothrow @trusted @nogc @live
	auto CHECKED_SK_CMP_FUNC(string type, P)(return scope P* p)

		do
		{
			return cast(.CHECKED_SK_CMP_FUNC_temp)(p);
		}
}

template STACK_OF(string type)
{
	enum STACK_OF = "stack_st_" ~ type;
}

template PREDECLARE_STACK_OF(string type)
{
	enum PREDECLARE_STACK_OF = libressl.openssl.safestack.STACK_OF!(type);
}

template DECLARE_STACK_OF(string type)
{
	enum DECLARE_STACK_OF = "struct " ~ libressl.openssl.safestack.STACK_OF!(type) ~ " { libressl.openssl.stack._STACK stack; }";
}

template DECLARE_SPECIAL_STACK_OF(string type, string type2)
{
	enum DECLARE_SPECIAL_STACK_OF = "struct " ~ libressl.openssl.safestack.STACK_OF!(type) ~ " { libressl.openssl.stack._STACK stack; }";
}

/**
 * nada (obsolete in new safestack approach)
 */
pragma(inline, true)
pure nothrow @safe @nogc @live
void IMPLEMENT_STACK_OF(TYPE)(scope const TYPE type)

	do
	{
	}

/*
 * Strings are special: normally an lhash entry will point to a single
 * (somewhat) mutable object. In the case of strings:
 *
 * a) Instead of a single char, there is an array of chars, NUL-terminated.
 * b) The string may have be immutable.
 *
 * So, they need their own declarations. Especially important for
 * type-checking tools, such as Deputy.
 *
o * In practice, however, it appears to be hard to have a const
 * string. For now, I'm settling for dealing with the fact it is a
 * string at all.
 */
alias OPENSSL_STRING = char*;

alias OPENSSL_CSTRING = const (char)*;

/*
 * Confusingly, LHASH_OF(STRING) deals with char ** throughout, but
 * STACK_OF(STRING) is really more like STACK_OF(char), only, as
 * mentioned above, instead of a single char each entry is a
 * NUL-terminated array of chars. So, we have to implement STRING
 * specially for STACK_OF. This is dealt with in the autogenerated
 * macros below.
 */

//DECLARE_SPECIAL_STACK_OF(OPENSSL_STRING, char)
struct stack_st_OPENSSL_STRING
{
	libressl.openssl.stack._STACK stack;
}

/*
 * Similarly, we sometimes use a block of characters, NOT
 * nul-terminated. These should also be distinguished from "normal"
 * stacks.
 */

alias OPENSSL_BLOCK = void*;

//DECLARE_SPECIAL_STACK_OF(OPENSSL_BLOCK, void)
struct stack_st_OPENSSL_BLOCK
{
	libressl.openssl.stack._STACK stack;
}

/*
 * SKM_sk_... stack macros are internal to safestack.h:
 * never use them directly, use sk_<type>_... instead
 */
pragma(inline, true)
auto SKM_sk_new(string type, CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return cast(mixin (.STACK_OF!(type) ~ "*"))(libressl.openssl.stack.sk_new(.CHECKED_SK_CMP_FUNC!(type)(cmp)));
	}

pragma(inline, true)
auto SKM_sk_new_null(string type)()

	do
	{
		return cast(mixin (.STACK_OF!(type) ~ "*"))(libressl.openssl.stack.sk_new_null());
	}

pragma(inline, true)
void SKM_sk_free(string type, ST_TYPE)(ST_TYPE st)

	do
	{
		libressl.openssl.stack.sk_free(.CHECKED_STACK_OF!(type)(st));
	}

pragma(inline, true)
int SKM_sk_num(string type, ST_TYPE)(ST_TYPE st)

	do
	{
		return libressl.openssl.stack.sk_num(.CHECKED_STACK_OF!(type)(st));
	}

pragma(inline, true)
auto SKM_sk_value(string type, ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return cast(mixin (type ~ "*"))(libressl.openssl.stack.sk_value(.CHECKED_STACK_OF!(type)(st), i));
	}

pragma(inline, true)
void* SKM_sk_set(string type, ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_set(.CHECKED_STACK_OF!(type)(st), i, libressl.openssl.asn1.CHECKED_PTR_OF!(type)(val));
	}

pragma(inline, true)
void SKM_sk_zero(string type, ST_TYPE)(ST_TYPE st)

	do
	{
		libressl.openssl.stack.sk_zero(.CHECKED_STACK_OF!(type)(st));
	}

pragma(inline, true)
int SKM_sk_push(string type, ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_push(.CHECKED_STACK_OF!(type)(st), libressl.openssl.asn1.CHECKED_PTR_OF!(type)(val));
	}

pragma(inline, true)
int SKM_sk_unshift(string type, ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_unshift(.CHECKED_STACK_OF!(type)(st), libressl.openssl.asn1.CHECKED_PTR_OF!(type)(val));
	}

pragma(inline, true)
int SKM_sk_find(string type, ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_find(.CHECKED_STACK_OF!(type)(st), libressl.openssl.asn1.CHECKED_PTR_OF!(type)(val));
	}

pragma(inline, true)
int SKM_sk_find_ex(string type, ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_find_ex(.CHECKED_STACK_OF!(type)(st), libressl.openssl.asn1.CHECKED_PTR_OF!(type)(val));
	}

pragma(inline, true)
auto SKM_sk_delete(string type, ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return cast(mixin (type ~ "*"))(libressl.openssl.stack.sk_delete(.CHECKED_STACK_OF!(type)(st), i));
	}

pragma(inline, true)
auto SKM_sk_delete_ptr(string type, ST_TYPE, PTR_)(ST_TYPE st, PTR_ ptr_)

	do
	{
		return cast(mixin (type ~ "*"))(libressl.openssl.stack.sk_delete_ptr(.CHECKED_STACK_OF!(type)(st), libressl.openssl.asn1.CHECKED_PTR_OF!(type)(ptr_)));
	}

pragma(inline, true)
int SKM_sk_insert(string type, ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return libressl.openssl.stack.sk_insert(.CHECKED_STACK_OF!(type)(st), libressl.openssl.asn1.CHECKED_PTR_OF!(type)(val), i);
	}

pragma(inline, true)
auto SKM_sk_set_cmp_func(string type, ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		alias SKM_sk_set_cmp_func_temp = /* Temporary type */ extern (C) nothrow @nogc int function(mixin ("const " ~ type ~ "**"), mixin ("const " ~ type ~ "**"));

		return cast(SKM_sk_set_cmp_func_temp)(libressl.openssl.stack.sk_set_cmp_func(.CHECKED_STACK_OF!(type)(st), .CHECKED_SK_CMP_FUNC!(type)(cmp)));
	}

pragma(inline, true)
auto SKM_sk_dup(string type, ST_TYPE)(ST_TYPE st)

	do
	{
		return cast(mixin (.STACK_OF!(type) ~ "*"))(libressl.openssl.stack.sk_dup(.CHECKED_STACK_OF!(type)(st)));
	}

pragma(inline, true)
void SKM_sk_pop_free(string type, ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		libressl.openssl.stack.sk_pop_free(.CHECKED_STACK_OF!(type)(st), .CHECKED_SK_FREE_FUNC!(type)(free_func));
	}

pragma(inline, true)
auto SKM_sk_shift(string type, ST_TYPE)(ST_TYPE st)

	do
	{
		return cast(mixin (type ~ "*"))(libressl.openssl.stack.sk_shift(.CHECKED_STACK_OF!(type)(st)));
	}

pragma(inline, true)
auto SKM_sk_pop(string type, ST_TYPE)(ST_TYPE st)

	do
	{
		return cast(mixin (type ~ "*"))(libressl.openssl.stack.sk_pop(.CHECKED_STACK_OF!(type)(st)));
	}

pragma(inline, true)
void SKM_sk_sort(string type, ST_TYPE)(ST_TYPE st)

	do
	{
		libressl.openssl.stack.sk_sort(.CHECKED_STACK_OF!(type)(st));
	}

pragma(inline, true)
int SKM_sk_is_sorted(string type, ST_TYPE)(ST_TYPE st)

	do
	{
		return libressl.openssl.stack.sk_is_sorted(.CHECKED_STACK_OF!(type)(st));
	}

pragma(inline, true)
auto sk_ACCESS_DESCRIPTION_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("ACCESS_DESCRIPTION")(cmp);
	}

pragma(inline, true)
auto sk_ACCESS_DESCRIPTION_new_null()

	do
	{
		return .SKM_sk_new_null!("ACCESS_DESCRIPTION")();
	}

pragma(inline, true)
void sk_ACCESS_DESCRIPTION_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("ACCESS_DESCRIPTION")(st);
	}

pragma(inline, true)
int sk_ACCESS_DESCRIPTION_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("ACCESS_DESCRIPTION")(st);
	}

pragma(inline, true)
auto sk_ACCESS_DESCRIPTION_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("ACCESS_DESCRIPTION")(st, i);
	}

pragma(inline, true)
void* sk_ACCESS_DESCRIPTION_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("ACCESS_DESCRIPTION")(st, i, val);
	}

pragma(inline, true)
void sk_ACCESS_DESCRIPTION_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("ACCESS_DESCRIPTION")(st);
	}

pragma(inline, true)
int sk_ACCESS_DESCRIPTION_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("ACCESS_DESCRIPTION")(st, val);
	}

pragma(inline, true)
int sk_ACCESS_DESCRIPTION_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("ACCESS_DESCRIPTION")(st, val);
	}

pragma(inline, true)
int sk_ACCESS_DESCRIPTION_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("ACCESS_DESCRIPTION")(st, val);
	}

pragma(inline, true)
int sk_ACCESS_DESCRIPTION_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("ACCESS_DESCRIPTION")(st, val);
	}

pragma(inline, true)
auto sk_ACCESS_DESCRIPTION_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("ACCESS_DESCRIPTION")(st, i);
	}

pragma(inline, true)
auto sk_ACCESS_DESCRIPTION_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("ACCESS_DESCRIPTION")(st, ptr_);
	}

pragma(inline, true)
int sk_ACCESS_DESCRIPTION_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("ACCESS_DESCRIPTION")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_ACCESS_DESCRIPTION_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("ACCESS_DESCRIPTION")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_ACCESS_DESCRIPTION_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("ACCESS_DESCRIPTION")(st);
	}

pragma(inline, true)
void sk_ACCESS_DESCRIPTION_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("ACCESS_DESCRIPTION")(st, free_func);
	}

pragma(inline, true)
auto sk_ACCESS_DESCRIPTION_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("ACCESS_DESCRIPTION")(st);
	}

pragma(inline, true)
auto sk_ACCESS_DESCRIPTION_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("ACCESS_DESCRIPTION")(st);
	}

pragma(inline, true)
void sk_ACCESS_DESCRIPTION_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("ACCESS_DESCRIPTION")(st);
	}

pragma(inline, true)
int sk_ACCESS_DESCRIPTION_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("ACCESS_DESCRIPTION")(st);
	}

version (OPENSSL_NO_RFC3779) {
} else {
	pragma(inline, true)
	auto sk_ASIdOrRange_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("ASIdOrRange")(cmp);
		}

	pragma(inline, true)
	auto sk_ASIdOrRange_new_null()

		do
		{
			return .SKM_sk_new_null!("ASIdOrRange")();
		}

	pragma(inline, true)
	void sk_ASIdOrRange_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("ASIdOrRange")(st);
		}

	pragma(inline, true)
	int sk_ASIdOrRange_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("ASIdOrRange")(st);
		}

	pragma(inline, true)
	auto sk_ASIdOrRange_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("ASIdOrRange")(st, i);
		}

	pragma(inline, true)
	void* sk_ASIdOrRange_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("ASIdOrRange")(st, i, val);
		}

	pragma(inline, true)
	void sk_ASIdOrRange_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("ASIdOrRange")(st);
		}

	pragma(inline, true)
	int sk_ASIdOrRange_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("ASIdOrRange")(st, val);
		}

	pragma(inline, true)
	int sk_ASIdOrRange_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("ASIdOrRange")(st, val);
		}

	pragma(inline, true)
	int sk_ASIdOrRange_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("ASIdOrRange")(st, val);
		}

	pragma(inline, true)
	int sk_ASIdOrRange_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("ASIdOrRange")(st, val);
		}

	pragma(inline, true)
	auto sk_ASIdOrRange_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("ASIdOrRange")(st, i);
		}

	pragma(inline, true)
	auto sk_ASIdOrRange_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("ASIdOrRange")(st, ptr_);
		}

	pragma(inline, true)
	int sk_ASIdOrRange_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("ASIdOrRange")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_ASIdOrRange_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("ASIdOrRange")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_ASIdOrRange_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("ASIdOrRange")(st);
		}

	pragma(inline, true)
	void sk_ASIdOrRange_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("ASIdOrRange")(st, free_func);
		}

	pragma(inline, true)
	auto sk_ASIdOrRange_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("ASIdOrRange")(st);
		}

	pragma(inline, true)
	auto sk_ASIdOrRange_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("ASIdOrRange")(st);
		}

	pragma(inline, true)
	void sk_ASIdOrRange_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("ASIdOrRange")(st);
		}

	pragma(inline, true)
	int sk_ASIdOrRange_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("ASIdOrRange")(st);
		}
}

pragma(inline, true)
auto sk_ASN1_GENERALSTRING_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("ASN1_GENERALSTRING")(cmp);
	}

pragma(inline, true)
auto sk_ASN1_GENERALSTRING_new_null()

	do
	{
		return .SKM_sk_new_null!("ASN1_GENERALSTRING")();
	}

pragma(inline, true)
void sk_ASN1_GENERALSTRING_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("ASN1_GENERALSTRING")(st);
	}

pragma(inline, true)
int sk_ASN1_GENERALSTRING_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("ASN1_GENERALSTRING")(st);
	}

pragma(inline, true)
auto sk_ASN1_GENERALSTRING_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("ASN1_GENERALSTRING")(st, i);
	}

pragma(inline, true)
void* sk_ASN1_GENERALSTRING_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("ASN1_GENERALSTRING")(st, i, val);
	}

pragma(inline, true)
void sk_ASN1_GENERALSTRING_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("ASN1_GENERALSTRING")(st);
	}

pragma(inline, true)
int sk_ASN1_GENERALSTRING_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("ASN1_GENERALSTRING")(st, val);
	}

pragma(inline, true)
int sk_ASN1_GENERALSTRING_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("ASN1_GENERALSTRING")(st, val);
	}

pragma(inline, true)
int sk_ASN1_GENERALSTRING_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("ASN1_GENERALSTRING")(st, val);
	}

pragma(inline, true)
int sk_ASN1_GENERALSTRING_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("ASN1_GENERALSTRING")(st, val);
	}

pragma(inline, true)
auto sk_ASN1_GENERALSTRING_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("ASN1_GENERALSTRING")(st, i);
	}

pragma(inline, true)
auto sk_ASN1_GENERALSTRING_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("ASN1_GENERALSTRING")(st, ptr_);
	}

pragma(inline, true)
int sk_ASN1_GENERALSTRING_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("ASN1_GENERALSTRING")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_ASN1_GENERALSTRING_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("ASN1_GENERALSTRING")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_ASN1_GENERALSTRING_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("ASN1_GENERALSTRING")(st);
	}

pragma(inline, true)
void sk_ASN1_GENERALSTRING_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("ASN1_GENERALSTRING")(st, free_func);
	}

pragma(inline, true)
auto sk_ASN1_GENERALSTRING_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("ASN1_GENERALSTRING")(st);
	}

pragma(inline, true)
auto sk_ASN1_GENERALSTRING_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("ASN1_GENERALSTRING")(st);
	}

pragma(inline, true)
void sk_ASN1_GENERALSTRING_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("ASN1_GENERALSTRING")(st);
	}

pragma(inline, true)
int sk_ASN1_GENERALSTRING_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("ASN1_GENERALSTRING")(st);
	}

pragma(inline, true)
auto sk_ASN1_INTEGER_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("ASN1_INTEGER")(cmp);
	}

pragma(inline, true)
auto sk_ASN1_INTEGER_new_null()

	do
	{
		return .SKM_sk_new_null!("ASN1_INTEGER")();
	}

pragma(inline, true)
void sk_ASN1_INTEGER_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("ASN1_INTEGER")(st);
	}

pragma(inline, true)
int sk_ASN1_INTEGER_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("ASN1_INTEGER")(st);
	}

pragma(inline, true)
auto sk_ASN1_INTEGER_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("ASN1_INTEGER")(st, i);
	}

pragma(inline, true)
void* sk_ASN1_INTEGER_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("ASN1_INTEGER")(st, i, val);
	}

pragma(inline, true)
void sk_ASN1_INTEGER_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("ASN1_INTEGER")(st);
	}

pragma(inline, true)
int sk_ASN1_INTEGER_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("ASN1_INTEGER")(st, val);
	}

pragma(inline, true)
int sk_ASN1_INTEGER_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("ASN1_INTEGER")(st, val);
	}

pragma(inline, true)
int sk_ASN1_INTEGER_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("ASN1_INTEGER")(st, val);
	}

pragma(inline, true)
int sk_ASN1_INTEGER_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("ASN1_INTEGER")(st, val);
	}

pragma(inline, true)
auto sk_ASN1_INTEGER_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("ASN1_INTEGER")(st, i);
	}

pragma(inline, true)
auto sk_ASN1_INTEGER_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("ASN1_INTEGER")(st, ptr_);
	}

pragma(inline, true)
int sk_ASN1_INTEGER_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("ASN1_INTEGER")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_ASN1_INTEGER_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("ASN1_INTEGER")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_ASN1_INTEGER_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("ASN1_INTEGER")(st);
	}

pragma(inline, true)
void sk_ASN1_INTEGER_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("ASN1_INTEGER")(st, free_func);
	}

pragma(inline, true)
auto sk_ASN1_INTEGER_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("ASN1_INTEGER")(st);
	}

pragma(inline, true)
auto sk_ASN1_INTEGER_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("ASN1_INTEGER")(st);
	}

pragma(inline, true)
void sk_ASN1_INTEGER_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("ASN1_INTEGER")(st);
	}

pragma(inline, true)
int sk_ASN1_INTEGER_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("ASN1_INTEGER")(st);
	}

pragma(inline, true)
auto sk_ASN1_OBJECT_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("ASN1_OBJECT")(cmp);
	}

pragma(inline, true)
auto sk_ASN1_OBJECT_new_null()

	do
	{
		return .SKM_sk_new_null!("ASN1_OBJECT")();
	}

pragma(inline, true)
void sk_ASN1_OBJECT_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("ASN1_OBJECT")(st);
	}

pragma(inline, true)
int sk_ASN1_OBJECT_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("ASN1_OBJECT")(st);
	}

pragma(inline, true)
auto sk_ASN1_OBJECT_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("ASN1_OBJECT")(st, i);
	}

pragma(inline, true)
void* sk_ASN1_OBJECT_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("ASN1_OBJECT")(st, i, val);
	}

pragma(inline, true)
void sk_ASN1_OBJECT_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("ASN1_OBJECT")(st);
	}

pragma(inline, true)
int sk_ASN1_OBJECT_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("ASN1_OBJECT")(st, val);
	}

pragma(inline, true)
int sk_ASN1_OBJECT_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("ASN1_OBJECT")(st, val);
	}

pragma(inline, true)
int sk_ASN1_OBJECT_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("ASN1_OBJECT")(st, val);
	}

pragma(inline, true)
int sk_ASN1_OBJECT_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("ASN1_OBJECT")(st, val);
	}

pragma(inline, true)
auto sk_ASN1_OBJECT_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("ASN1_OBJECT")(st, i);
	}

pragma(inline, true)
auto sk_ASN1_OBJECT_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("ASN1_OBJECT")(st, ptr_);
	}

pragma(inline, true)
int sk_ASN1_OBJECT_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("ASN1_OBJECT")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_ASN1_OBJECT_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("ASN1_OBJECT")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_ASN1_OBJECT_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("ASN1_OBJECT")(st);
	}

pragma(inline, true)
void sk_ASN1_OBJECT_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("ASN1_OBJECT")(st, free_func);
	}

pragma(inline, true)
auto sk_ASN1_OBJECT_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("ASN1_OBJECT")(st);
	}

pragma(inline, true)
auto sk_ASN1_OBJECT_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("ASN1_OBJECT")(st);
	}

pragma(inline, true)
void sk_ASN1_OBJECT_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("ASN1_OBJECT")(st);
	}

pragma(inline, true)
int sk_ASN1_OBJECT_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("ASN1_OBJECT")(st);
	}

pragma(inline, true)
auto sk_ASN1_STRING_TABLE_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("ASN1_STRING_TABLE")(cmp);
	}

pragma(inline, true)
auto sk_ASN1_STRING_TABLE_new_null()

	do
	{
		return .SKM_sk_new_null!("ASN1_STRING_TABLE")();
	}

pragma(inline, true)
void sk_ASN1_STRING_TABLE_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("ASN1_STRING_TABLE")(st);
	}

pragma(inline, true)
int sk_ASN1_STRING_TABLE_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("ASN1_STRING_TABLE")(st);
	}

pragma(inline, true)
auto sk_ASN1_STRING_TABLE_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("ASN1_STRING_TABLE")(st, i);
	}

pragma(inline, true)
void* sk_ASN1_STRING_TABLE_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("ASN1_STRING_TABLE")(st, i, val);
	}

pragma(inline, true)
void sk_ASN1_STRING_TABLE_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("ASN1_STRING_TABLE")(st);
	}

pragma(inline, true)
int sk_ASN1_STRING_TABLE_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("ASN1_STRING_TABLE")(st, val);
	}

pragma(inline, true)
int sk_ASN1_STRING_TABLE_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("ASN1_STRING_TABLE")(st, val);
	}

pragma(inline, true)
int sk_ASN1_STRING_TABLE_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("ASN1_STRING_TABLE")(st, val);
	}

pragma(inline, true)
int sk_ASN1_STRING_TABLE_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("ASN1_STRING_TABLE")(st, val);
	}

pragma(inline, true)
auto sk_ASN1_STRING_TABLE_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("ASN1_STRING_TABLE")(st, i);
	}

pragma(inline, true)
auto sk_ASN1_STRING_TABLE_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("ASN1_STRING_TABLE")(st, ptr_);
	}

pragma(inline, true)
int sk_ASN1_STRING_TABLE_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("ASN1_STRING_TABLE")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_ASN1_STRING_TABLE_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("ASN1_STRING_TABLE")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_ASN1_STRING_TABLE_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("ASN1_STRING_TABLE")(st);
	}

pragma(inline, true)
void sk_ASN1_STRING_TABLE_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("ASN1_STRING_TABLE")(st, free_func);
	}

pragma(inline, true)
auto sk_ASN1_STRING_TABLE_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("ASN1_STRING_TABLE")(st);
	}

pragma(inline, true)
auto sk_ASN1_STRING_TABLE_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("ASN1_STRING_TABLE")(st);
	}

pragma(inline, true)
void sk_ASN1_STRING_TABLE_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("ASN1_STRING_TABLE")(st);
	}

pragma(inline, true)
int sk_ASN1_STRING_TABLE_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("ASN1_STRING_TABLE")(st);
	}

pragma(inline, true)
auto sk_ASN1_TYPE_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("ASN1_TYPE")(cmp);
	}

pragma(inline, true)
auto sk_ASN1_TYPE_new_null()

	do
	{
		return .SKM_sk_new_null!("ASN1_TYPE")();
	}

pragma(inline, true)
void sk_ASN1_TYPE_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("ASN1_TYPE")(st);
	}

pragma(inline, true)
int sk_ASN1_TYPE_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("ASN1_TYPE")(st);
	}

pragma(inline, true)
auto sk_ASN1_TYPE_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("ASN1_TYPE")(st, i);
	}

pragma(inline, true)
void* sk_ASN1_TYPE_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("ASN1_TYPE")(st, i, val);
	}

pragma(inline, true)
void sk_ASN1_TYPE_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("ASN1_TYPE")(st);
	}

pragma(inline, true)
int sk_ASN1_TYPE_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("ASN1_TYPE")(st, val);
	}

pragma(inline, true)
int sk_ASN1_TYPE_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("ASN1_TYPE")(st, val);
	}

pragma(inline, true)
int sk_ASN1_TYPE_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("ASN1_TYPE")(st, val);
	}

pragma(inline, true)
int sk_ASN1_TYPE_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("ASN1_TYPE")(st, val);
	}

pragma(inline, true)
auto sk_ASN1_TYPE_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("ASN1_TYPE")(st, i);
	}

pragma(inline, true)
auto sk_ASN1_TYPE_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("ASN1_TYPE")(st, ptr_);
	}

pragma(inline, true)
int sk_ASN1_TYPE_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("ASN1_TYPE")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_ASN1_TYPE_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("ASN1_TYPE")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_ASN1_TYPE_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("ASN1_TYPE")(st);
	}

pragma(inline, true)
void sk_ASN1_TYPE_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("ASN1_TYPE")(st, free_func);
	}

pragma(inline, true)
auto sk_ASN1_TYPE_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("ASN1_TYPE")(st);
	}

pragma(inline, true)
auto sk_ASN1_TYPE_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("ASN1_TYPE")(st);
	}

pragma(inline, true)
void sk_ASN1_TYPE_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("ASN1_TYPE")(st);
	}

pragma(inline, true)
int sk_ASN1_TYPE_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("ASN1_TYPE")(st);
	}

pragma(inline, true)
auto sk_ASN1_UTF8STRING_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("ASN1_UTF8STRING")(cmp);
	}

pragma(inline, true)
auto sk_ASN1_UTF8STRING_new_null()

	do
	{
		return .SKM_sk_new_null!("ASN1_UTF8STRING")();
	}

pragma(inline, true)
void sk_ASN1_UTF8STRING_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("ASN1_UTF8STRING")(st);
	}

pragma(inline, true)
int sk_ASN1_UTF8STRING_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("ASN1_UTF8STRING")(st);
	}

pragma(inline, true)
auto sk_ASN1_UTF8STRING_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("ASN1_UTF8STRING")(st, i);
	}

pragma(inline, true)
void* sk_ASN1_UTF8STRING_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("ASN1_UTF8STRING")(st, i, val);
	}

pragma(inline, true)
void sk_ASN1_UTF8STRING_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("ASN1_UTF8STRING")(st);
	}

pragma(inline, true)
int sk_ASN1_UTF8STRING_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("ASN1_UTF8STRING")(st, val);
	}

pragma(inline, true)
int sk_ASN1_UTF8STRING_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("ASN1_UTF8STRING")(st, val);
	}

pragma(inline, true)
int sk_ASN1_UTF8STRING_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("ASN1_UTF8STRING")(st, val);
	}

pragma(inline, true)
int sk_ASN1_UTF8STRING_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("ASN1_UTF8STRING")(st, val);
	}

pragma(inline, true)
auto sk_ASN1_UTF8STRING_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("ASN1_UTF8STRING")(st, i);
	}

pragma(inline, true)
auto sk_ASN1_UTF8STRING_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("ASN1_UTF8STRING")(st, ptr_);
	}

pragma(inline, true)
int sk_ASN1_UTF8STRING_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("ASN1_UTF8STRING")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_ASN1_UTF8STRING_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("ASN1_UTF8STRING")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_ASN1_UTF8STRING_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("ASN1_UTF8STRING")(st);
	}

pragma(inline, true)
void sk_ASN1_UTF8STRING_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("ASN1_UTF8STRING")(st, free_func);
	}

pragma(inline, true)
auto sk_ASN1_UTF8STRING_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("ASN1_UTF8STRING")(st);
	}

pragma(inline, true)
auto sk_ASN1_UTF8STRING_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("ASN1_UTF8STRING")(st);
	}

pragma(inline, true)
void sk_ASN1_UTF8STRING_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("ASN1_UTF8STRING")(st);
	}

pragma(inline, true)
int sk_ASN1_UTF8STRING_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("ASN1_UTF8STRING")(st);
	}

pragma(inline, true)
auto sk_ASN1_VALUE_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("ASN1_VALUE")(cmp);
	}

pragma(inline, true)
auto sk_ASN1_VALUE_new_null()

	do
	{
		return .SKM_sk_new_null!("ASN1_VALUE")();
	}

pragma(inline, true)
void sk_ASN1_VALUE_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("ASN1_VALUE")(st);
	}

pragma(inline, true)
int sk_ASN1_VALUE_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("ASN1_VALUE")(st);
	}

pragma(inline, true)
auto sk_ASN1_VALUE_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("ASN1_VALUE")(st, i);
	}

pragma(inline, true)
void* sk_ASN1_VALUE_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("ASN1_VALUE")(st, i, val);
	}

pragma(inline, true)
void sk_ASN1_VALUE_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("ASN1_VALUE")(st);
	}

pragma(inline, true)
int sk_ASN1_VALUE_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("ASN1_VALUE")(st, val);
	}

pragma(inline, true)
int sk_ASN1_VALUE_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("ASN1_VALUE")(st, val);
	}

pragma(inline, true)
int sk_ASN1_VALUE_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("ASN1_VALUE")(st, val);
	}

pragma(inline, true)
int sk_ASN1_VALUE_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("ASN1_VALUE")(st, val);
	}

pragma(inline, true)
auto sk_ASN1_VALUE_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("ASN1_VALUE")(st, i);
	}

pragma(inline, true)
auto sk_ASN1_VALUE_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("ASN1_VALUE")(st, ptr_);
	}

pragma(inline, true)
int sk_ASN1_VALUE_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("ASN1_VALUE")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_ASN1_VALUE_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("ASN1_VALUE")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_ASN1_VALUE_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("ASN1_VALUE")(st);
	}

pragma(inline, true)
void sk_ASN1_VALUE_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("ASN1_VALUE")(st, free_func);
	}

pragma(inline, true)
auto sk_ASN1_VALUE_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("ASN1_VALUE")(st);
	}

pragma(inline, true)
auto sk_ASN1_VALUE_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("ASN1_VALUE")(st);
	}

pragma(inline, true)
void sk_ASN1_VALUE_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("ASN1_VALUE")(st);
	}

pragma(inline, true)
int sk_ASN1_VALUE_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("ASN1_VALUE")(st);
	}

pragma(inline, true)
auto sk_BIO_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("BIO")(cmp);
	}

pragma(inline, true)
auto sk_BIO_new_null()

	do
	{
		return .SKM_sk_new_null!("BIO")();
	}

pragma(inline, true)
void sk_BIO_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("BIO")(st);
	}

pragma(inline, true)
int sk_BIO_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("BIO")(st);
	}

pragma(inline, true)
auto sk_BIO_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("BIO")(st, i);
	}

pragma(inline, true)
void* sk_BIO_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("BIO")(st, i, val);
	}

pragma(inline, true)
void sk_BIO_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("BIO")(st);
	}

pragma(inline, true)
int sk_BIO_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("BIO")(st, val);
	}

pragma(inline, true)
int sk_BIO_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("BIO")(st, val);
	}

pragma(inline, true)
int sk_BIO_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("BIO")(st, val);
	}

pragma(inline, true)
int sk_BIO_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("BIO")(st, val);
	}

pragma(inline, true)
auto sk_BIO_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("BIO")(st, i);
	}

pragma(inline, true)
auto sk_BIO_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("BIO")(st, ptr_);
	}

pragma(inline, true)
int sk_BIO_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("BIO")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_BIO_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("BIO")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_BIO_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("BIO")(st);
	}

pragma(inline, true)
void sk_BIO_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("BIO")(st, free_func);
	}

pragma(inline, true)
auto sk_BIO_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("BIO")(st);
	}

pragma(inline, true)
auto sk_BIO_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("BIO")(st);
	}

pragma(inline, true)
void sk_BIO_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("BIO")(st);
	}

pragma(inline, true)
int sk_BIO_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("BIO")(st);
	}

version (none) {
	pragma(inline, true)
	auto sk_BY_DIR_ENTRY_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("BY_DIR_ENTRY")(cmp);
		}

	pragma(inline, true)
	auto sk_BY_DIR_ENTRY_new_null()

		do
		{
			return .SKM_sk_new_null!("BY_DIR_ENTRY")();
		}

	pragma(inline, true)
	void sk_BY_DIR_ENTRY_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("BY_DIR_ENTRY")(st);
		}

	pragma(inline, true)
	int sk_BY_DIR_ENTRY_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("BY_DIR_ENTRY")(st);
		}

	pragma(inline, true)
	auto sk_BY_DIR_ENTRY_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("BY_DIR_ENTRY")(st, i);
		}

	pragma(inline, true)
	void* sk_BY_DIR_ENTRY_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("BY_DIR_ENTRY")(st, i, val);
		}

	pragma(inline, true)
	void sk_BY_DIR_ENTRY_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("BY_DIR_ENTRY")(st);
		}

	pragma(inline, true)
	int sk_BY_DIR_ENTRY_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("BY_DIR_ENTRY")(st, val);
		}

	pragma(inline, true)
	int sk_BY_DIR_ENTRY_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("BY_DIR_ENTRY")(st, val);
		}

	pragma(inline, true)
	int sk_BY_DIR_ENTRY_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("BY_DIR_ENTRY")(st, val);
		}

	pragma(inline, true)
	int sk_BY_DIR_ENTRY_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("BY_DIR_ENTRY")(st, val);
		}

	pragma(inline, true)
	auto sk_BY_DIR_ENTRY_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("BY_DIR_ENTRY")(st, i);
		}

	pragma(inline, true)
	auto sk_BY_DIR_ENTRY_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("BY_DIR_ENTRY")(st, ptr_);
		}

	pragma(inline, true)
	int sk_BY_DIR_ENTRY_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("BY_DIR_ENTRY")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_BY_DIR_ENTRY_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("BY_DIR_ENTRY")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_BY_DIR_ENTRY_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("BY_DIR_ENTRY")(st);
		}

	pragma(inline, true)
	void sk_BY_DIR_ENTRY_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("BY_DIR_ENTRY")(st, free_func);
		}

	pragma(inline, true)
	auto sk_BY_DIR_ENTRY_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("BY_DIR_ENTRY")(st);
		}

	pragma(inline, true)
	auto sk_BY_DIR_ENTRY_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("BY_DIR_ENTRY")(st);
		}

	pragma(inline, true)
	void sk_BY_DIR_ENTRY_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("BY_DIR_ENTRY")(st);
		}

	pragma(inline, true)
	int sk_BY_DIR_ENTRY_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("BY_DIR_ENTRY")(st);
		}
}

version (none) {
	pragma(inline, true)
	auto sk_BY_DIR_HASH_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("BY_DIR_HASH")(cmp);
		}

	pragma(inline, true)
	auto sk_BY_DIR_HASH_new_null()

		do
		{
			return .SKM_sk_new_null!("BY_DIR_HASH")();
		}

	pragma(inline, true)
	void sk_BY_DIR_HASH_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("BY_DIR_HASH")(st);
		}

	pragma(inline, true)
	int sk_BY_DIR_HASH_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("BY_DIR_HASH")(st);
		}

	pragma(inline, true)
	auto sk_BY_DIR_HASH_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("BY_DIR_HASH")(st, i);
		}

	pragma(inline, true)
	void* sk_BY_DIR_HASH_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("BY_DIR_HASH")(st, i, val);
		}

	pragma(inline, true)
	void sk_BY_DIR_HASH_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("BY_DIR_HASH")(st);
		}

	pragma(inline, true)
	int sk_BY_DIR_HASH_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("BY_DIR_HASH")(st, val);
		}

	pragma(inline, true)
	int sk_BY_DIR_HASH_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("BY_DIR_HASH")(st, val);
		}

	pragma(inline, true)
	int sk_BY_DIR_HASH_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("BY_DIR_HASH")(st, val);
		}

	pragma(inline, true)
	int sk_BY_DIR_HASH_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("BY_DIR_HASH")(st, val);
		}

	pragma(inline, true)
	auto sk_BY_DIR_HASH_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("BY_DIR_HASH")(st, i);
		}

	pragma(inline, true)
	auto sk_BY_DIR_HASH_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("BY_DIR_HASH")(st, ptr_);
		}

	pragma(inline, true)
	int sk_BY_DIR_HASH_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("BY_DIR_HASH")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_BY_DIR_HASH_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("BY_DIR_HASH")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_BY_DIR_HASH_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("BY_DIR_HASH")(st);
		}

	pragma(inline, true)
	void sk_BY_DIR_HASH_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("BY_DIR_HASH")(st, free_func);
		}

	pragma(inline, true)
	auto sk_BY_DIR_HASH_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("BY_DIR_HASH")(st);
		}

	pragma(inline, true)
	auto sk_BY_DIR_HASH_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("BY_DIR_HASH")(st);
		}

	pragma(inline, true)
	void sk_BY_DIR_HASH_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("BY_DIR_HASH")(st);
		}

	pragma(inline, true)
	int sk_BY_DIR_HASH_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("BY_DIR_HASH")(st);
		}
}

version (OPENSSL_NO_CMS) {
} else {
	version (none) {
		pragma(inline, true)
		auto sk_CMS_CertificateChoices_new(CMP_TYPE)(CMP_TYPE cmp)

			do
			{
				return .SKM_sk_new!("CMS_CertificateChoices")(cmp);
			}

		pragma(inline, true)
		auto sk_CMS_CertificateChoices_new_null()

			do
			{
				return .SKM_sk_new_null!("CMS_CertificateChoices")();
			}

		pragma(inline, true)
		void sk_CMS_CertificateChoices_free(ST_TYPE)(ST_TYPE st)

			do
			{
				.SKM_sk_free!("CMS_CertificateChoices")(st);
			}

		pragma(inline, true)
		int sk_CMS_CertificateChoices_num(ST_TYPE)(ST_TYPE st)

			do
			{
				return .SKM_sk_num!("CMS_CertificateChoices")(st);
			}

		pragma(inline, true)
		auto sk_CMS_CertificateChoices_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

			do
			{
				return .SKM_sk_value!("CMS_CertificateChoices")(st, i);
			}

		pragma(inline, true)
		void* sk_CMS_CertificateChoices_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

			do
			{
				return .SKM_sk_set!("CMS_CertificateChoices")(st, i, val);
			}

		pragma(inline, true)
		void sk_CMS_CertificateChoices_zero(ST_TYPE)(ST_TYPE st)

			do
			{
				.SKM_sk_zero!("CMS_CertificateChoices")(st);
			}

		pragma(inline, true)
		int sk_CMS_CertificateChoices_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

			do
			{
				return .SKM_sk_push!("CMS_CertificateChoices")(st, val);
			}

		pragma(inline, true)
		int sk_CMS_CertificateChoices_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

			do
			{
				return .SKM_sk_unshift!("CMS_CertificateChoices")(st, val);
			}

		pragma(inline, true)
		int sk_CMS_CertificateChoices_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

			do
			{
				return .SKM_sk_find!("CMS_CertificateChoices")(st, val);
			}

		pragma(inline, true)
		int sk_CMS_CertificateChoices_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

			do
			{
				return .SKM_sk_find_ex!("CMS_CertificateChoices")(st, val);
			}

		pragma(inline, true)
		auto sk_CMS_CertificateChoices_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

			do
			{
				return .SKM_sk_delete!("CMS_CertificateChoices")(st, i);
			}

		pragma(inline, true)
		auto sk_CMS_CertificateChoices_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

			do
			{
				return .SKM_sk_delete_ptr!("CMS_CertificateChoices")(st, ptr_);
			}

		pragma(inline, true)
		int sk_CMS_CertificateChoices_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

			do
			{
				return .SKM_sk_insert!("CMS_CertificateChoices")(st, val, i);
			}

		/+
		pragma(inline, true)
		auto sk_CMS_CertificateChoices_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

			do
			{
				return .SKM_sk_set_cmp_func!("CMS_CertificateChoices")(st, cmp);
			}
		+/

		pragma(inline, true)
		auto sk_CMS_CertificateChoices_dup(ST_TYPE)(ST_TYPE st)

			do
			{
				return .SKM_sk_dup!("CMS_CertificateChoices")(st);
			}

		pragma(inline, true)
		void sk_CMS_CertificateChoices_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

			do
			{
				.SKM_sk_pop_free!("CMS_CertificateChoices")(st, free_func);
			}

		pragma(inline, true)
		auto sk_CMS_CertificateChoices_shift(ST_TYPE)(ST_TYPE st)

			do
			{
				return .SKM_sk_shift!("CMS_CertificateChoices")(st);
			}

		pragma(inline, true)
		auto sk_CMS_CertificateChoices_pop(ST_TYPE)(ST_TYPE st)

			do
			{
				return .SKM_sk_pop!("CMS_CertificateChoices")(st);
			}

		pragma(inline, true)
		void sk_CMS_CertificateChoices_sort(ST_TYPE)(ST_TYPE st)

			do
			{
				.SKM_sk_sort!("CMS_CertificateChoices")(st);
			}

		pragma(inline, true)
		int sk_CMS_CertificateChoices_is_sorted(ST_TYPE)(ST_TYPE st)

			do
			{
				return .SKM_sk_is_sorted!("CMS_CertificateChoices")(st);
			}
	}

	pragma(inline, true)
	auto sk_CMS_RecipientEncryptedKey_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("CMS_RecipientEncryptedKey")(cmp);
		}

	pragma(inline, true)
	auto sk_CMS_RecipientEncryptedKey_new_null()

		do
		{
			return .SKM_sk_new_null!("CMS_RecipientEncryptedKey")();
		}

	pragma(inline, true)
	void sk_CMS_RecipientEncryptedKey_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("CMS_RecipientEncryptedKey")(st);
		}

	pragma(inline, true)
	int sk_CMS_RecipientEncryptedKey_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("CMS_RecipientEncryptedKey")(st);
		}

	pragma(inline, true)
	auto sk_CMS_RecipientEncryptedKey_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("CMS_RecipientEncryptedKey")(st, i);
		}

	pragma(inline, true)
	void* sk_CMS_RecipientEncryptedKey_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("CMS_RecipientEncryptedKey")(st, i, val);
		}

	pragma(inline, true)
	void sk_CMS_RecipientEncryptedKey_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("CMS_RecipientEncryptedKey")(st);
		}

	pragma(inline, true)
	int sk_CMS_RecipientEncryptedKey_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("CMS_RecipientEncryptedKey")(st, val);
		}

	pragma(inline, true)
	int sk_CMS_RecipientEncryptedKey_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("CMS_RecipientEncryptedKey")(st, val);
		}

	pragma(inline, true)
	int sk_CMS_RecipientEncryptedKey_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("CMS_RecipientEncryptedKey")(st, val);
		}

	pragma(inline, true)
	int sk_CMS_RecipientEncryptedKey_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("CMS_RecipientEncryptedKey")(st, val);
		}

	pragma(inline, true)
	auto sk_CMS_RecipientEncryptedKey_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("CMS_RecipientEncryptedKey")(st, i);
		}

	pragma(inline, true)
	auto sk_CMS_RecipientEncryptedKey_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("CMS_RecipientEncryptedKey")(st, ptr_);
		}

	pragma(inline, true)
	int sk_CMS_RecipientEncryptedKey_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("CMS_RecipientEncryptedKey")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_CMS_RecipientEncryptedKey_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("CMS_RecipientEncryptedKey")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_CMS_RecipientEncryptedKey_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("CMS_RecipientEncryptedKey")(st);
		}

	pragma(inline, true)
	void sk_CMS_RecipientEncryptedKey_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("CMS_RecipientEncryptedKey")(st, free_func);
		}

	pragma(inline, true)
	auto sk_CMS_RecipientEncryptedKey_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("CMS_RecipientEncryptedKey")(st);
		}

	pragma(inline, true)
	auto sk_CMS_RecipientEncryptedKey_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("CMS_RecipientEncryptedKey")(st);
		}

	pragma(inline, true)
	void sk_CMS_RecipientEncryptedKey_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("CMS_RecipientEncryptedKey")(st);
		}

	pragma(inline, true)
	int sk_CMS_RecipientEncryptedKey_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("CMS_RecipientEncryptedKey")(st);
		}

	pragma(inline, true)
	auto sk_CMS_RecipientInfo_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("CMS_RecipientInfo")(cmp);
		}

	pragma(inline, true)
	auto sk_CMS_RecipientInfo_new_null()

		do
		{
			return .SKM_sk_new_null!("CMS_RecipientInfo")();
		}

	pragma(inline, true)
	void sk_CMS_RecipientInfo_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("CMS_RecipientInfo")(st);
		}

	pragma(inline, true)
	int sk_CMS_RecipientInfo_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("CMS_RecipientInfo")(st);
		}

	pragma(inline, true)
	auto sk_CMS_RecipientInfo_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("CMS_RecipientInfo")(st, i);
		}

	pragma(inline, true)
	void* sk_CMS_RecipientInfo_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("CMS_RecipientInfo")(st, i, val);
		}

	pragma(inline, true)
	void sk_CMS_RecipientInfo_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("CMS_RecipientInfo")(st);
		}

	pragma(inline, true)
	int sk_CMS_RecipientInfo_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("CMS_RecipientInfo")(st, val);
		}

	pragma(inline, true)
	int sk_CMS_RecipientInfo_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("CMS_RecipientInfo")(st, val);
		}

	pragma(inline, true)
	int sk_CMS_RecipientInfo_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("CMS_RecipientInfo")(st, val);
		}

	pragma(inline, true)
	int sk_CMS_RecipientInfo_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("CMS_RecipientInfo")(st, val);
		}

	pragma(inline, true)
	auto sk_CMS_RecipientInfo_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("CMS_RecipientInfo")(st, i);
		}

	pragma(inline, true)
	auto sk_CMS_RecipientInfo_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("CMS_RecipientInfo")(st, ptr_);
		}

	pragma(inline, true)
	int sk_CMS_RecipientInfo_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("CMS_RecipientInfo")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_CMS_RecipientInfo_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("CMS_RecipientInfo")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_CMS_RecipientInfo_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("CMS_RecipientInfo")(st);
		}

	pragma(inline, true)
	void sk_CMS_RecipientInfo_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("CMS_RecipientInfo")(st, free_func);
		}

	pragma(inline, true)
	auto sk_CMS_RecipientInfo_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("CMS_RecipientInfo")(st);
		}

	pragma(inline, true)
	auto sk_CMS_RecipientInfo_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("CMS_RecipientInfo")(st);
		}

	pragma(inline, true)
	void sk_CMS_RecipientInfo_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("CMS_RecipientInfo")(st);
		}

	pragma(inline, true)
	int sk_CMS_RecipientInfo_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("CMS_RecipientInfo")(st);
		}

	pragma(inline, true)
	auto sk_CMS_RevocationInfoChoice_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("CMS_RevocationInfoChoice")(cmp);
		}

	pragma(inline, true)
	auto sk_CMS_RevocationInfoChoice_new_null()

		do
		{
			return .SKM_sk_new_null!("CMS_RevocationInfoChoice")();
		}

	pragma(inline, true)
	void sk_CMS_RevocationInfoChoice_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("CMS_RevocationInfoChoice")(st);
		}

	pragma(inline, true)
	int sk_CMS_RevocationInfoChoice_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("CMS_RevocationInfoChoice")(st);
		}

	pragma(inline, true)
	auto sk_CMS_RevocationInfoChoice_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("CMS_RevocationInfoChoice")(st, i);
		}

	pragma(inline, true)
	void* sk_CMS_RevocationInfoChoice_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("CMS_RevocationInfoChoice")(st, i, val);
		}

	pragma(inline, true)
	void sk_CMS_RevocationInfoChoice_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("CMS_RevocationInfoChoice")(st);
		}

	pragma(inline, true)
	int sk_CMS_RevocationInfoChoice_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("CMS_RevocationInfoChoice")(st, val);
		}

	pragma(inline, true)
	int sk_CMS_RevocationInfoChoice_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("CMS_RevocationInfoChoice")(st, val);
		}

	pragma(inline, true)
	int sk_CMS_RevocationInfoChoice_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("CMS_RevocationInfoChoice")(st, val);
		}

	pragma(inline, true)
	int sk_CMS_RevocationInfoChoice_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("CMS_RevocationInfoChoice")(st, val);
		}

	pragma(inline, true)
	auto sk_CMS_RevocationInfoChoice_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("CMS_RevocationInfoChoice")(st, i);
		}

	pragma(inline, true)
	auto sk_CMS_RevocationInfoChoice_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("CMS_RevocationInfoChoice")(st, ptr_);
		}

	pragma(inline, true)
	int sk_CMS_RevocationInfoChoice_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("CMS_RevocationInfoChoice")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_CMS_RevocationInfoChoice_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("CMS_RevocationInfoChoice")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_CMS_RevocationInfoChoice_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("CMS_RevocationInfoChoice")(st);
		}

	pragma(inline, true)
	void sk_CMS_RevocationInfoChoice_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("CMS_RevocationInfoChoice")(st, free_func);
		}

	pragma(inline, true)
	auto sk_CMS_RevocationInfoChoice_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("CMS_RevocationInfoChoice")(st);
		}

	pragma(inline, true)
	auto sk_CMS_RevocationInfoChoice_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("CMS_RevocationInfoChoice")(st);
		}

	pragma(inline, true)
	void sk_CMS_RevocationInfoChoice_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("CMS_RevocationInfoChoice")(st);
		}

	pragma(inline, true)
	int sk_CMS_RevocationInfoChoice_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("CMS_RevocationInfoChoice")(st);
		}

	pragma(inline, true)
	auto sk_CMS_SignerInfo_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("CMS_SignerInfo")(cmp);
		}

	pragma(inline, true)
	auto sk_CMS_SignerInfo_new_null()

		do
		{
			return .SKM_sk_new_null!("CMS_SignerInfo")();
		}

	pragma(inline, true)
	void sk_CMS_SignerInfo_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("CMS_SignerInfo")(st);
		}

	pragma(inline, true)
	int sk_CMS_SignerInfo_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("CMS_SignerInfo")(st);
		}

	pragma(inline, true)
	auto sk_CMS_SignerInfo_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("CMS_SignerInfo")(st, i);
		}

	pragma(inline, true)
	void* sk_CMS_SignerInfo_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("CMS_SignerInfo")(st, i, val);
		}

	pragma(inline, true)
	void sk_CMS_SignerInfo_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("CMS_SignerInfo")(st);
		}

	pragma(inline, true)
	int sk_CMS_SignerInfo_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("CMS_SignerInfo")(st, val);
		}

	pragma(inline, true)
	int sk_CMS_SignerInfo_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("CMS_SignerInfo")(st, val);
		}

	pragma(inline, true)
	int sk_CMS_SignerInfo_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("CMS_SignerInfo")(st, val);
		}

	pragma(inline, true)
	int sk_CMS_SignerInfo_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("CMS_SignerInfo")(st, val);
		}

	pragma(inline, true)
	auto sk_CMS_SignerInfo_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("CMS_SignerInfo")(st, i);
		}

	pragma(inline, true)
	auto sk_CMS_SignerInfo_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("CMS_SignerInfo")(st, ptr_);
		}

	pragma(inline, true)
	int sk_CMS_SignerInfo_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("CMS_SignerInfo")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_CMS_SignerInfo_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("CMS_SignerInfo")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_CMS_SignerInfo_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("CMS_SignerInfo")(st);
		}

	pragma(inline, true)
	void sk_CMS_SignerInfo_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("CMS_SignerInfo")(st, free_func);
		}

	pragma(inline, true)
	auto sk_CMS_SignerInfo_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("CMS_SignerInfo")(st);
		}

	pragma(inline, true)
	auto sk_CMS_SignerInfo_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("CMS_SignerInfo")(st);
		}

	pragma(inline, true)
	void sk_CMS_SignerInfo_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("CMS_SignerInfo")(st);
		}

	pragma(inline, true)
	int sk_CMS_SignerInfo_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("CMS_SignerInfo")(st);
		}
}

pragma(inline, true)
auto sk_CONF_IMODULE_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("CONF_IMODULE")(cmp);
	}

pragma(inline, true)
auto sk_CONF_IMODULE_new_null()

	do
	{
		return .SKM_sk_new_null!("CONF_IMODULE")();
	}

pragma(inline, true)
void sk_CONF_IMODULE_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("CONF_IMODULE")(st);
	}

pragma(inline, true)
int sk_CONF_IMODULE_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("CONF_IMODULE")(st);
	}

pragma(inline, true)
auto sk_CONF_IMODULE_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("CONF_IMODULE")(st, i);
	}

pragma(inline, true)
void* sk_CONF_IMODULE_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("CONF_IMODULE")(st, i, val);
	}

pragma(inline, true)
void sk_CONF_IMODULE_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("CONF_IMODULE")(st);
	}

pragma(inline, true)
int sk_CONF_IMODULE_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("CONF_IMODULE")(st, val);
	}

pragma(inline, true)
int sk_CONF_IMODULE_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("CONF_IMODULE")(st, val);
	}

pragma(inline, true)
int sk_CONF_IMODULE_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("CONF_IMODULE")(st, val);
	}

pragma(inline, true)
int sk_CONF_IMODULE_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("CONF_IMODULE")(st, val);
	}

pragma(inline, true)
auto sk_CONF_IMODULE_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("CONF_IMODULE")(st, i);
	}

pragma(inline, true)
auto sk_CONF_IMODULE_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("CONF_IMODULE")(st, ptr_);
	}

pragma(inline, true)
int sk_CONF_IMODULE_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("CONF_IMODULE")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_CONF_IMODULE_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("CONF_IMODULE")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_CONF_IMODULE_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("CONF_IMODULE")(st);
	}

pragma(inline, true)
void sk_CONF_IMODULE_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("CONF_IMODULE")(st, free_func);
	}

pragma(inline, true)
auto sk_CONF_IMODULE_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("CONF_IMODULE")(st);
	}

pragma(inline, true)
auto sk_CONF_IMODULE_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("CONF_IMODULE")(st);
	}

pragma(inline, true)
void sk_CONF_IMODULE_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("CONF_IMODULE")(st);
	}

pragma(inline, true)
int sk_CONF_IMODULE_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("CONF_IMODULE")(st);
	}

pragma(inline, true)
auto sk_CONF_MODULE_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("CONF_MODULE")(cmp);
	}

pragma(inline, true)
auto sk_CONF_MODULE_new_null()

	do
	{
		return .SKM_sk_new_null!("CONF_MODULE")();
	}

pragma(inline, true)
void sk_CONF_MODULE_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("CONF_MODULE")(st);
	}

pragma(inline, true)
int sk_CONF_MODULE_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("CONF_MODULE")(st);
	}

pragma(inline, true)
auto sk_CONF_MODULE_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("CONF_MODULE")(st, i);
	}

pragma(inline, true)
void* sk_CONF_MODULE_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("CONF_MODULE")(st, i, val);
	}

pragma(inline, true)
void sk_CONF_MODULE_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("CONF_MODULE")(st);
	}

pragma(inline, true)
int sk_CONF_MODULE_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("CONF_MODULE")(st, val);
	}

pragma(inline, true)
int sk_CONF_MODULE_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("CONF_MODULE")(st, val);
	}

pragma(inline, true)
int sk_CONF_MODULE_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("CONF_MODULE")(st, val);
	}

pragma(inline, true)
int sk_CONF_MODULE_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("CONF_MODULE")(st, val);
	}

pragma(inline, true)
auto sk_CONF_MODULE_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("CONF_MODULE")(st, i);
	}

pragma(inline, true)
auto sk_CONF_MODULE_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("CONF_MODULE")(st, ptr_);
	}

pragma(inline, true)
int sk_CONF_MODULE_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("CONF_MODULE")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_CONF_MODULE_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("CONF_MODULE")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_CONF_MODULE_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("CONF_MODULE")(st);
	}

pragma(inline, true)
void sk_CONF_MODULE_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("CONF_MODULE")(st, free_func);
	}

pragma(inline, true)
auto sk_CONF_MODULE_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("CONF_MODULE")(st);
	}

pragma(inline, true)
auto sk_CONF_MODULE_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("CONF_MODULE")(st);
	}

pragma(inline, true)
void sk_CONF_MODULE_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("CONF_MODULE")(st);
	}

pragma(inline, true)
int sk_CONF_MODULE_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("CONF_MODULE")(st);
	}

pragma(inline, true)
auto sk_CONF_VALUE_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("CONF_VALUE")(cmp);
	}

pragma(inline, true)
auto sk_CONF_VALUE_new_null()

	do
	{
		return .SKM_sk_new_null!("CONF_VALUE")();
	}

pragma(inline, true)
void sk_CONF_VALUE_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("CONF_VALUE")(st);
	}

pragma(inline, true)
int sk_CONF_VALUE_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("CONF_VALUE")(st);
	}

pragma(inline, true)
auto sk_CONF_VALUE_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("CONF_VALUE")(st, i);
	}

pragma(inline, true)
void* sk_CONF_VALUE_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("CONF_VALUE")(st, i, val);
	}

pragma(inline, true)
void sk_CONF_VALUE_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("CONF_VALUE")(st);
	}

pragma(inline, true)
int sk_CONF_VALUE_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("CONF_VALUE")(st, val);
	}

pragma(inline, true)
int sk_CONF_VALUE_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("CONF_VALUE")(st, val);
	}

pragma(inline, true)
int sk_CONF_VALUE_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("CONF_VALUE")(st, val);
	}

pragma(inline, true)
int sk_CONF_VALUE_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("CONF_VALUE")(st, val);
	}

pragma(inline, true)
auto sk_CONF_VALUE_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("CONF_VALUE")(st, i);
	}

pragma(inline, true)
auto sk_CONF_VALUE_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("CONF_VALUE")(st, ptr_);
	}

pragma(inline, true)
int sk_CONF_VALUE_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("CONF_VALUE")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_CONF_VALUE_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("CONF_VALUE")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_CONF_VALUE_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("CONF_VALUE")(st);
	}

pragma(inline, true)
void sk_CONF_VALUE_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("CONF_VALUE")(st, free_func);
	}

pragma(inline, true)
auto sk_CONF_VALUE_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("CONF_VALUE")(st);
	}

pragma(inline, true)
auto sk_CONF_VALUE_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("CONF_VALUE")(st);
	}

pragma(inline, true)
void sk_CONF_VALUE_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("CONF_VALUE")(st);
	}

pragma(inline, true)
int sk_CONF_VALUE_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("CONF_VALUE")(st);
	}

pragma(inline, true)
auto sk_CRYPTO_EX_DATA_FUNCS_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("CRYPTO_EX_DATA_FUNCS")(cmp);
	}

pragma(inline, true)
auto sk_CRYPTO_EX_DATA_FUNCS_new_null()

	do
	{
		return .SKM_sk_new_null!("CRYPTO_EX_DATA_FUNCS")();
	}

pragma(inline, true)
void sk_CRYPTO_EX_DATA_FUNCS_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("CRYPTO_EX_DATA_FUNCS")(st);
	}

pragma(inline, true)
int sk_CRYPTO_EX_DATA_FUNCS_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("CRYPTO_EX_DATA_FUNCS")(st);
	}

pragma(inline, true)
auto sk_CRYPTO_EX_DATA_FUNCS_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("CRYPTO_EX_DATA_FUNCS")(st, i);
	}

pragma(inline, true)
void* sk_CRYPTO_EX_DATA_FUNCS_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("CRYPTO_EX_DATA_FUNCS")(st, i, val);
	}

pragma(inline, true)
void sk_CRYPTO_EX_DATA_FUNCS_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("CRYPTO_EX_DATA_FUNCS")(st);
	}

pragma(inline, true)
int sk_CRYPTO_EX_DATA_FUNCS_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("CRYPTO_EX_DATA_FUNCS")(st, val);
	}

pragma(inline, true)
int sk_CRYPTO_EX_DATA_FUNCS_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("CRYPTO_EX_DATA_FUNCS")(st, val);
	}

pragma(inline, true)
int sk_CRYPTO_EX_DATA_FUNCS_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("CRYPTO_EX_DATA_FUNCS")(st, val);
	}

pragma(inline, true)
int sk_CRYPTO_EX_DATA_FUNCS_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("CRYPTO_EX_DATA_FUNCS")(st, val);
	}

pragma(inline, true)
auto sk_CRYPTO_EX_DATA_FUNCS_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("CRYPTO_EX_DATA_FUNCS")(st, i);
	}

pragma(inline, true)
auto sk_CRYPTO_EX_DATA_FUNCS_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("CRYPTO_EX_DATA_FUNCS")(st, ptr_);
	}

pragma(inline, true)
int sk_CRYPTO_EX_DATA_FUNCS_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("CRYPTO_EX_DATA_FUNCS")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_CRYPTO_EX_DATA_FUNCS_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("CRYPTO_EX_DATA_FUNCS")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_CRYPTO_EX_DATA_FUNCS_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("CRYPTO_EX_DATA_FUNCS")(st);
	}

pragma(inline, true)
void sk_CRYPTO_EX_DATA_FUNCS_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("CRYPTO_EX_DATA_FUNCS")(st, free_func);
	}

pragma(inline, true)
auto sk_CRYPTO_EX_DATA_FUNCS_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("CRYPTO_EX_DATA_FUNCS")(st);
	}

pragma(inline, true)
auto sk_CRYPTO_EX_DATA_FUNCS_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("CRYPTO_EX_DATA_FUNCS")(st);
	}

pragma(inline, true)
void sk_CRYPTO_EX_DATA_FUNCS_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("CRYPTO_EX_DATA_FUNCS")(st);
	}

pragma(inline, true)
int sk_CRYPTO_EX_DATA_FUNCS_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("CRYPTO_EX_DATA_FUNCS")(st);
	}

version (none) {
	pragma(inline, true)
	auto sk_CRYPTO_dynlock_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("CRYPTO_dynlock")(cmp);
		}

	pragma(inline, true)
	auto sk_CRYPTO_dynlock_new_null()

		do
		{
			return .SKM_sk_new_null!("CRYPTO_dynlock")();
		}

	pragma(inline, true)
	void sk_CRYPTO_dynlock_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("CRYPTO_dynlock")(st);
		}

	pragma(inline, true)
	int sk_CRYPTO_dynlock_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("CRYPTO_dynlock")(st);
		}

	pragma(inline, true)
	auto sk_CRYPTO_dynlock_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("CRYPTO_dynlock")(st, i);
		}

	pragma(inline, true)
	void* sk_CRYPTO_dynlock_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("CRYPTO_dynlock")(st, i, val);
		}

	pragma(inline, true)
	void sk_CRYPTO_dynlock_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("CRYPTO_dynlock")(st);
		}

	pragma(inline, true)
	int sk_CRYPTO_dynlock_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("CRYPTO_dynlock")(st, val);
		}

	pragma(inline, true)
	int sk_CRYPTO_dynlock_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("CRYPTO_dynlock")(st, val);
		}

	pragma(inline, true)
	int sk_CRYPTO_dynlock_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("CRYPTO_dynlock")(st, val);
		}

	pragma(inline, true)
	int sk_CRYPTO_dynlock_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("CRYPTO_dynlock")(st, val);
		}

	pragma(inline, true)
	auto sk_CRYPTO_dynlock_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("CRYPTO_dynlock")(st, i);
		}

	pragma(inline, true)
	auto sk_CRYPTO_dynlock_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("CRYPTO_dynlock")(st, ptr_);
		}

	pragma(inline, true)
	int sk_CRYPTO_dynlock_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("CRYPTO_dynlock")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_CRYPTO_dynlock_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("CRYPTO_dynlock")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_CRYPTO_dynlock_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("CRYPTO_dynlock")(st);
		}

	pragma(inline, true)
	void sk_CRYPTO_dynlock_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("CRYPTO_dynlock")(st, free_func);
		}

	pragma(inline, true)
	auto sk_CRYPTO_dynlock_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("CRYPTO_dynlock")(st);
		}

	pragma(inline, true)
	auto sk_CRYPTO_dynlock_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("CRYPTO_dynlock")(st);
		}

	pragma(inline, true)
	void sk_CRYPTO_dynlock_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("CRYPTO_dynlock")(st);
		}

	pragma(inline, true)
	int sk_CRYPTO_dynlock_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("CRYPTO_dynlock")(st);
		}
}

version (OPENSSL_NO_CT) {
} else {
	pragma(inline, true)
	auto sk_CTLOG_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("CTLOG")(cmp);
		}

	pragma(inline, true)
	auto sk_CTLOG_new_null()

		do
		{
			return .SKM_sk_new_null!("CTLOG")();
		}

	pragma(inline, true)
	void sk_CTLOG_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("CTLOG")(st);
		}

	pragma(inline, true)
	int sk_CTLOG_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("CTLOG")(st);
		}

	pragma(inline, true)
	auto sk_CTLOG_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("CTLOG")(st, i);
		}

	pragma(inline, true)
	void* sk_CTLOG_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("CTLOG")(st, i, val);
		}

	pragma(inline, true)
	void sk_CTLOG_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("CTLOG")(st);
		}

	pragma(inline, true)
	int sk_CTLOG_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("CTLOG")(st, val);
		}

	pragma(inline, true)
	int sk_CTLOG_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("CTLOG")(st, val);
		}

	pragma(inline, true)
	int sk_CTLOG_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("CTLOG")(st, val);
		}

	pragma(inline, true)
	int sk_CTLOG_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("CTLOG")(st, val);
		}

	pragma(inline, true)
	auto sk_CTLOG_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("CTLOG")(st, i);
		}


	pragma(inline, true)
	auto sk_CTLOG_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("CTLOG")(st, ptr);
		}


	pragma(inline, true)
	int sk_CTLOG_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("CTLOG")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_CTLOG_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("CTLOG")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_CTLOG_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("CTLOG")(st);
		}

	pragma(inline, true)
	void sk_CTLOG_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("CTLOG")(st, free_func);
		}

	pragma(inline, true)
	auto sk_CTLOG_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("CTLOG")(st);
		}

	pragma(inline, true)
	auto sk_CTLOG_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("CTLOG")(st);
		}

	pragma(inline, true)
	void sk_CTLOG_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("CTLOG")(st);
		}

	pragma(inline, true)
	int sk_CTLOG_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("CTLOG")(st);
		}
}

pragma(inline, true)
auto sk_DIST_POINT_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("DIST_POINT")(cmp);
	}

pragma(inline, true)
auto sk_DIST_POINT_new_null()

	do
	{
		return .SKM_sk_new_null!("DIST_POINT")();
	}

pragma(inline, true)
void sk_DIST_POINT_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("DIST_POINT")(st);
	}

pragma(inline, true)
int sk_DIST_POINT_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("DIST_POINT")(st);
	}

pragma(inline, true)
auto sk_DIST_POINT_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("DIST_POINT")(st, i);
	}

pragma(inline, true)
void* sk_DIST_POINT_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("DIST_POINT")(st, i, val);
	}

pragma(inline, true)
void sk_DIST_POINT_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("DIST_POINT")(st);
	}

pragma(inline, true)
int sk_DIST_POINT_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("DIST_POINT")(st, val);
	}

pragma(inline, true)
int sk_DIST_POINT_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("DIST_POINT")(st, val);
	}

pragma(inline, true)
int sk_DIST_POINT_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("DIST_POINT")(st, val);
	}

pragma(inline, true)
int sk_DIST_POINT_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("DIST_POINT")(st, val);
	}

pragma(inline, true)
auto sk_DIST_POINT_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("DIST_POINT")(st, i);
	}

pragma(inline, true)
auto sk_DIST_POINT_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("DIST_POINT")(st, ptr_);
	}

pragma(inline, true)
int sk_DIST_POINT_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("DIST_POINT")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_DIST_POINT_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("DIST_POINT")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_DIST_POINT_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("DIST_POINT")(st);
	}

pragma(inline, true)
void sk_DIST_POINT_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("DIST_POINT")(st, free_func);
	}

pragma(inline, true)
auto sk_DIST_POINT_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("DIST_POINT")(st);
	}

pragma(inline, true)
auto sk_DIST_POINT_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("DIST_POINT")(st);
	}

pragma(inline, true)
void sk_DIST_POINT_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("DIST_POINT")(st);
	}

pragma(inline, true)
int sk_DIST_POINT_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("DIST_POINT")(st);
	}

version (none) {
	pragma(inline, true)
	auto sk_ENGINE_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("ENGINE")(cmp);
		}

	pragma(inline, true)
	auto sk_ENGINE_new_null()

		do
		{
			return .SKM_sk_new_null!("ENGINE")();
		}

	pragma(inline, true)
	void sk_ENGINE_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("ENGINE")(st);
		}

	pragma(inline, true)
	int sk_ENGINE_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("ENGINE")(st);
		}

	pragma(inline, true)
	auto sk_ENGINE_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("ENGINE")(st, i);
		}

	pragma(inline, true)
	void* sk_ENGINE_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("ENGINE")(st, i, val);
		}

	pragma(inline, true)
	void sk_ENGINE_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("ENGINE")(st);
		}

	pragma(inline, true)
	int sk_ENGINE_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("ENGINE")(st, val);
		}

	pragma(inline, true)
	int sk_ENGINE_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("ENGINE")(st, val);
		}

	pragma(inline, true)
	int sk_ENGINE_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("ENGINE")(st, val);
		}

	pragma(inline, true)
	int sk_ENGINE_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("ENGINE")(st, val);
		}

	pragma(inline, true)
	auto sk_ENGINE_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("ENGINE")(st, i);
		}

	pragma(inline, true)
	auto sk_ENGINE_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("ENGINE")(st, ptr_);
		}

	pragma(inline, true)
	int sk_ENGINE_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("ENGINE")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_ENGINE_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("ENGINE")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_ENGINE_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("ENGINE")(st);
		}

	pragma(inline, true)
	void sk_ENGINE_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("ENGINE")(st, free_func);
		}

	pragma(inline, true)
	auto sk_ENGINE_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("ENGINE")(st);
		}

	pragma(inline, true)
	auto sk_ENGINE_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("ENGINE")(st);
		}

	pragma(inline, true)
	void sk_ENGINE_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("ENGINE")(st);
		}

	pragma(inline, true)
	int sk_ENGINE_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("ENGINE")(st);
		}
}

version (none) {
	pragma(inline, true)
	auto sk_ENGINE_CLEANUP_ITEM_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("ENGINE_CLEANUP_ITEM")(cmp);
		}

	pragma(inline, true)
	auto sk_ENGINE_CLEANUP_ITEM_new_null()

		do
		{
			return .SKM_sk_new_null!("ENGINE_CLEANUP_ITEM")();
		}

	pragma(inline, true)
	void sk_ENGINE_CLEANUP_ITEM_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("ENGINE_CLEANUP_ITEM")(st);
		}

	pragma(inline, true)
	int sk_ENGINE_CLEANUP_ITEM_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("ENGINE_CLEANUP_ITEM")(st);
		}

	pragma(inline, true)
	auto sk_ENGINE_CLEANUP_ITEM_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("ENGINE_CLEANUP_ITEM")(st, i);
		}

	pragma(inline, true)
	void* sk_ENGINE_CLEANUP_ITEM_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("ENGINE_CLEANUP_ITEM")(st, i, val);
		}

	pragma(inline, true)
	void sk_ENGINE_CLEANUP_ITEM_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("ENGINE_CLEANUP_ITEM")(st);
		}

	pragma(inline, true)
	int sk_ENGINE_CLEANUP_ITEM_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("ENGINE_CLEANUP_ITEM")(st, val);
		}

	pragma(inline, true)
	int sk_ENGINE_CLEANUP_ITEM_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("ENGINE_CLEANUP_ITEM")(st, val);
		}

	pragma(inline, true)
	int sk_ENGINE_CLEANUP_ITEM_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("ENGINE_CLEANUP_ITEM")(st, val);
		}

	pragma(inline, true)
	int sk_ENGINE_CLEANUP_ITEM_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("ENGINE_CLEANUP_ITEM")(st, val);
		}

	pragma(inline, true)
	auto sk_ENGINE_CLEANUP_ITEM_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("ENGINE_CLEANUP_ITEM")(st, i);
		}

	pragma(inline, true)
	auto sk_ENGINE_CLEANUP_ITEM_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("ENGINE_CLEANUP_ITEM")(st, ptr_);
		}

	pragma(inline, true)
	int sk_ENGINE_CLEANUP_ITEM_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("ENGINE_CLEANUP_ITEM")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_ENGINE_CLEANUP_ITEM_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("ENGINE_CLEANUP_ITEM")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_ENGINE_CLEANUP_ITEM_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("ENGINE_CLEANUP_ITEM")(st);
		}

	pragma(inline, true)
	void sk_ENGINE_CLEANUP_ITEM_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("ENGINE_CLEANUP_ITEM")(st, free_func);
		}

	pragma(inline, true)
	auto sk_ENGINE_CLEANUP_ITEM_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("ENGINE_CLEANUP_ITEM")(st);
		}

	pragma(inline, true)
	auto sk_ENGINE_CLEANUP_ITEM_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("ENGINE_CLEANUP_ITEM")(st);
		}

	pragma(inline, true)
	void sk_ENGINE_CLEANUP_ITEM_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("ENGINE_CLEANUP_ITEM")(st);
		}

	pragma(inline, true)
	int sk_ENGINE_CLEANUP_ITEM_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("ENGINE_CLEANUP_ITEM")(st);
		}
}

pragma(inline, true)
auto sk_ESS_CERT_ID_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("ESS_CERT_ID")(cmp);
	}

pragma(inline, true)
auto sk_ESS_CERT_ID_new_null()

	do
	{
		return .SKM_sk_new_null!("ESS_CERT_ID")();
	}

pragma(inline, true)
void sk_ESS_CERT_ID_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("ESS_CERT_ID")(st);
	}

pragma(inline, true)
int sk_ESS_CERT_ID_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("ESS_CERT_ID")(st);
	}

pragma(inline, true)
auto sk_ESS_CERT_ID_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("ESS_CERT_ID")(st, i);
	}

pragma(inline, true)
void* sk_ESS_CERT_ID_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("ESS_CERT_ID")(st, i, val);
	}

pragma(inline, true)
void sk_ESS_CERT_ID_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("ESS_CERT_ID")(st);
	}

pragma(inline, true)
int sk_ESS_CERT_ID_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("ESS_CERT_ID")(st, val);
	}

pragma(inline, true)
int sk_ESS_CERT_ID_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("ESS_CERT_ID")(st, val);
	}

pragma(inline, true)
int sk_ESS_CERT_ID_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("ESS_CERT_ID")(st, val);
	}

pragma(inline, true)
int sk_ESS_CERT_ID_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("ESS_CERT_ID")(st, val);
	}

pragma(inline, true)
auto sk_ESS_CERT_ID_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("ESS_CERT_ID")(st, i);
	}

pragma(inline, true)
auto sk_ESS_CERT_ID_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("ESS_CERT_ID")(st, ptr_);
	}

pragma(inline, true)
int sk_ESS_CERT_ID_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("ESS_CERT_ID")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_ESS_CERT_ID_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("ESS_CERT_ID")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_ESS_CERT_ID_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("ESS_CERT_ID")(st);
	}

pragma(inline, true)
void sk_ESS_CERT_ID_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("ESS_CERT_ID")(st, free_func);
	}

pragma(inline, true)
auto sk_ESS_CERT_ID_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("ESS_CERT_ID")(st);
	}

pragma(inline, true)
auto sk_ESS_CERT_ID_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("ESS_CERT_ID")(st);
	}

pragma(inline, true)
void sk_ESS_CERT_ID_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("ESS_CERT_ID")(st);
	}

pragma(inline, true)
int sk_ESS_CERT_ID_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("ESS_CERT_ID")(st);
	}

version (LIBRESSL_INTERNAL) {
	pragma(inline, true)
	auto sk_ESS_CERT_ID_V2_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("ESS_CERT_ID_V2")(cmp);
		}

	pragma(inline, true)
	auto sk_ESS_CERT_ID_V2_new_null()

		do
		{
			return .SKM_sk_new_null!("ESS_CERT_ID_V2")();
		}

	pragma(inline, true)
	void sk_ESS_CERT_ID_V2_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("ESS_CERT_ID_V2")(st);
		}

	pragma(inline, true)
	int sk_ESS_CERT_ID_V2_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("ESS_CERT_ID_V2")(st);
		}

	pragma(inline, true)
	auto sk_ESS_CERT_ID_V2_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("ESS_CERT_ID_V2")(st, i);
		}

	pragma(inline, true)
	void* sk_ESS_CERT_ID_V2_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("ESS_CERT_ID_V2")(st, i, val);
		}

	pragma(inline, true)
	void sk_ESS_CERT_ID_V2_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("ESS_CERT_ID_V2")(st);
		}

	pragma(inline, true)
	int sk_ESS_CERT_ID_V2_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("ESS_CERT_ID_V2")(st, val);
		}

	pragma(inline, true)
	int sk_ESS_CERT_ID_V2_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("ESS_CERT_ID_V2")(st, val);
		}

	pragma(inline, true)
	int sk_ESS_CERT_ID_V2_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("ESS_CERT_ID_V2")(st, val);
		}

	pragma(inline, true)
	int sk_ESS_CERT_ID_V2_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("ESS_CERT_ID_V2")(st, val);
		}

	pragma(inline, true)
	auto sk_ESS_CERT_ID_V2_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("ESS_CERT_ID_V2")(st, i);
		}


	pragma(inline, true)
	auto sk_ESS_CERT_ID_V2_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("ESS_CERT_ID_V2")(st, ptr);
		}


	pragma(inline, true)
	int sk_ESS_CERT_ID_V2_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("ESS_CERT_ID_V2")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_ESS_CERT_ID_V2_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("ESS_CERT_ID_V2")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_ESS_CERT_ID_V2_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("ESS_CERT_ID_V2")(st);
		}

	pragma(inline, true)
	void sk_ESS_CERT_ID_V2_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("ESS_CERT_ID_V2")(st, free_func);
		}

	pragma(inline, true)
	auto sk_ESS_CERT_ID_V2_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("ESS_CERT_ID_V2")(st);
		}

	pragma(inline, true)
	auto sk_ESS_CERT_ID_V2_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("ESS_CERT_ID_V2")(st);
		}

	pragma(inline, true)
	void sk_ESS_CERT_ID_V2_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("ESS_CERT_ID_V2")(st);
		}

	pragma(inline, true)
	int sk_ESS_CERT_ID_V2_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("ESS_CERT_ID_V2")(st);
		}
}

pragma(inline, true)
auto sk_EVP_MD_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("EVP_MD")(cmp);
	}

pragma(inline, true)
auto sk_EVP_MD_new_null()

	do
	{
		return .SKM_sk_new_null!("EVP_MD")();
	}

pragma(inline, true)
void sk_EVP_MD_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("EVP_MD")(st);
	}

pragma(inline, true)
int sk_EVP_MD_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("EVP_MD")(st);
	}

pragma(inline, true)
auto sk_EVP_MD_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("EVP_MD")(st, i);
	}

pragma(inline, true)
void* sk_EVP_MD_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("EVP_MD")(st, i, val);
	}

pragma(inline, true)
void sk_EVP_MD_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("EVP_MD")(st);
	}

pragma(inline, true)
int sk_EVP_MD_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("EVP_MD")(st, val);
	}

pragma(inline, true)
int sk_EVP_MD_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("EVP_MD")(st, val);
	}

pragma(inline, true)
int sk_EVP_MD_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("EVP_MD")(st, val);
	}

pragma(inline, true)
int sk_EVP_MD_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("EVP_MD")(st, val);
	}

pragma(inline, true)
auto sk_EVP_MD_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("EVP_MD")(st, i);
	}

pragma(inline, true)
auto sk_EVP_MD_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("EVP_MD")(st, ptr_);
	}

pragma(inline, true)
int sk_EVP_MD_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("EVP_MD")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_EVP_MD_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("EVP_MD")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_EVP_MD_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("EVP_MD")(st);
	}

pragma(inline, true)
void sk_EVP_MD_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("EVP_MD")(st, free_func);
	}

pragma(inline, true)
auto sk_EVP_MD_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("EVP_MD")(st);
	}

pragma(inline, true)
auto sk_EVP_MD_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("EVP_MD")(st);
	}

pragma(inline, true)
void sk_EVP_MD_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("EVP_MD")(st);
	}

pragma(inline, true)
int sk_EVP_MD_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("EVP_MD")(st);
	}

version (none) {
	pragma(inline, true)
	auto sk_EVP_PBE_CTL_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("EVP_PBE_CTL")(cmp);
		}

	pragma(inline, true)
	auto sk_EVP_PBE_CTL_new_null()

		do
		{
			return .SKM_sk_new_null!("EVP_PBE_CTL")();
		}

	pragma(inline, true)
	void sk_EVP_PBE_CTL_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("EVP_PBE_CTL")(st);
		}

	pragma(inline, true)
	int sk_EVP_PBE_CTL_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("EVP_PBE_CTL")(st);
		}

	pragma(inline, true)
	auto sk_EVP_PBE_CTL_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("EVP_PBE_CTL")(st, i);
		}

	pragma(inline, true)
	void* sk_EVP_PBE_CTL_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("EVP_PBE_CTL")(st, i, val);
		}

	pragma(inline, true)
	void sk_EVP_PBE_CTL_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("EVP_PBE_CTL")(st);
		}

	pragma(inline, true)
	int sk_EVP_PBE_CTL_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("EVP_PBE_CTL")(st, val);
		}

	pragma(inline, true)
	int sk_EVP_PBE_CTL_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("EVP_PBE_CTL")(st, val);
		}

	pragma(inline, true)
	int sk_EVP_PBE_CTL_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("EVP_PBE_CTL")(st, val);
		}

	pragma(inline, true)
	int sk_EVP_PBE_CTL_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("EVP_PBE_CTL")(st, val);
		}

	pragma(inline, true)
	auto sk_EVP_PBE_CTL_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("EVP_PBE_CTL")(st, i);
		}

	pragma(inline, true)
	auto sk_EVP_PBE_CTL_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("EVP_PBE_CTL")(st, ptr_);
		}

	pragma(inline, true)
	int sk_EVP_PBE_CTL_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("EVP_PBE_CTL")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_EVP_PBE_CTL_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("EVP_PBE_CTL")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_EVP_PBE_CTL_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("EVP_PBE_CTL")(st);
		}

	pragma(inline, true)
	void sk_EVP_PBE_CTL_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("EVP_PBE_CTL")(st, free_func);
		}

	pragma(inline, true)
	auto sk_EVP_PBE_CTL_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("EVP_PBE_CTL")(st);
		}

	pragma(inline, true)
	auto sk_EVP_PBE_CTL_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("EVP_PBE_CTL")(st);
		}

	pragma(inline, true)
	void sk_EVP_PBE_CTL_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("EVP_PBE_CTL")(st);
		}

	pragma(inline, true)
	int sk_EVP_PBE_CTL_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("EVP_PBE_CTL")(st);
		}
}

version (none) {
	pragma(inline, true)
	auto sk_EVP_PKEY_ASN1_METHOD_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("EVP_PKEY_ASN1_METHOD")(cmp);
		}

	pragma(inline, true)
	auto sk_EVP_PKEY_ASN1_METHOD_new_null()

		do
		{
			return .SKM_sk_new_null!("EVP_PKEY_ASN1_METHOD")();
		}

	pragma(inline, true)
	void sk_EVP_PKEY_ASN1_METHOD_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("EVP_PKEY_ASN1_METHOD")(st);
		}

	pragma(inline, true)
	int sk_EVP_PKEY_ASN1_METHOD_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("EVP_PKEY_ASN1_METHOD")(st);
		}

	pragma(inline, true)
	auto sk_EVP_PKEY_ASN1_METHOD_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("EVP_PKEY_ASN1_METHOD")(st, i);
		}

	pragma(inline, true)
	void* sk_EVP_PKEY_ASN1_METHOD_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("EVP_PKEY_ASN1_METHOD")(st, i, val);
		}

	pragma(inline, true)
	void sk_EVP_PKEY_ASN1_METHOD_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("EVP_PKEY_ASN1_METHOD")(st);
		}

	pragma(inline, true)
	int sk_EVP_PKEY_ASN1_METHOD_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("EVP_PKEY_ASN1_METHOD")(st, val);
		}

	pragma(inline, true)
	int sk_EVP_PKEY_ASN1_METHOD_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("EVP_PKEY_ASN1_METHOD")(st, val);
		}

	pragma(inline, true)
	int sk_EVP_PKEY_ASN1_METHOD_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("EVP_PKEY_ASN1_METHOD")(st, val);
		}

	pragma(inline, true)
	int sk_EVP_PKEY_ASN1_METHOD_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("EVP_PKEY_ASN1_METHOD")(st, val);
		}

	pragma(inline, true)
	auto sk_EVP_PKEY_ASN1_METHOD_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("EVP_PKEY_ASN1_METHOD")(st, i);
		}

	pragma(inline, true)
	auto sk_EVP_PKEY_ASN1_METHOD_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("EVP_PKEY_ASN1_METHOD")(st, ptr_);
		}

	pragma(inline, true)
	int sk_EVP_PKEY_ASN1_METHOD_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("EVP_PKEY_ASN1_METHOD")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_EVP_PKEY_ASN1_METHOD_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("EVP_PKEY_ASN1_METHOD")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_EVP_PKEY_ASN1_METHOD_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("EVP_PKEY_ASN1_METHOD")(st);
		}

	pragma(inline, true)
	void sk_EVP_PKEY_ASN1_METHOD_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("EVP_PKEY_ASN1_METHOD")(st, free_func);
		}

	pragma(inline, true)
	auto sk_EVP_PKEY_ASN1_METHOD_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("EVP_PKEY_ASN1_METHOD")(st);
		}

	pragma(inline, true)
	auto sk_EVP_PKEY_ASN1_METHOD_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("EVP_PKEY_ASN1_METHOD")(st);
		}

	pragma(inline, true)
	void sk_EVP_PKEY_ASN1_METHOD_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("EVP_PKEY_ASN1_METHOD")(st);
		}

	pragma(inline, true)
	int sk_EVP_PKEY_ASN1_METHOD_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("EVP_PKEY_ASN1_METHOD")(st);
		}
}

version (none) {
	pragma(inline, true)
	auto sk_EVP_PKEY_METHOD_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("EVP_PKEY_METHOD")(cmp);
		}

	pragma(inline, true)
	auto sk_EVP_PKEY_METHOD_new_null()

		do
		{
			return .SKM_sk_new_null!("EVP_PKEY_METHOD")();
		}

	pragma(inline, true)
	void sk_EVP_PKEY_METHOD_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("EVP_PKEY_METHOD")(st);
		}

	pragma(inline, true)
	int sk_EVP_PKEY_METHOD_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("EVP_PKEY_METHOD")(st);
		}

	pragma(inline, true)
	auto sk_EVP_PKEY_METHOD_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("EVP_PKEY_METHOD")(st, i);
		}

	pragma(inline, true)
	void* sk_EVP_PKEY_METHOD_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("EVP_PKEY_METHOD")(st, i, val);
		}

	pragma(inline, true)
	void sk_EVP_PKEY_METHOD_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("EVP_PKEY_METHOD")(st);
		}

	pragma(inline, true)
	int sk_EVP_PKEY_METHOD_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("EVP_PKEY_METHOD")(st, val);
		}

	pragma(inline, true)
	int sk_EVP_PKEY_METHOD_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("EVP_PKEY_METHOD")(st, val);
		}

	pragma(inline, true)
	int sk_EVP_PKEY_METHOD_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("EVP_PKEY_METHOD")(st, val);
		}

	pragma(inline, true)
	int sk_EVP_PKEY_METHOD_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("EVP_PKEY_METHOD")(st, val);
		}

	pragma(inline, true)
	auto sk_EVP_PKEY_METHOD_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("EVP_PKEY_METHOD")(st, i);
		}

	pragma(inline, true)
	auto sk_EVP_PKEY_METHOD_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("EVP_PKEY_METHOD")(st, ptr_);
		}

	pragma(inline, true)
	int sk_EVP_PKEY_METHOD_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("EVP_PKEY_METHOD")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_EVP_PKEY_METHOD_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("EVP_PKEY_METHOD")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_EVP_PKEY_METHOD_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("EVP_PKEY_METHOD")(st);
		}

	pragma(inline, true)
	void sk_EVP_PKEY_METHOD_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("EVP_PKEY_METHOD")(st, free_func);
		}

	pragma(inline, true)
	auto sk_EVP_PKEY_METHOD_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("EVP_PKEY_METHOD")(st);
		}

	pragma(inline, true)
	auto sk_EVP_PKEY_METHOD_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("EVP_PKEY_METHOD")(st);
		}

	pragma(inline, true)
	void sk_EVP_PKEY_METHOD_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("EVP_PKEY_METHOD")(st);
		}

	pragma(inline, true)
	int sk_EVP_PKEY_METHOD_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("EVP_PKEY_METHOD")(st);
		}
}

pragma(inline, true)
auto sk_GENERAL_NAME_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("GENERAL_NAME")(cmp);
	}

pragma(inline, true)
auto sk_GENERAL_NAME_new_null()

	do
	{
		return .SKM_sk_new_null!("GENERAL_NAME")();
	}

pragma(inline, true)
void sk_GENERAL_NAME_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("GENERAL_NAME")(st);
	}

pragma(inline, true)
int sk_GENERAL_NAME_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("GENERAL_NAME")(st);
	}

pragma(inline, true)
auto sk_GENERAL_NAME_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("GENERAL_NAME")(st, i);
	}

pragma(inline, true)
void* sk_GENERAL_NAME_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("GENERAL_NAME")(st, i, val);
	}

pragma(inline, true)
void sk_GENERAL_NAME_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("GENERAL_NAME")(st);
	}

pragma(inline, true)
int sk_GENERAL_NAME_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("GENERAL_NAME")(st, val);
	}

pragma(inline, true)
int sk_GENERAL_NAME_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("GENERAL_NAME")(st, val);
	}

pragma(inline, true)
int sk_GENERAL_NAME_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("GENERAL_NAME")(st, val);
	}

pragma(inline, true)
int sk_GENERAL_NAME_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("GENERAL_NAME")(st, val);
	}

pragma(inline, true)
auto sk_GENERAL_NAME_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("GENERAL_NAME")(st, i);
	}

pragma(inline, true)
auto sk_GENERAL_NAME_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("GENERAL_NAME")(st, ptr_);
	}

pragma(inline, true)
int sk_GENERAL_NAME_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("GENERAL_NAME")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_GENERAL_NAME_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("GENERAL_NAME")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_GENERAL_NAME_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("GENERAL_NAME")(st);
	}

pragma(inline, true)
void sk_GENERAL_NAME_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("GENERAL_NAME")(st, free_func);
	}

pragma(inline, true)
auto sk_GENERAL_NAME_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("GENERAL_NAME")(st);
	}

pragma(inline, true)
auto sk_GENERAL_NAME_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("GENERAL_NAME")(st);
	}

pragma(inline, true)
void sk_GENERAL_NAME_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("GENERAL_NAME")(st);
	}

pragma(inline, true)
int sk_GENERAL_NAME_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("GENERAL_NAME")(st);
	}

pragma(inline, true)
auto sk_GENERAL_NAMES_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("GENERAL_NAMES")(cmp);
	}

pragma(inline, true)
auto sk_GENERAL_NAMES_new_null()

	do
	{
		return .SKM_sk_new_null!("GENERAL_NAMES")();
	}

pragma(inline, true)
void sk_GENERAL_NAMES_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("GENERAL_NAMES")(st);
	}

pragma(inline, true)
int sk_GENERAL_NAMES_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("GENERAL_NAMES")(st);
	}

pragma(inline, true)
auto sk_GENERAL_NAMES_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("GENERAL_NAMES")(st, i);
	}

pragma(inline, true)
void* sk_GENERAL_NAMES_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("GENERAL_NAMES")(st, i, val);
	}

pragma(inline, true)
void sk_GENERAL_NAMES_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("GENERAL_NAMES")(st);
	}

pragma(inline, true)
int sk_GENERAL_NAMES_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("GENERAL_NAMES")(st, val);
	}

pragma(inline, true)
int sk_GENERAL_NAMES_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("GENERAL_NAMES")(st, val);
	}

pragma(inline, true)
int sk_GENERAL_NAMES_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("GENERAL_NAMES")(st, val);
	}

pragma(inline, true)
int sk_GENERAL_NAMES_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("GENERAL_NAMES")(st, val);
	}

pragma(inline, true)
auto sk_GENERAL_NAMES_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("GENERAL_NAMES")(st, i);
	}

pragma(inline, true)
auto sk_GENERAL_NAMES_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("GENERAL_NAMES")(st, ptr_);
	}

pragma(inline, true)
int sk_GENERAL_NAMES_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("GENERAL_NAMES")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_GENERAL_NAMES_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("GENERAL_NAMES")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_GENERAL_NAMES_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("GENERAL_NAMES")(st);
	}

pragma(inline, true)
void sk_GENERAL_NAMES_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("GENERAL_NAMES")(st, free_func);
	}

pragma(inline, true)
auto sk_GENERAL_NAMES_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("GENERAL_NAMES")(st);
	}

pragma(inline, true)
auto sk_GENERAL_NAMES_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("GENERAL_NAMES")(st);
	}

pragma(inline, true)
void sk_GENERAL_NAMES_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("GENERAL_NAMES")(st);
	}

pragma(inline, true)
int sk_GENERAL_NAMES_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("GENERAL_NAMES")(st);
	}

pragma(inline, true)
auto sk_GENERAL_SUBTREE_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("GENERAL_SUBTREE")(cmp);
	}

pragma(inline, true)
auto sk_GENERAL_SUBTREE_new_null()

	do
	{
		return .SKM_sk_new_null!("GENERAL_SUBTREE")();
	}

pragma(inline, true)
void sk_GENERAL_SUBTREE_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("GENERAL_SUBTREE")(st);
	}

pragma(inline, true)
int sk_GENERAL_SUBTREE_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("GENERAL_SUBTREE")(st);
	}

pragma(inline, true)
auto sk_GENERAL_SUBTREE_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("GENERAL_SUBTREE")(st, i);
	}

pragma(inline, true)
void* sk_GENERAL_SUBTREE_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("GENERAL_SUBTREE")(st, i, val);
	}

pragma(inline, true)
void sk_GENERAL_SUBTREE_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("GENERAL_SUBTREE")(st);
	}

pragma(inline, true)
int sk_GENERAL_SUBTREE_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("GENERAL_SUBTREE")(st, val);
	}

pragma(inline, true)
int sk_GENERAL_SUBTREE_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("GENERAL_SUBTREE")(st, val);
	}

pragma(inline, true)
int sk_GENERAL_SUBTREE_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("GENERAL_SUBTREE")(st, val);
	}

pragma(inline, true)
int sk_GENERAL_SUBTREE_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("GENERAL_SUBTREE")(st, val);
	}

pragma(inline, true)
auto sk_GENERAL_SUBTREE_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("GENERAL_SUBTREE")(st, i);
	}

pragma(inline, true)
auto sk_GENERAL_SUBTREE_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("GENERAL_SUBTREE")(st, ptr_);
	}

pragma(inline, true)
int sk_GENERAL_SUBTREE_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("GENERAL_SUBTREE")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_GENERAL_SUBTREE_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("GENERAL_SUBTREE")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_GENERAL_SUBTREE_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("GENERAL_SUBTREE")(st);
	}

pragma(inline, true)
void sk_GENERAL_SUBTREE_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("GENERAL_SUBTREE")(st, free_func);
	}

pragma(inline, true)
auto sk_GENERAL_SUBTREE_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("GENERAL_SUBTREE")(st);
	}

pragma(inline, true)
auto sk_GENERAL_SUBTREE_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("GENERAL_SUBTREE")(st);
	}

pragma(inline, true)
void sk_GENERAL_SUBTREE_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("GENERAL_SUBTREE")(st);
	}

pragma(inline, true)
int sk_GENERAL_SUBTREE_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("GENERAL_SUBTREE")(st);
	}

version (OPENSSL_NO_RFC3779) {
} else {
	pragma(inline, true)
	auto sk_IPAddressFamily_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("IPAddressFamily")(cmp);
		}

	pragma(inline, true)
	auto sk_IPAddressFamily_new_null()

		do
		{
			return .SKM_sk_new_null!("IPAddressFamily")();
		}

	pragma(inline, true)
	void sk_IPAddressFamily_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("IPAddressFamily")(st);
		}

	pragma(inline, true)
	int sk_IPAddressFamily_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("IPAddressFamily")(st);
		}

	pragma(inline, true)
	auto sk_IPAddressFamily_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("IPAddressFamily")(st, i);
		}

	pragma(inline, true)
	void* sk_IPAddressFamily_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("IPAddressFamily")(st, i, val);
		}

	pragma(inline, true)
	void sk_IPAddressFamily_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("IPAddressFamily")(st);
		}

	pragma(inline, true)
	int sk_IPAddressFamily_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("IPAddressFamily")(st, val);
		}

	pragma(inline, true)
	int sk_IPAddressFamily_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("IPAddressFamily")(st, val);
		}

	pragma(inline, true)
	int sk_IPAddressFamily_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("IPAddressFamily")(st, val);
		}

	pragma(inline, true)
	int sk_IPAddressFamily_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("IPAddressFamily")(st, val);
		}

	pragma(inline, true)
	auto sk_IPAddressFamily_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("IPAddressFamily")(st, i);
		}

	pragma(inline, true)
	auto sk_IPAddressFamily_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("IPAddressFamily")(st, ptr_);
		}

	pragma(inline, true)
	int sk_IPAddressFamily_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("IPAddressFamily")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_IPAddressFamily_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("IPAddressFamily")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_IPAddressFamily_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("IPAddressFamily")(st);
		}

	pragma(inline, true)
	void sk_IPAddressFamily_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("IPAddressFamily")(st, free_func);
		}

	pragma(inline, true)
	auto sk_IPAddressFamily_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("IPAddressFamily")(st);
		}

	pragma(inline, true)
	auto sk_IPAddressFamily_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("IPAddressFamily")(st);
		}

	pragma(inline, true)
	void sk_IPAddressFamily_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("IPAddressFamily")(st);
		}

	pragma(inline, true)
	int sk_IPAddressFamily_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("IPAddressFamily")(st);
		}

	pragma(inline, true)
	auto sk_IPAddressOrRange_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("IPAddressOrRange")(cmp);
		}

	pragma(inline, true)
	auto sk_IPAddressOrRange_new_null()

		do
		{
			return .SKM_sk_new_null!("IPAddressOrRange")();
		}

	pragma(inline, true)
	void sk_IPAddressOrRange_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("IPAddressOrRange")(st);
		}

	pragma(inline, true)
	int sk_IPAddressOrRange_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("IPAddressOrRange")(st);
		}

	pragma(inline, true)
	auto sk_IPAddressOrRange_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("IPAddressOrRange")(st, i);
		}

	pragma(inline, true)
	void* sk_IPAddressOrRange_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("IPAddressOrRange")(st, i, val);
		}

	pragma(inline, true)
	void sk_IPAddressOrRange_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("IPAddressOrRange")(st);
		}

	pragma(inline, true)
	int sk_IPAddressOrRange_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("IPAddressOrRange")(st, val);
		}

	pragma(inline, true)
	int sk_IPAddressOrRange_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("IPAddressOrRange")(st, val);
		}

	pragma(inline, true)
	int sk_IPAddressOrRange_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("IPAddressOrRange")(st, val);
		}

	pragma(inline, true)
	int sk_IPAddressOrRange_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("IPAddressOrRange")(st, val);
		}

	pragma(inline, true)
	auto sk_IPAddressOrRange_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("IPAddressOrRange")(st, i);
		}

	pragma(inline, true)
	auto sk_IPAddressOrRange_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("IPAddressOrRange")(st, ptr_);
		}

	pragma(inline, true)
	int sk_IPAddressOrRange_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("IPAddressOrRange")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_IPAddressOrRange_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("IPAddressOrRange")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_IPAddressOrRange_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("IPAddressOrRange")(st);
		}

	pragma(inline, true)
	void sk_IPAddressOrRange_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("IPAddressOrRange")(st, free_func);
		}

	pragma(inline, true)
	auto sk_IPAddressOrRange_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("IPAddressOrRange")(st);
		}

	pragma(inline, true)
	auto sk_IPAddressOrRange_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("IPAddressOrRange")(st);
		}

	pragma(inline, true)
	void sk_IPAddressOrRange_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("IPAddressOrRange")(st);
		}

	pragma(inline, true)
	int sk_IPAddressOrRange_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("IPAddressOrRange")(st);
		}
}

version (none) {
	pragma(inline, true)
	auto sk_MEM_OBJECT_DATA_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("MEM_OBJECT_DATA")(cmp);
		}

	pragma(inline, true)
	auto sk_MEM_OBJECT_DATA_new_null()

		do
		{
			return .SKM_sk_new_null!("MEM_OBJECT_DATA")();
		}

	pragma(inline, true)
	void sk_MEM_OBJECT_DATA_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("MEM_OBJECT_DATA")(st);
		}

	pragma(inline, true)
	int sk_MEM_OBJECT_DATA_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("MEM_OBJECT_DATA")(st);
		}

	pragma(inline, true)
	auto sk_MEM_OBJECT_DATA_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("MEM_OBJECT_DATA")(st, i);
		}

	pragma(inline, true)
	void* sk_MEM_OBJECT_DATA_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("MEM_OBJECT_DATA")(st, i, val);
		}

	pragma(inline, true)
	void sk_MEM_OBJECT_DATA_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("MEM_OBJECT_DATA")(st);
		}

	pragma(inline, true)
	int sk_MEM_OBJECT_DATA_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("MEM_OBJECT_DATA")(st, val);
		}

	pragma(inline, true)
	int sk_MEM_OBJECT_DATA_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("MEM_OBJECT_DATA")(st, val);
		}

	pragma(inline, true)
	int sk_MEM_OBJECT_DATA_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("MEM_OBJECT_DATA")(st, val);
		}

	pragma(inline, true)
	int sk_MEM_OBJECT_DATA_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("MEM_OBJECT_DATA")(st, val);
		}

	pragma(inline, true)
	auto sk_MEM_OBJECT_DATA_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("MEM_OBJECT_DATA")(st, i);
		}

	pragma(inline, true)
	auto sk_MEM_OBJECT_DATA_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("MEM_OBJECT_DATA")(st, ptr_);
		}

	pragma(inline, true)
	int sk_MEM_OBJECT_DATA_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("MEM_OBJECT_DATA")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_MEM_OBJECT_DATA_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("MEM_OBJECT_DATA")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_MEM_OBJECT_DATA_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("MEM_OBJECT_DATA")(st);
		}

	pragma(inline, true)
	void sk_MEM_OBJECT_DATA_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("MEM_OBJECT_DATA")(st, free_func);
		}

	pragma(inline, true)
	auto sk_MEM_OBJECT_DATA_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("MEM_OBJECT_DATA")(st);
		}

	pragma(inline, true)
	auto sk_MEM_OBJECT_DATA_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("MEM_OBJECT_DATA")(st);
		}

	pragma(inline, true)
	void sk_MEM_OBJECT_DATA_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("MEM_OBJECT_DATA")(st);
		}

	pragma(inline, true)
	int sk_MEM_OBJECT_DATA_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("MEM_OBJECT_DATA")(st);
		}
}

version (none) {
	pragma(inline, true)
	auto sk_MIME_HEADER_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("MIME_HEADER")(cmp);
		}

	pragma(inline, true)
	auto sk_MIME_HEADER_new_null()

		do
		{
			return .SKM_sk_new_null!("MIME_HEADER")();
		}

	pragma(inline, true)
	void sk_MIME_HEADER_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("MIME_HEADER")(st);
		}

	pragma(inline, true)
	int sk_MIME_HEADER_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("MIME_HEADER")(st);
		}

	pragma(inline, true)
	auto sk_MIME_HEADER_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("MIME_HEADER")(st, i);
		}

	pragma(inline, true)
	void* sk_MIME_HEADER_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("MIME_HEADER")(st, i, val);
		}

	pragma(inline, true)
	void sk_MIME_HEADER_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("MIME_HEADER")(st);
		}

	pragma(inline, true)
	int sk_MIME_HEADER_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("MIME_HEADER")(st, val);
		}

	pragma(inline, true)
	int sk_MIME_HEADER_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("MIME_HEADER")(st, val);
		}

	pragma(inline, true)
	int sk_MIME_HEADER_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("MIME_HEADER")(st, val);
		}

	pragma(inline, true)
	int sk_MIME_HEADER_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("MIME_HEADER")(st, val);
		}

	pragma(inline, true)
	auto sk_MIME_HEADER_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("MIME_HEADER")(st, i);
		}

	pragma(inline, true)
	auto sk_MIME_HEADER_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("MIME_HEADER")(st, ptr_);
		}

	pragma(inline, true)
	int sk_MIME_HEADER_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("MIME_HEADER")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_MIME_HEADER_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("MIME_HEADER")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_MIME_HEADER_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("MIME_HEADER")(st);
		}

	pragma(inline, true)
	void sk_MIME_HEADER_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("MIME_HEADER")(st, free_func);
		}

	pragma(inline, true)
	auto sk_MIME_HEADER_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("MIME_HEADER")(st);
		}

	pragma(inline, true)
	auto sk_MIME_HEADER_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("MIME_HEADER")(st);
		}

	pragma(inline, true)
	void sk_MIME_HEADER_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("MIME_HEADER")(st);
		}

	pragma(inline, true)
	int sk_MIME_HEADER_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("MIME_HEADER")(st);
		}
}

version (none) {
	pragma(inline, true)
	auto sk_MIME_PARAM_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("MIME_PARAM")(cmp);
		}

	pragma(inline, true)
	auto sk_MIME_PARAM_new_null()

		do
		{
			return .SKM_sk_new_null!("MIME_PARAM")();
		}

	pragma(inline, true)
	void sk_MIME_PARAM_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("MIME_PARAM")(st);
		}

	pragma(inline, true)
	int sk_MIME_PARAM_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("MIME_PARAM")(st);
		}

	pragma(inline, true)
	auto sk_MIME_PARAM_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("MIME_PARAM")(st, i);
		}

	pragma(inline, true)
	void* sk_MIME_PARAM_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("MIME_PARAM")(st, i, val);
		}

	pragma(inline, true)
	void sk_MIME_PARAM_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("MIME_PARAM")(st);
		}

	pragma(inline, true)
	int sk_MIME_PARAM_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("MIME_PARAM")(st, val);
		}

	pragma(inline, true)
	int sk_MIME_PARAM_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("MIME_PARAM")(st, val);
		}

	pragma(inline, true)
	int sk_MIME_PARAM_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("MIME_PARAM")(st, val);
		}

	pragma(inline, true)
	int sk_MIME_PARAM_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("MIME_PARAM")(st, val);
		}

	pragma(inline, true)
	auto sk_MIME_PARAM_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("MIME_PARAM")(st, i);
		}

	pragma(inline, true)
	auto sk_MIME_PARAM_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("MIME_PARAM")(st, ptr_);
		}

	pragma(inline, true)
	int sk_MIME_PARAM_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("MIME_PARAM")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_MIME_PARAM_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("MIME_PARAM")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_MIME_PARAM_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("MIME_PARAM")(st);
		}

	pragma(inline, true)
	void sk_MIME_PARAM_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("MIME_PARAM")(st, free_func);
		}

	pragma(inline, true)
	auto sk_MIME_PARAM_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("MIME_PARAM")(st);
		}

	pragma(inline, true)
	auto sk_MIME_PARAM_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("MIME_PARAM")(st);
		}

	pragma(inline, true)
	void sk_MIME_PARAM_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("MIME_PARAM")(st);
		}

	pragma(inline, true)
	int sk_MIME_PARAM_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("MIME_PARAM")(st);
		}
}

version (none) {
	pragma(inline, true)
	auto sk_NAME_FUNCS_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("NAME_FUNCS")(cmp);
		}

	pragma(inline, true)
	auto sk_NAME_FUNCS_new_null()

		do
		{
			return .SKM_sk_new_null!("NAME_FUNCS")();
		}

	pragma(inline, true)
	void sk_NAME_FUNCS_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("NAME_FUNCS")(st);
		}

	pragma(inline, true)
	int sk_NAME_FUNCS_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("NAME_FUNCS")(st);
		}

	pragma(inline, true)
	auto sk_NAME_FUNCS_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("NAME_FUNCS")(st, i);
		}

	pragma(inline, true)
	void* sk_NAME_FUNCS_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("NAME_FUNCS")(st, i, val);
		}

	pragma(inline, true)
	void sk_NAME_FUNCS_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("NAME_FUNCS")(st);
		}

	pragma(inline, true)
	int sk_NAME_FUNCS_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("NAME_FUNCS")(st, val);
		}

	pragma(inline, true)
	int sk_NAME_FUNCS_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("NAME_FUNCS")(st, val);
		}

	pragma(inline, true)
	int sk_NAME_FUNCS_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("NAME_FUNCS")(st, val);
		}

	pragma(inline, true)
	int sk_NAME_FUNCS_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("NAME_FUNCS")(st, val);
		}

	pragma(inline, true)
	auto sk_NAME_FUNCS_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("NAME_FUNCS")(st, i);
		}

	pragma(inline, true)
	auto sk_NAME_FUNCS_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("NAME_FUNCS")(st, ptr_);
		}

	pragma(inline, true)
	int sk_NAME_FUNCS_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("NAME_FUNCS")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_NAME_FUNCS_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("NAME_FUNCS")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_NAME_FUNCS_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("NAME_FUNCS")(st);
		}

	pragma(inline, true)
	void sk_NAME_FUNCS_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("NAME_FUNCS")(st, free_func);
		}

	pragma(inline, true)
	auto sk_NAME_FUNCS_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("NAME_FUNCS")(st);
		}

	pragma(inline, true)
	auto sk_NAME_FUNCS_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("NAME_FUNCS")(st);
		}

	pragma(inline, true)
	void sk_NAME_FUNCS_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("NAME_FUNCS")(st);
		}

	pragma(inline, true)
	int sk_NAME_FUNCS_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("NAME_FUNCS")(st);
		}
}

pragma(inline, true)
auto sk_OCSP_CERTID_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("OCSP_CERTID")(cmp);
	}

pragma(inline, true)
auto sk_OCSP_CERTID_new_null()

	do
	{
		return .SKM_sk_new_null!("OCSP_CERTID")();
	}

pragma(inline, true)
void sk_OCSP_CERTID_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("OCSP_CERTID")(st);
	}

pragma(inline, true)
int sk_OCSP_CERTID_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("OCSP_CERTID")(st);
	}

pragma(inline, true)
auto sk_OCSP_CERTID_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("OCSP_CERTID")(st, i);
	}

pragma(inline, true)
void* sk_OCSP_CERTID_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("OCSP_CERTID")(st, i, val);
	}

pragma(inline, true)
void sk_OCSP_CERTID_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("OCSP_CERTID")(st);
	}

pragma(inline, true)
int sk_OCSP_CERTID_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("OCSP_CERTID")(st, val);
	}

pragma(inline, true)
int sk_OCSP_CERTID_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("OCSP_CERTID")(st, val);
	}

pragma(inline, true)
int sk_OCSP_CERTID_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("OCSP_CERTID")(st, val);
	}

pragma(inline, true)
int sk_OCSP_CERTID_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("OCSP_CERTID")(st, val);
	}

pragma(inline, true)
auto sk_OCSP_CERTID_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("OCSP_CERTID")(st, i);
	}

pragma(inline, true)
auto sk_OCSP_CERTID_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("OCSP_CERTID")(st, ptr_);
	}

pragma(inline, true)
int sk_OCSP_CERTID_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("OCSP_CERTID")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_OCSP_CERTID_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("OCSP_CERTID")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_OCSP_CERTID_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("OCSP_CERTID")(st);
	}

pragma(inline, true)
void sk_OCSP_CERTID_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("OCSP_CERTID")(st, free_func);
	}

pragma(inline, true)
auto sk_OCSP_CERTID_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("OCSP_CERTID")(st);
	}

pragma(inline, true)
auto sk_OCSP_CERTID_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("OCSP_CERTID")(st);
	}

pragma(inline, true)
void sk_OCSP_CERTID_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("OCSP_CERTID")(st);
	}

pragma(inline, true)
int sk_OCSP_CERTID_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("OCSP_CERTID")(st);
	}

pragma(inline, true)
auto sk_OCSP_ONEREQ_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("OCSP_ONEREQ")(cmp);
	}

pragma(inline, true)
auto sk_OCSP_ONEREQ_new_null()

	do
	{
		return .SKM_sk_new_null!("OCSP_ONEREQ")();
	}

pragma(inline, true)
void sk_OCSP_ONEREQ_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("OCSP_ONEREQ")(st);
	}

pragma(inline, true)
int sk_OCSP_ONEREQ_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("OCSP_ONEREQ")(st);
	}

pragma(inline, true)
auto sk_OCSP_ONEREQ_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("OCSP_ONEREQ")(st, i);
	}

pragma(inline, true)
void* sk_OCSP_ONEREQ_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("OCSP_ONEREQ")(st, i, val);
	}

pragma(inline, true)
void sk_OCSP_ONEREQ_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("OCSP_ONEREQ")(st);
	}

pragma(inline, true)
int sk_OCSP_ONEREQ_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("OCSP_ONEREQ")(st, val);
	}

pragma(inline, true)
int sk_OCSP_ONEREQ_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("OCSP_ONEREQ")(st, val);
	}

pragma(inline, true)
int sk_OCSP_ONEREQ_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("OCSP_ONEREQ")(st, val);
	}

pragma(inline, true)
int sk_OCSP_ONEREQ_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("OCSP_ONEREQ")(st, val);
	}

pragma(inline, true)
auto sk_OCSP_ONEREQ_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("OCSP_ONEREQ")(st, i);
	}

pragma(inline, true)
auto sk_OCSP_ONEREQ_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("OCSP_ONEREQ")(st, ptr_);
	}

pragma(inline, true)
int sk_OCSP_ONEREQ_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("OCSP_ONEREQ")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_OCSP_ONEREQ_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("OCSP_ONEREQ")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_OCSP_ONEREQ_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("OCSP_ONEREQ")(st);
	}

pragma(inline, true)
void sk_OCSP_ONEREQ_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("OCSP_ONEREQ")(st, free_func);
	}

pragma(inline, true)
auto sk_OCSP_ONEREQ_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("OCSP_ONEREQ")(st);
	}

pragma(inline, true)
auto sk_OCSP_ONEREQ_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("OCSP_ONEREQ")(st);
	}

pragma(inline, true)
void sk_OCSP_ONEREQ_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("OCSP_ONEREQ")(st);
	}

pragma(inline, true)
int sk_OCSP_ONEREQ_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("OCSP_ONEREQ")(st);
	}

pragma(inline, true)
auto sk_OCSP_RESPID_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("OCSP_RESPID")(cmp);
	}

pragma(inline, true)
auto sk_OCSP_RESPID_new_null()

	do
	{
		return .SKM_sk_new_null!("OCSP_RESPID")();
	}

pragma(inline, true)
void sk_OCSP_RESPID_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("OCSP_RESPID")(st);
	}

pragma(inline, true)
int sk_OCSP_RESPID_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("OCSP_RESPID")(st);
	}

pragma(inline, true)
auto sk_OCSP_RESPID_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("OCSP_RESPID")(st, i);
	}

pragma(inline, true)
void* sk_OCSP_RESPID_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("OCSP_RESPID")(st, i, val);
	}

pragma(inline, true)
void sk_OCSP_RESPID_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("OCSP_RESPID")(st);
	}

pragma(inline, true)
int sk_OCSP_RESPID_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("OCSP_RESPID")(st, val);
	}

pragma(inline, true)
int sk_OCSP_RESPID_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("OCSP_RESPID")(st, val);
	}

pragma(inline, true)
int sk_OCSP_RESPID_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("OCSP_RESPID")(st, val);
	}

pragma(inline, true)
int sk_OCSP_RESPID_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("OCSP_RESPID")(st, val);
	}

pragma(inline, true)
auto sk_OCSP_RESPID_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("OCSP_RESPID")(st, i);
	}

pragma(inline, true)
auto sk_OCSP_RESPID_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("OCSP_RESPID")(st, ptr_);
	}

pragma(inline, true)
int sk_OCSP_RESPID_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("OCSP_RESPID")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_OCSP_RESPID_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("OCSP_RESPID")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_OCSP_RESPID_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("OCSP_RESPID")(st);
	}

pragma(inline, true)
void sk_OCSP_RESPID_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("OCSP_RESPID")(st, free_func);
	}

pragma(inline, true)
auto sk_OCSP_RESPID_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("OCSP_RESPID")(st);
	}

pragma(inline, true)
auto sk_OCSP_RESPID_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("OCSP_RESPID")(st);
	}

pragma(inline, true)
void sk_OCSP_RESPID_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("OCSP_RESPID")(st);
	}

pragma(inline, true)
int sk_OCSP_RESPID_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("OCSP_RESPID")(st);
	}

pragma(inline, true)
auto sk_OCSP_SINGLERESP_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("OCSP_SINGLERESP")(cmp);
	}

pragma(inline, true)
auto sk_OCSP_SINGLERESP_new_null()

	do
	{
		return .SKM_sk_new_null!("OCSP_SINGLERESP")();
	}

pragma(inline, true)
void sk_OCSP_SINGLERESP_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("OCSP_SINGLERESP")(st);
	}

pragma(inline, true)
int sk_OCSP_SINGLERESP_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("OCSP_SINGLERESP")(st);
	}

pragma(inline, true)
auto sk_OCSP_SINGLERESP_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("OCSP_SINGLERESP")(st, i);
	}

pragma(inline, true)
void* sk_OCSP_SINGLERESP_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("OCSP_SINGLERESP")(st, i, val);
	}

pragma(inline, true)
void sk_OCSP_SINGLERESP_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("OCSP_SINGLERESP")(st);
	}

pragma(inline, true)
int sk_OCSP_SINGLERESP_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("OCSP_SINGLERESP")(st, val);
	}

pragma(inline, true)
int sk_OCSP_SINGLERESP_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("OCSP_SINGLERESP")(st, val);
	}

pragma(inline, true)
int sk_OCSP_SINGLERESP_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("OCSP_SINGLERESP")(st, val);
	}

pragma(inline, true)
int sk_OCSP_SINGLERESP_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("OCSP_SINGLERESP")(st, val);
	}

pragma(inline, true)
auto sk_OCSP_SINGLERESP_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("OCSP_SINGLERESP")(st, i);
	}

pragma(inline, true)
auto sk_OCSP_SINGLERESP_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("OCSP_SINGLERESP")(st, ptr_);
	}

pragma(inline, true)
int sk_OCSP_SINGLERESP_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("OCSP_SINGLERESP")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_OCSP_SINGLERESP_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("OCSP_SINGLERESP")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_OCSP_SINGLERESP_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("OCSP_SINGLERESP")(st);
	}

pragma(inline, true)
void sk_OCSP_SINGLERESP_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("OCSP_SINGLERESP")(st, free_func);
	}

pragma(inline, true)
auto sk_OCSP_SINGLERESP_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("OCSP_SINGLERESP")(st);
	}

pragma(inline, true)
auto sk_OCSP_SINGLERESP_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("OCSP_SINGLERESP")(st);
	}

pragma(inline, true)
void sk_OCSP_SINGLERESP_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("OCSP_SINGLERESP")(st);
	}

pragma(inline, true)
int sk_OCSP_SINGLERESP_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("OCSP_SINGLERESP")(st);
	}

pragma(inline, true)
auto sk_PKCS12_SAFEBAG_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("PKCS12_SAFEBAG")(cmp);
	}

pragma(inline, true)
auto sk_PKCS12_SAFEBAG_new_null()

	do
	{
		return .SKM_sk_new_null!("PKCS12_SAFEBAG")();
	}

pragma(inline, true)
void sk_PKCS12_SAFEBAG_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("PKCS12_SAFEBAG")(st);
	}

pragma(inline, true)
int sk_PKCS12_SAFEBAG_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("PKCS12_SAFEBAG")(st);
	}

pragma(inline, true)
auto sk_PKCS12_SAFEBAG_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("PKCS12_SAFEBAG")(st, i);
	}

pragma(inline, true)
void* sk_PKCS12_SAFEBAG_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("PKCS12_SAFEBAG")(st, i, val);
	}

pragma(inline, true)
void sk_PKCS12_SAFEBAG_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("PKCS12_SAFEBAG")(st);
	}

pragma(inline, true)
int sk_PKCS12_SAFEBAG_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("PKCS12_SAFEBAG")(st, val);
	}

pragma(inline, true)
int sk_PKCS12_SAFEBAG_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("PKCS12_SAFEBAG")(st, val);
	}

pragma(inline, true)
int sk_PKCS12_SAFEBAG_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("PKCS12_SAFEBAG")(st, val);
	}

pragma(inline, true)
int sk_PKCS12_SAFEBAG_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("PKCS12_SAFEBAG")(st, val);
	}

pragma(inline, true)
auto sk_PKCS12_SAFEBAG_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("PKCS12_SAFEBAG")(st, i);
	}

pragma(inline, true)
auto sk_PKCS12_SAFEBAG_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("PKCS12_SAFEBAG")(st, ptr_);
	}

pragma(inline, true)
int sk_PKCS12_SAFEBAG_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("PKCS12_SAFEBAG")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_PKCS12_SAFEBAG_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("PKCS12_SAFEBAG")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_PKCS12_SAFEBAG_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("PKCS12_SAFEBAG")(st);
	}

pragma(inline, true)
void sk_PKCS12_SAFEBAG_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("PKCS12_SAFEBAG")(st, free_func);
	}

pragma(inline, true)
auto sk_PKCS12_SAFEBAG_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("PKCS12_SAFEBAG")(st);
	}

pragma(inline, true)
auto sk_PKCS12_SAFEBAG_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("PKCS12_SAFEBAG")(st);
	}

pragma(inline, true)
void sk_PKCS12_SAFEBAG_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("PKCS12_SAFEBAG")(st);
	}

pragma(inline, true)
int sk_PKCS12_SAFEBAG_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("PKCS12_SAFEBAG")(st);
	}

pragma(inline, true)
auto sk_PKCS7_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("PKCS7")(cmp);
	}

pragma(inline, true)
auto sk_PKCS7_new_null()

	do
	{
		return .SKM_sk_new_null!("PKCS7")();
	}

pragma(inline, true)
void sk_PKCS7_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("PKCS7")(st);
	}

pragma(inline, true)
int sk_PKCS7_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("PKCS7")(st);
	}

pragma(inline, true)
auto sk_PKCS7_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("PKCS7")(st, i);
	}

pragma(inline, true)
void* sk_PKCS7_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("PKCS7")(st, i, val);
	}

pragma(inline, true)
void sk_PKCS7_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("PKCS7")(st);
	}

pragma(inline, true)
int sk_PKCS7_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("PKCS7")(st, val);
	}

pragma(inline, true)
int sk_PKCS7_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("PKCS7")(st, val);
	}

pragma(inline, true)
int sk_PKCS7_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("PKCS7")(st, val);
	}

pragma(inline, true)
int sk_PKCS7_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("PKCS7")(st, val);
	}

pragma(inline, true)
auto sk_PKCS7_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("PKCS7")(st, i);
	}

pragma(inline, true)
auto sk_PKCS7_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("PKCS7")(st, ptr_);
	}

pragma(inline, true)
int sk_PKCS7_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("PKCS7")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_PKCS7_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("PKCS7")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_PKCS7_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("PKCS7")(st);
	}

pragma(inline, true)
void sk_PKCS7_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("PKCS7")(st, free_func);
	}

pragma(inline, true)
auto sk_PKCS7_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("PKCS7")(st);
	}

pragma(inline, true)
auto sk_PKCS7_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("PKCS7")(st);
	}

pragma(inline, true)
void sk_PKCS7_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("PKCS7")(st);
	}

pragma(inline, true)
int sk_PKCS7_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("PKCS7")(st);
	}

pragma(inline, true)
auto sk_PKCS7_RECIP_INFO_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("PKCS7_RECIP_INFO")(cmp);
	}

pragma(inline, true)
auto sk_PKCS7_RECIP_INFO_new_null()

	do
	{
		return .SKM_sk_new_null!("PKCS7_RECIP_INFO")();
	}

pragma(inline, true)
void sk_PKCS7_RECIP_INFO_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("PKCS7_RECIP_INFO")(st);
	}

pragma(inline, true)
int sk_PKCS7_RECIP_INFO_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("PKCS7_RECIP_INFO")(st);
	}

pragma(inline, true)
auto sk_PKCS7_RECIP_INFO_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("PKCS7_RECIP_INFO")(st, i);
	}

pragma(inline, true)
void* sk_PKCS7_RECIP_INFO_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("PKCS7_RECIP_INFO")(st, i, val);
	}

pragma(inline, true)
void sk_PKCS7_RECIP_INFO_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("PKCS7_RECIP_INFO")(st);
	}

pragma(inline, true)
int sk_PKCS7_RECIP_INFO_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("PKCS7_RECIP_INFO")(st, val);
	}

pragma(inline, true)
int sk_PKCS7_RECIP_INFO_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("PKCS7_RECIP_INFO")(st, val);
	}

pragma(inline, true)
int sk_PKCS7_RECIP_INFO_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("PKCS7_RECIP_INFO")(st, val);
	}

pragma(inline, true)
int sk_PKCS7_RECIP_INFO_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("PKCS7_RECIP_INFO")(st, val);
	}

pragma(inline, true)
auto sk_PKCS7_RECIP_INFO_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("PKCS7_RECIP_INFO")(st, i);
	}

pragma(inline, true)
auto sk_PKCS7_RECIP_INFO_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("PKCS7_RECIP_INFO")(st, ptr_);
	}

pragma(inline, true)
int sk_PKCS7_RECIP_INFO_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("PKCS7_RECIP_INFO")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_PKCS7_RECIP_INFO_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("PKCS7_RECIP_INFO")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_PKCS7_RECIP_INFO_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("PKCS7_RECIP_INFO")(st);
	}

pragma(inline, true)
void sk_PKCS7_RECIP_INFO_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("PKCS7_RECIP_INFO")(st, free_func);
	}

pragma(inline, true)
auto sk_PKCS7_RECIP_INFO_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("PKCS7_RECIP_INFO")(st);
	}

pragma(inline, true)
auto sk_PKCS7_RECIP_INFO_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("PKCS7_RECIP_INFO")(st);
	}

pragma(inline, true)
void sk_PKCS7_RECIP_INFO_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("PKCS7_RECIP_INFO")(st);
	}

pragma(inline, true)
int sk_PKCS7_RECIP_INFO_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("PKCS7_RECIP_INFO")(st);
	}

pragma(inline, true)
auto sk_PKCS7_SIGNER_INFO_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("PKCS7_SIGNER_INFO")(cmp);
	}

pragma(inline, true)
auto sk_PKCS7_SIGNER_INFO_new_null()

	do
	{
		return .SKM_sk_new_null!("PKCS7_SIGNER_INFO")();
	}

pragma(inline, true)
void sk_PKCS7_SIGNER_INFO_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("PKCS7_SIGNER_INFO")(st);
	}

pragma(inline, true)
int sk_PKCS7_SIGNER_INFO_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("PKCS7_SIGNER_INFO")(st);
	}

pragma(inline, true)
auto sk_PKCS7_SIGNER_INFO_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("PKCS7_SIGNER_INFO")(st, i);
	}

pragma(inline, true)
void* sk_PKCS7_SIGNER_INFO_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("PKCS7_SIGNER_INFO")(st, i, val);
	}

pragma(inline, true)
void sk_PKCS7_SIGNER_INFO_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("PKCS7_SIGNER_INFO")(st);
	}

pragma(inline, true)
int sk_PKCS7_SIGNER_INFO_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("PKCS7_SIGNER_INFO")(st, val);
	}

pragma(inline, true)
int sk_PKCS7_SIGNER_INFO_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("PKCS7_SIGNER_INFO")(st, val);
	}

pragma(inline, true)
int sk_PKCS7_SIGNER_INFO_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("PKCS7_SIGNER_INFO")(st, val);
	}

pragma(inline, true)
int sk_PKCS7_SIGNER_INFO_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("PKCS7_SIGNER_INFO")(st, val);
	}

pragma(inline, true)
auto sk_PKCS7_SIGNER_INFO_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("PKCS7_SIGNER_INFO")(st, i);
	}

pragma(inline, true)
auto sk_PKCS7_SIGNER_INFO_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("PKCS7_SIGNER_INFO")(st, ptr_);
	}

pragma(inline, true)
int sk_PKCS7_SIGNER_INFO_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("PKCS7_SIGNER_INFO")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_PKCS7_SIGNER_INFO_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("PKCS7_SIGNER_INFO")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_PKCS7_SIGNER_INFO_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("PKCS7_SIGNER_INFO")(st);
	}

pragma(inline, true)
void sk_PKCS7_SIGNER_INFO_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("PKCS7_SIGNER_INFO")(st, free_func);
	}

pragma(inline, true)
auto sk_PKCS7_SIGNER_INFO_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("PKCS7_SIGNER_INFO")(st);
	}

pragma(inline, true)
auto sk_PKCS7_SIGNER_INFO_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("PKCS7_SIGNER_INFO")(st);
	}

pragma(inline, true)
void sk_PKCS7_SIGNER_INFO_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("PKCS7_SIGNER_INFO")(st);
	}

pragma(inline, true)
int sk_PKCS7_SIGNER_INFO_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("PKCS7_SIGNER_INFO")(st);
	}

pragma(inline, true)
auto sk_POLICYINFO_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("POLICYINFO")(cmp);
	}

pragma(inline, true)
auto sk_POLICYINFO_new_null()

	do
	{
		return .SKM_sk_new_null!("POLICYINFO")();
	}

pragma(inline, true)
void sk_POLICYINFO_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("POLICYINFO")(st);
	}

pragma(inline, true)
int sk_POLICYINFO_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("POLICYINFO")(st);
	}

pragma(inline, true)
auto sk_POLICYINFO_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("POLICYINFO")(st, i);
	}

pragma(inline, true)
void* sk_POLICYINFO_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("POLICYINFO")(st, i, val);
	}

pragma(inline, true)
void sk_POLICYINFO_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("POLICYINFO")(st);
	}

pragma(inline, true)
int sk_POLICYINFO_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("POLICYINFO")(st, val);
	}

pragma(inline, true)
int sk_POLICYINFO_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("POLICYINFO")(st, val);
	}

pragma(inline, true)
int sk_POLICYINFO_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("POLICYINFO")(st, val);
	}

pragma(inline, true)
int sk_POLICYINFO_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("POLICYINFO")(st, val);
	}

pragma(inline, true)
auto sk_POLICYINFO_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("POLICYINFO")(st, i);
	}

pragma(inline, true)
auto sk_POLICYINFO_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("POLICYINFO")(st, ptr_);
	}

pragma(inline, true)
int sk_POLICYINFO_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("POLICYINFO")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_POLICYINFO_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("POLICYINFO")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_POLICYINFO_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("POLICYINFO")(st);
	}

pragma(inline, true)
void sk_POLICYINFO_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("POLICYINFO")(st, free_func);
	}

pragma(inline, true)
auto sk_POLICYINFO_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("POLICYINFO")(st);
	}

pragma(inline, true)
auto sk_POLICYINFO_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("POLICYINFO")(st);
	}

pragma(inline, true)
void sk_POLICYINFO_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("POLICYINFO")(st);
	}

pragma(inline, true)
int sk_POLICYINFO_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("POLICYINFO")(st);
	}

pragma(inline, true)
auto sk_POLICYQUALINFO_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("POLICYQUALINFO")(cmp);
	}

pragma(inline, true)
auto sk_POLICYQUALINFO_new_null()

	do
	{
		return .SKM_sk_new_null!("POLICYQUALINFO")();
	}

pragma(inline, true)
void sk_POLICYQUALINFO_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("POLICYQUALINFO")(st);
	}

pragma(inline, true)
int sk_POLICYQUALINFO_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("POLICYQUALINFO")(st);
	}

pragma(inline, true)
auto sk_POLICYQUALINFO_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("POLICYQUALINFO")(st, i);
	}

pragma(inline, true)
void* sk_POLICYQUALINFO_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("POLICYQUALINFO")(st, i, val);
	}

pragma(inline, true)
void sk_POLICYQUALINFO_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("POLICYQUALINFO")(st);
	}

pragma(inline, true)
int sk_POLICYQUALINFO_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("POLICYQUALINFO")(st, val);
	}

pragma(inline, true)
int sk_POLICYQUALINFO_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("POLICYQUALINFO")(st, val);
	}

pragma(inline, true)
int sk_POLICYQUALINFO_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("POLICYQUALINFO")(st, val);
	}

pragma(inline, true)
int sk_POLICYQUALINFO_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("POLICYQUALINFO")(st, val);
	}

pragma(inline, true)
auto sk_POLICYQUALINFO_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("POLICYQUALINFO")(st, i);
	}

pragma(inline, true)
auto sk_POLICYQUALINFO_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("POLICYQUALINFO")(st, ptr_);
	}

pragma(inline, true)
int sk_POLICYQUALINFO_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("POLICYQUALINFO")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_POLICYQUALINFO_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("POLICYQUALINFO")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_POLICYQUALINFO_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("POLICYQUALINFO")(st);
	}

pragma(inline, true)
void sk_POLICYQUALINFO_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("POLICYQUALINFO")(st, free_func);
	}

pragma(inline, true)
auto sk_POLICYQUALINFO_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("POLICYQUALINFO")(st);
	}

pragma(inline, true)
auto sk_POLICYQUALINFO_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("POLICYQUALINFO")(st);
	}

pragma(inline, true)
void sk_POLICYQUALINFO_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("POLICYQUALINFO")(st);
	}

pragma(inline, true)
int sk_POLICYQUALINFO_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("POLICYQUALINFO")(st);
	}

pragma(inline, true)
auto sk_POLICY_MAPPING_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("POLICY_MAPPING")(cmp);
	}

pragma(inline, true)
auto sk_POLICY_MAPPING_new_null()

	do
	{
		return .SKM_sk_new_null!("POLICY_MAPPING")();
	}

pragma(inline, true)
void sk_POLICY_MAPPING_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("POLICY_MAPPING")(st);
	}

pragma(inline, true)
int sk_POLICY_MAPPING_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("POLICY_MAPPING")(st);
	}

pragma(inline, true)
auto sk_POLICY_MAPPING_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("POLICY_MAPPING")(st, i);
	}

pragma(inline, true)
void* sk_POLICY_MAPPING_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("POLICY_MAPPING")(st, i, val);
	}

pragma(inline, true)
void sk_POLICY_MAPPING_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("POLICY_MAPPING")(st);
	}

pragma(inline, true)
int sk_POLICY_MAPPING_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("POLICY_MAPPING")(st, val);
	}

pragma(inline, true)
int sk_POLICY_MAPPING_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("POLICY_MAPPING")(st, val);
	}

pragma(inline, true)
int sk_POLICY_MAPPING_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("POLICY_MAPPING")(st, val);
	}

pragma(inline, true)
int sk_POLICY_MAPPING_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("POLICY_MAPPING")(st, val);
	}

pragma(inline, true)
auto sk_POLICY_MAPPING_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("POLICY_MAPPING")(st, i);
	}

pragma(inline, true)
auto sk_POLICY_MAPPING_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("POLICY_MAPPING")(st, ptr_);
	}

pragma(inline, true)
int sk_POLICY_MAPPING_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("POLICY_MAPPING")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_POLICY_MAPPING_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("POLICY_MAPPING")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_POLICY_MAPPING_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("POLICY_MAPPING")(st);
	}

pragma(inline, true)
void sk_POLICY_MAPPING_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("POLICY_MAPPING")(st, free_func);
	}

pragma(inline, true)
auto sk_POLICY_MAPPING_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("POLICY_MAPPING")(st);
	}

pragma(inline, true)
auto sk_POLICY_MAPPING_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("POLICY_MAPPING")(st);
	}

pragma(inline, true)
void sk_POLICY_MAPPING_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("POLICY_MAPPING")(st);
	}

pragma(inline, true)
int sk_POLICY_MAPPING_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("POLICY_MAPPING")(st);
	}

version (OPENSSL_NO_CT) {
} else {
	pragma(inline, true)
	auto sk_SCT_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("SCT")(cmp);
		}

	pragma(inline, true)
	auto sk_SCT_new_null()

		do
		{
			return .SKM_sk_new_null!("SCT")();
		}

	pragma(inline, true)
	void sk_SCT_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("SCT")(st);
		}

	pragma(inline, true)
	int sk_SCT_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("SCT")(st);
		}

	pragma(inline, true)
	auto sk_SCT_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("SCT")(st, i);
		}

	pragma(inline, true)
	void* sk_SCT_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("SCT")(st, i, val);
		}

	pragma(inline, true)
	void sk_SCT_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("SCT")(st);
		}

	pragma(inline, true)
	int sk_SCT_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("SCT")(st, val);
		}

	pragma(inline, true)
	int sk_SCT_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("SCT")(st, val);
		}

	pragma(inline, true)
	int sk_SCT_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("SCT")(st, val);
		}

	pragma(inline, true)
	int sk_SCT_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("SCT")(st, val);
		}

	pragma(inline, true)
	auto sk_SCT_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("SCT")(st, i);
		}


	pragma(inline, true)
	auto sk_SCT_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("SCT")(st, ptr);
		}


	pragma(inline, true)
	int sk_SCT_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("SCT")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_SCT_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("SCT")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_SCT_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("SCT")(st);
		}

	pragma(inline, true)
	void sk_SCT_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("SCT")(st, free_func);
		}

	pragma(inline, true)
	auto sk_SCT_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("SCT")(st);
		}

	pragma(inline, true)
	auto sk_SCT_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("SCT")(st);
		}

	pragma(inline, true)
	void sk_SCT_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("SCT")(st);
		}

	pragma(inline, true)
	int sk_SCT_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("SCT")(st);
		}
}

pragma(inline, true)
auto sk_SRTP_PROTECTION_PROFILE_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("SRTP_PROTECTION_PROFILE")(cmp);
	}

pragma(inline, true)
auto sk_SRTP_PROTECTION_PROFILE_new_null()

	do
	{
		return .SKM_sk_new_null!("SRTP_PROTECTION_PROFILE")();
	}

pragma(inline, true)
void sk_SRTP_PROTECTION_PROFILE_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("SRTP_PROTECTION_PROFILE")(st);
	}

pragma(inline, true)
int sk_SRTP_PROTECTION_PROFILE_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("SRTP_PROTECTION_PROFILE")(st);
	}

pragma(inline, true)
auto sk_SRTP_PROTECTION_PROFILE_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("SRTP_PROTECTION_PROFILE")(st, i);
	}

pragma(inline, true)
void* sk_SRTP_PROTECTION_PROFILE_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("SRTP_PROTECTION_PROFILE")(st, i, val);
	}

pragma(inline, true)
void sk_SRTP_PROTECTION_PROFILE_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("SRTP_PROTECTION_PROFILE")(st);
	}

pragma(inline, true)
int sk_SRTP_PROTECTION_PROFILE_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("SRTP_PROTECTION_PROFILE")(st, val);
	}

pragma(inline, true)
int sk_SRTP_PROTECTION_PROFILE_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("SRTP_PROTECTION_PROFILE")(st, val);
	}

pragma(inline, true)
int sk_SRTP_PROTECTION_PROFILE_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("SRTP_PROTECTION_PROFILE")(st, val);
	}

pragma(inline, true)
int sk_SRTP_PROTECTION_PROFILE_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("SRTP_PROTECTION_PROFILE")(st, val);
	}

pragma(inline, true)
auto sk_SRTP_PROTECTION_PROFILE_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("SRTP_PROTECTION_PROFILE")(st, i);
	}

pragma(inline, true)
auto sk_SRTP_PROTECTION_PROFILE_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("SRTP_PROTECTION_PROFILE")(st, ptr_);
	}

pragma(inline, true)
int sk_SRTP_PROTECTION_PROFILE_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("SRTP_PROTECTION_PROFILE")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_SRTP_PROTECTION_PROFILE_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("SRTP_PROTECTION_PROFILE")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_SRTP_PROTECTION_PROFILE_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("SRTP_PROTECTION_PROFILE")(st);
	}

pragma(inline, true)
void sk_SRTP_PROTECTION_PROFILE_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("SRTP_PROTECTION_PROFILE")(st, free_func);
	}

pragma(inline, true)
auto sk_SRTP_PROTECTION_PROFILE_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("SRTP_PROTECTION_PROFILE")(st);
	}

pragma(inline, true)
auto sk_SRTP_PROTECTION_PROFILE_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("SRTP_PROTECTION_PROFILE")(st);
	}

pragma(inline, true)
void sk_SRTP_PROTECTION_PROFILE_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("SRTP_PROTECTION_PROFILE")(st);
	}

pragma(inline, true)
int sk_SRTP_PROTECTION_PROFILE_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("SRTP_PROTECTION_PROFILE")(st);
	}

pragma(inline, true)
auto sk_SSL_CIPHER_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("SSL_CIPHER")(cmp);
	}

pragma(inline, true)
auto sk_SSL_CIPHER_new_null()

	do
	{
		return .SKM_sk_new_null!("SSL_CIPHER")();
	}

pragma(inline, true)
void sk_SSL_CIPHER_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("SSL_CIPHER")(st);
	}

pragma(inline, true)
int sk_SSL_CIPHER_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("SSL_CIPHER")(st);
	}

pragma(inline, true)
auto sk_SSL_CIPHER_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("SSL_CIPHER")(st, i);
	}

pragma(inline, true)
void* sk_SSL_CIPHER_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("SSL_CIPHER")(st, i, val);
	}

pragma(inline, true)
void sk_SSL_CIPHER_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("SSL_CIPHER")(st);
	}

pragma(inline, true)
int sk_SSL_CIPHER_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("SSL_CIPHER")(st, val);
	}

pragma(inline, true)
int sk_SSL_CIPHER_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("SSL_CIPHER")(st, val);
	}

pragma(inline, true)
int sk_SSL_CIPHER_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("SSL_CIPHER")(st, val);
	}

pragma(inline, true)
int sk_SSL_CIPHER_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("SSL_CIPHER")(st, val);
	}

pragma(inline, true)
auto sk_SSL_CIPHER_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("SSL_CIPHER")(st, i);
	}

pragma(inline, true)
auto sk_SSL_CIPHER_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("SSL_CIPHER")(st, ptr_);
	}

pragma(inline, true)
int sk_SSL_CIPHER_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("SSL_CIPHER")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_SSL_CIPHER_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("SSL_CIPHER")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_SSL_CIPHER_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("SSL_CIPHER")(st);
	}

pragma(inline, true)
void sk_SSL_CIPHER_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("SSL_CIPHER")(st, free_func);
	}

pragma(inline, true)
auto sk_SSL_CIPHER_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("SSL_CIPHER")(st);
	}

pragma(inline, true)
auto sk_SSL_CIPHER_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("SSL_CIPHER")(st);
	}

pragma(inline, true)
void sk_SSL_CIPHER_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("SSL_CIPHER")(st);
	}

pragma(inline, true)
int sk_SSL_CIPHER_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("SSL_CIPHER")(st);
	}

version (LIBRESSL_INTERNAL) {
	pragma(inline, true)
	auto sk_SSL_COMP_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("SSL_COMP")(cmp);
		}

	pragma(inline, true)
	auto sk_SSL_COMP_new_null()

		do
		{
			return .SKM_sk_new_null!("SSL_COMP")();
		}

	pragma(inline, true)
	void sk_SSL_COMP_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("SSL_COMP")(st);
		}

	pragma(inline, true)
	int sk_SSL_COMP_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("SSL_COMP")(st);
		}

	pragma(inline, true)
	auto sk_SSL_COMP_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("SSL_COMP")(st, i);
		}

	pragma(inline, true)
	void* sk_SSL_COMP_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("SSL_COMP")(st, i, val);
		}

	pragma(inline, true)
	void sk_SSL_COMP_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("SSL_COMP")(st);
		}

	pragma(inline, true)
	int sk_SSL_COMP_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("SSL_COMP")(st, val);
		}

	pragma(inline, true)
	int sk_SSL_COMP_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("SSL_COMP")(st, val);
		}

	pragma(inline, true)
	int sk_SSL_COMP_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("SSL_COMP")(st, val);
		}

	pragma(inline, true)
	int sk_SSL_COMP_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("SSL_COMP")(st, val);
		}

	pragma(inline, true)
	auto sk_SSL_COMP_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("SSL_COMP")(st, i);
		}

	pragma(inline, true)
	auto sk_SSL_COMP_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("SSL_COMP")(st, ptr_);
		}

	pragma(inline, true)
	int sk_SSL_COMP_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("SSL_COMP")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_SSL_COMP_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("SSL_COMP")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_SSL_COMP_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("SSL_COMP")(st);
		}

	pragma(inline, true)
	void sk_SSL_COMP_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("SSL_COMP")(st, free_func);
		}

	pragma(inline, true)
	auto sk_SSL_COMP_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("SSL_COMP")(st);
		}

	pragma(inline, true)
	auto sk_SSL_COMP_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("SSL_COMP")(st);
		}

	pragma(inline, true)
	void sk_SSL_COMP_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("SSL_COMP")(st);
		}

	pragma(inline, true)
	int sk_SSL_COMP_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("SSL_COMP")(st);
		}
}

version (none) {
	pragma(inline, true)
	auto sk_STACK_OF_X509_NAME_ENTRY_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("STACK_OF_X509_NAME_ENTRY")(cmp);
		}

	pragma(inline, true)
	auto sk_STACK_OF_X509_NAME_ENTRY_new_null()

		do
		{
			return .SKM_sk_new_null!("STACK_OF_X509_NAME_ENTRY")();
		}

	pragma(inline, true)
	void sk_STACK_OF_X509_NAME_ENTRY_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("STACK_OF_X509_NAME_ENTRY")(st);
		}

	pragma(inline, true)
	int sk_STACK_OF_X509_NAME_ENTRY_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("STACK_OF_X509_NAME_ENTRY")(st);
		}

	pragma(inline, true)
	auto sk_STACK_OF_X509_NAME_ENTRY_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("STACK_OF_X509_NAME_ENTRY")(st, i);
		}

	pragma(inline, true)
	void* sk_STACK_OF_X509_NAME_ENTRY_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("STACK_OF_X509_NAME_ENTRY")(st, i, val);
		}

	pragma(inline, true)
	void sk_STACK_OF_X509_NAME_ENTRY_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("STACK_OF_X509_NAME_ENTRY")(st);
		}

	pragma(inline, true)
	int sk_STACK_OF_X509_NAME_ENTRY_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("STACK_OF_X509_NAME_ENTRY")(st, val);
		}

	pragma(inline, true)
	int sk_STACK_OF_X509_NAME_ENTRY_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("STACK_OF_X509_NAME_ENTRY")(st, val);
		}

	pragma(inline, true)
	int sk_STACK_OF_X509_NAME_ENTRY_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("STACK_OF_X509_NAME_ENTRY")(st, val);
		}

	pragma(inline, true)
	int sk_STACK_OF_X509_NAME_ENTRY_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("STACK_OF_X509_NAME_ENTRY")(st, val);
		}

	pragma(inline, true)
	auto sk_STACK_OF_X509_NAME_ENTRY_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("STACK_OF_X509_NAME_ENTRY")(st, i);
		}

	pragma(inline, true)
	auto sk_STACK_OF_X509_NAME_ENTRY_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("STACK_OF_X509_NAME_ENTRY")(st, ptr_);
		}

	pragma(inline, true)
	int sk_STACK_OF_X509_NAME_ENTRY_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("STACK_OF_X509_NAME_ENTRY")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_STACK_OF_X509_NAME_ENTRY_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("STACK_OF_X509_NAME_ENTRY")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_STACK_OF_X509_NAME_ENTRY_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("STACK_OF_X509_NAME_ENTRY")(st);
		}

	pragma(inline, true)
	void sk_STACK_OF_X509_NAME_ENTRY_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("STACK_OF_X509_NAME_ENTRY")(st, free_func);
		}

	pragma(inline, true)
	auto sk_STACK_OF_X509_NAME_ENTRY_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("STACK_OF_X509_NAME_ENTRY")(st);
		}

	pragma(inline, true)
	auto sk_STACK_OF_X509_NAME_ENTRY_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("STACK_OF_X509_NAME_ENTRY")(st);
		}

	pragma(inline, true)
	void sk_STACK_OF_X509_NAME_ENTRY_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("STACK_OF_X509_NAME_ENTRY")(st);
		}

	pragma(inline, true)
	int sk_STACK_OF_X509_NAME_ENTRY_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("STACK_OF_X509_NAME_ENTRY")(st);
		}
}

version (none) {
	pragma(inline, true)
	auto sk_STORE_ATTR_INFO_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("STORE_ATTR_INFO")(cmp);
		}

	pragma(inline, true)
	auto sk_STORE_ATTR_INFO_new_null()

		do
		{
			return .SKM_sk_new_null!("STORE_ATTR_INFO")();
		}

	pragma(inline, true)
	void sk_STORE_ATTR_INFO_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("STORE_ATTR_INFO")(st);
		}

	pragma(inline, true)
	int sk_STORE_ATTR_INFO_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("STORE_ATTR_INFO")(st);
		}

	pragma(inline, true)
	auto sk_STORE_ATTR_INFO_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("STORE_ATTR_INFO")(st, i);
		}

	pragma(inline, true)
	void* sk_STORE_ATTR_INFO_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("STORE_ATTR_INFO")(st, i, val);
		}

	pragma(inline, true)
	void sk_STORE_ATTR_INFO_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("STORE_ATTR_INFO")(st);
		}

	pragma(inline, true)
	int sk_STORE_ATTR_INFO_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("STORE_ATTR_INFO")(st, val);
		}

	pragma(inline, true)
	int sk_STORE_ATTR_INFO_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("STORE_ATTR_INFO")(st, val);
		}

	pragma(inline, true)
	int sk_STORE_ATTR_INFO_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("STORE_ATTR_INFO")(st, val);
		}

	pragma(inline, true)
	int sk_STORE_ATTR_INFO_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("STORE_ATTR_INFO")(st, val);
		}

	pragma(inline, true)
	auto sk_STORE_ATTR_INFO_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("STORE_ATTR_INFO")(st, i);
		}

	pragma(inline, true)
	auto sk_STORE_ATTR_INFO_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("STORE_ATTR_INFO")(st, ptr_);
		}

	pragma(inline, true)
	int sk_STORE_ATTR_INFO_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("STORE_ATTR_INFO")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_STORE_ATTR_INFO_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("STORE_ATTR_INFO")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_STORE_ATTR_INFO_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("STORE_ATTR_INFO")(st);
		}

	pragma(inline, true)
	void sk_STORE_ATTR_INFO_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("STORE_ATTR_INFO")(st, free_func);
		}

	pragma(inline, true)
	auto sk_STORE_ATTR_INFO_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("STORE_ATTR_INFO")(st);
		}

	pragma(inline, true)
	auto sk_STORE_ATTR_INFO_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("STORE_ATTR_INFO")(st);
		}

	pragma(inline, true)
	void sk_STORE_ATTR_INFO_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("STORE_ATTR_INFO")(st);
		}

	pragma(inline, true)
	int sk_STORE_ATTR_INFO_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("STORE_ATTR_INFO")(st);
		}
}

version (none) {
	pragma(inline, true)
	auto sk_STORE_OBJECT_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("STORE_OBJECT")(cmp);
		}

	pragma(inline, true)
	auto sk_STORE_OBJECT_new_null()

		do
		{
			return .SKM_sk_new_null!("STORE_OBJECT")();
		}

	pragma(inline, true)
	void sk_STORE_OBJECT_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("STORE_OBJECT")(st);
		}

	pragma(inline, true)
	int sk_STORE_OBJECT_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("STORE_OBJECT")(st);
		}

	pragma(inline, true)
	auto sk_STORE_OBJECT_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("STORE_OBJECT")(st, i);
		}

	pragma(inline, true)
	void* sk_STORE_OBJECT_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("STORE_OBJECT")(st, i, val);
		}

	pragma(inline, true)
	void sk_STORE_OBJECT_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("STORE_OBJECT")(st);
		}

	pragma(inline, true)
	int sk_STORE_OBJECT_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("STORE_OBJECT")(st, val);
		}

	pragma(inline, true)
	int sk_STORE_OBJECT_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("STORE_OBJECT")(st, val);
		}

	pragma(inline, true)
	int sk_STORE_OBJECT_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("STORE_OBJECT")(st, val);
		}

	pragma(inline, true)
	int sk_STORE_OBJECT_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("STORE_OBJECT")(st, val);
		}

	pragma(inline, true)
	auto sk_STORE_OBJECT_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("STORE_OBJECT")(st, i);
		}

	pragma(inline, true)
	auto sk_STORE_OBJECT_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("STORE_OBJECT")(st, ptr_);
		}

	pragma(inline, true)
	int sk_STORE_OBJECT_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("STORE_OBJECT")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_STORE_OBJECT_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("STORE_OBJECT")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_STORE_OBJECT_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("STORE_OBJECT")(st);
		}

	pragma(inline, true)
	void sk_STORE_OBJECT_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("STORE_OBJECT")(st, free_func);
		}

	pragma(inline, true)
	auto sk_STORE_OBJECT_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("STORE_OBJECT")(st);
		}

	pragma(inline, true)
	auto sk_STORE_OBJECT_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("STORE_OBJECT")(st);
		}

	pragma(inline, true)
	void sk_STORE_OBJECT_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("STORE_OBJECT")(st);
		}

	pragma(inline, true)
	int sk_STORE_OBJECT_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("STORE_OBJECT")(st);
		}
}

pragma(inline, true)
auto sk_SXNETID_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("SXNETID")(cmp);
	}

pragma(inline, true)
auto sk_SXNETID_new_null()

	do
	{
		return .SKM_sk_new_null!("SXNETID")();
	}

pragma(inline, true)
void sk_SXNETID_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("SXNETID")(st);
	}

pragma(inline, true)
int sk_SXNETID_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("SXNETID")(st);
	}

pragma(inline, true)
auto sk_SXNETID_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("SXNETID")(st, i);
	}

pragma(inline, true)
void* sk_SXNETID_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("SXNETID")(st, i, val);
	}

pragma(inline, true)
void sk_SXNETID_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("SXNETID")(st);
	}

pragma(inline, true)
int sk_SXNETID_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("SXNETID")(st, val);
	}

pragma(inline, true)
int sk_SXNETID_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("SXNETID")(st, val);
	}

pragma(inline, true)
int sk_SXNETID_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("SXNETID")(st, val);
	}

pragma(inline, true)
int sk_SXNETID_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("SXNETID")(st, val);
	}

pragma(inline, true)
auto sk_SXNETID_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("SXNETID")(st, i);
	}

pragma(inline, true)
auto sk_SXNETID_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("SXNETID")(st, ptr_);
	}

pragma(inline, true)
int sk_SXNETID_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("SXNETID")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_SXNETID_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("SXNETID")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_SXNETID_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("SXNETID")(st);
	}

pragma(inline, true)
void sk_SXNETID_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("SXNETID")(st, free_func);
	}

pragma(inline, true)
auto sk_SXNETID_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("SXNETID")(st);
	}

pragma(inline, true)
auto sk_SXNETID_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("SXNETID")(st);
	}

pragma(inline, true)
void sk_SXNETID_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("SXNETID")(st);
	}

pragma(inline, true)
int sk_SXNETID_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("SXNETID")(st);
	}

pragma(inline, true)
auto sk_UI_STRING_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("UI_STRING")(cmp);
	}

pragma(inline, true)
auto sk_UI_STRING_new_null()

	do
	{
		return .SKM_sk_new_null!("UI_STRING")();
	}

pragma(inline, true)
void sk_UI_STRING_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("UI_STRING")(st);
	}

pragma(inline, true)
int sk_UI_STRING_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("UI_STRING")(st);
	}

pragma(inline, true)
auto sk_UI_STRING_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("UI_STRING")(st, i);
	}

pragma(inline, true)
void* sk_UI_STRING_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("UI_STRING")(st, i, val);
	}

pragma(inline, true)
void sk_UI_STRING_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("UI_STRING")(st);
	}

pragma(inline, true)
int sk_UI_STRING_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("UI_STRING")(st, val);
	}

pragma(inline, true)
int sk_UI_STRING_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("UI_STRING")(st, val);
	}

pragma(inline, true)
int sk_UI_STRING_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("UI_STRING")(st, val);
	}

pragma(inline, true)
int sk_UI_STRING_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("UI_STRING")(st, val);
	}

pragma(inline, true)
auto sk_UI_STRING_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("UI_STRING")(st, i);
	}

pragma(inline, true)
auto sk_UI_STRING_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("UI_STRING")(st, ptr_);
	}

pragma(inline, true)
int sk_UI_STRING_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("UI_STRING")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_UI_STRING_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("UI_STRING")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_UI_STRING_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("UI_STRING")(st);
	}

pragma(inline, true)
void sk_UI_STRING_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("UI_STRING")(st, free_func);
	}

pragma(inline, true)
auto sk_UI_STRING_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("UI_STRING")(st);
	}

pragma(inline, true)
auto sk_UI_STRING_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("UI_STRING")(st);
	}

pragma(inline, true)
void sk_UI_STRING_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("UI_STRING")(st);
	}

pragma(inline, true)
int sk_UI_STRING_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("UI_STRING")(st);
	}

pragma(inline, true)
auto sk_X509_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("X509")(cmp);
	}

pragma(inline, true)
auto sk_X509_new_null()

	do
	{
		return .SKM_sk_new_null!("X509")();
	}

pragma(inline, true)
void sk_X509_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("X509")(st);
	}

pragma(inline, true)
int sk_X509_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("X509")(st);
	}

pragma(inline, true)
auto sk_X509_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("X509")(st, i);
	}

pragma(inline, true)
void* sk_X509_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("X509")(st, i, val);
	}

pragma(inline, true)
void sk_X509_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("X509")(st);
	}

pragma(inline, true)
int sk_X509_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("X509")(st, val);
	}

pragma(inline, true)
int sk_X509_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("X509")(st, val);
	}

pragma(inline, true)
int sk_X509_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("X509")(st, val);
	}

pragma(inline, true)
int sk_X509_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("X509")(st, val);
	}

pragma(inline, true)
auto sk_X509_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("X509")(st, i);
	}

pragma(inline, true)
auto sk_X509_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("X509")(st, ptr_);
	}

pragma(inline, true)
int sk_X509_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("X509")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_X509_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("X509")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_X509_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("X509")(st);
	}

pragma(inline, true)
void sk_X509_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("X509")(st, free_func);
	}

pragma(inline, true)
auto sk_X509_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("X509")(st);
	}

pragma(inline, true)
auto sk_X509_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("X509")(st);
	}

pragma(inline, true)
void sk_X509_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("X509")(st);
	}

pragma(inline, true)
int sk_X509_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("X509")(st);
	}

pragma(inline, true)
auto sk_X509V3_EXT_METHOD_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("X509V3_EXT_METHOD")(cmp);
	}

pragma(inline, true)
auto sk_X509V3_EXT_METHOD_new_null()

	do
	{
		return .SKM_sk_new_null!("X509V3_EXT_METHOD")();
	}

pragma(inline, true)
void sk_X509V3_EXT_METHOD_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("X509V3_EXT_METHOD")(st);
	}

pragma(inline, true)
int sk_X509V3_EXT_METHOD_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("X509V3_EXT_METHOD")(st);
	}

pragma(inline, true)
auto sk_X509V3_EXT_METHOD_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("X509V3_EXT_METHOD")(st, i);
	}

pragma(inline, true)
void* sk_X509V3_EXT_METHOD_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("X509V3_EXT_METHOD")(st, i, val);
	}

pragma(inline, true)
void sk_X509V3_EXT_METHOD_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("X509V3_EXT_METHOD")(st);
	}

pragma(inline, true)
int sk_X509V3_EXT_METHOD_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("X509V3_EXT_METHOD")(st, val);
	}

pragma(inline, true)
int sk_X509V3_EXT_METHOD_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("X509V3_EXT_METHOD")(st, val);
	}

pragma(inline, true)
int sk_X509V3_EXT_METHOD_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("X509V3_EXT_METHOD")(st, val);
	}

pragma(inline, true)
int sk_X509V3_EXT_METHOD_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("X509V3_EXT_METHOD")(st, val);
	}

pragma(inline, true)
auto sk_X509V3_EXT_METHOD_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("X509V3_EXT_METHOD")(st, i);
	}

pragma(inline, true)
auto sk_X509V3_EXT_METHOD_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("X509V3_EXT_METHOD")(st, ptr_);
	}

pragma(inline, true)
int sk_X509V3_EXT_METHOD_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("X509V3_EXT_METHOD")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_X509V3_EXT_METHOD_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("X509V3_EXT_METHOD")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_X509V3_EXT_METHOD_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("X509V3_EXT_METHOD")(st);
	}

pragma(inline, true)
void sk_X509V3_EXT_METHOD_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("X509V3_EXT_METHOD")(st, free_func);
	}

pragma(inline, true)
auto sk_X509V3_EXT_METHOD_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("X509V3_EXT_METHOD")(st);
	}

pragma(inline, true)
auto sk_X509V3_EXT_METHOD_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("X509V3_EXT_METHOD")(st);
	}

pragma(inline, true)
void sk_X509V3_EXT_METHOD_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("X509V3_EXT_METHOD")(st);
	}

pragma(inline, true)
int sk_X509V3_EXT_METHOD_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("X509V3_EXT_METHOD")(st);
	}

pragma(inline, true)
auto sk_X509_ALGOR_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("X509_ALGOR")(cmp);
	}

pragma(inline, true)
auto sk_X509_ALGOR_new_null()

	do
	{
		return .SKM_sk_new_null!("X509_ALGOR")();
	}

pragma(inline, true)
void sk_X509_ALGOR_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("X509_ALGOR")(st);
	}

pragma(inline, true)
int sk_X509_ALGOR_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("X509_ALGOR")(st);
	}

pragma(inline, true)
auto sk_X509_ALGOR_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("X509_ALGOR")(st, i);
	}

pragma(inline, true)
void* sk_X509_ALGOR_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("X509_ALGOR")(st, i, val);
	}

pragma(inline, true)
void sk_X509_ALGOR_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("X509_ALGOR")(st);
	}

pragma(inline, true)
int sk_X509_ALGOR_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("X509_ALGOR")(st, val);
	}

pragma(inline, true)
int sk_X509_ALGOR_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("X509_ALGOR")(st, val);
	}

pragma(inline, true)
int sk_X509_ALGOR_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("X509_ALGOR")(st, val);
	}

pragma(inline, true)
int sk_X509_ALGOR_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("X509_ALGOR")(st, val);
	}

pragma(inline, true)
auto sk_X509_ALGOR_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("X509_ALGOR")(st, i);
	}

pragma(inline, true)
auto sk_X509_ALGOR_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("X509_ALGOR")(st, ptr_);
	}

pragma(inline, true)
int sk_X509_ALGOR_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("X509_ALGOR")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_X509_ALGOR_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("X509_ALGOR")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_X509_ALGOR_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("X509_ALGOR")(st);
	}

pragma(inline, true)
void sk_X509_ALGOR_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("X509_ALGOR")(st, free_func);
	}

pragma(inline, true)
auto sk_X509_ALGOR_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("X509_ALGOR")(st);
	}

pragma(inline, true)
auto sk_X509_ALGOR_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("X509_ALGOR")(st);
	}

pragma(inline, true)
void sk_X509_ALGOR_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("X509_ALGOR")(st);
	}

pragma(inline, true)
int sk_X509_ALGOR_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("X509_ALGOR")(st);
	}

pragma(inline, true)
auto sk_X509_ATTRIBUTE_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("X509_ATTRIBUTE")(cmp);
	}

pragma(inline, true)
auto sk_X509_ATTRIBUTE_new_null()

	do
	{
		return .SKM_sk_new_null!("X509_ATTRIBUTE")();
	}

pragma(inline, true)
void sk_X509_ATTRIBUTE_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("X509_ATTRIBUTE")(st);
	}

pragma(inline, true)
int sk_X509_ATTRIBUTE_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("X509_ATTRIBUTE")(st);
	}

pragma(inline, true)
auto sk_X509_ATTRIBUTE_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("X509_ATTRIBUTE")(st, i);
	}

pragma(inline, true)
void* sk_X509_ATTRIBUTE_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("X509_ATTRIBUTE")(st, i, val);
	}

pragma(inline, true)
void sk_X509_ATTRIBUTE_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("X509_ATTRIBUTE")(st);
	}

pragma(inline, true)
int sk_X509_ATTRIBUTE_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("X509_ATTRIBUTE")(st, val);
	}

pragma(inline, true)
int sk_X509_ATTRIBUTE_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("X509_ATTRIBUTE")(st, val);
	}

pragma(inline, true)
int sk_X509_ATTRIBUTE_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("X509_ATTRIBUTE")(st, val);
	}

pragma(inline, true)
int sk_X509_ATTRIBUTE_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("X509_ATTRIBUTE")(st, val);
	}

pragma(inline, true)
auto sk_X509_ATTRIBUTE_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("X509_ATTRIBUTE")(st, i);
	}

pragma(inline, true)
auto sk_X509_ATTRIBUTE_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("X509_ATTRIBUTE")(st, ptr_);
	}

pragma(inline, true)
int sk_X509_ATTRIBUTE_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("X509_ATTRIBUTE")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_X509_ATTRIBUTE_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("X509_ATTRIBUTE")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_X509_ATTRIBUTE_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("X509_ATTRIBUTE")(st);
	}

pragma(inline, true)
void sk_X509_ATTRIBUTE_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("X509_ATTRIBUTE")(st, free_func);
	}

pragma(inline, true)
auto sk_X509_ATTRIBUTE_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("X509_ATTRIBUTE")(st);
	}

pragma(inline, true)
auto sk_X509_ATTRIBUTE_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("X509_ATTRIBUTE")(st);
	}

pragma(inline, true)
void sk_X509_ATTRIBUTE_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("X509_ATTRIBUTE")(st);
	}

pragma(inline, true)
int sk_X509_ATTRIBUTE_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("X509_ATTRIBUTE")(st);
	}

pragma(inline, true)
auto sk_X509_CRL_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("X509_CRL")(cmp);
	}

pragma(inline, true)
auto sk_X509_CRL_new_null()

	do
	{
		return .SKM_sk_new_null!("X509_CRL")();
	}

pragma(inline, true)
void sk_X509_CRL_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("X509_CRL")(st);
	}

pragma(inline, true)
int sk_X509_CRL_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("X509_CRL")(st);
	}

pragma(inline, true)
auto sk_X509_CRL_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("X509_CRL")(st, i);
	}

pragma(inline, true)
void* sk_X509_CRL_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("X509_CRL")(st, i, val);
	}

pragma(inline, true)
void sk_X509_CRL_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("X509_CRL")(st);
	}

pragma(inline, true)
int sk_X509_CRL_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("X509_CRL")(st, val);
	}

pragma(inline, true)
int sk_X509_CRL_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("X509_CRL")(st, val);
	}

pragma(inline, true)
int sk_X509_CRL_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("X509_CRL")(st, val);
	}

pragma(inline, true)
int sk_X509_CRL_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("X509_CRL")(st, val);
	}

pragma(inline, true)
auto sk_X509_CRL_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("X509_CRL")(st, i);
	}

pragma(inline, true)
auto sk_X509_CRL_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("X509_CRL")(st, ptr_);
	}

pragma(inline, true)
int sk_X509_CRL_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("X509_CRL")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_X509_CRL_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("X509_CRL")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_X509_CRL_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("X509_CRL")(st);
	}

pragma(inline, true)
void sk_X509_CRL_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("X509_CRL")(st, free_func);
	}

pragma(inline, true)
auto sk_X509_CRL_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("X509_CRL")(st);
	}

pragma(inline, true)
auto sk_X509_CRL_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("X509_CRL")(st);
	}

pragma(inline, true)
void sk_X509_CRL_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("X509_CRL")(st);
	}

pragma(inline, true)
int sk_X509_CRL_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("X509_CRL")(st);
	}

pragma(inline, true)
auto sk_X509_EXTENSION_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("X509_EXTENSION")(cmp);
	}

pragma(inline, true)
auto sk_X509_EXTENSION_new_null()

	do
	{
		return .SKM_sk_new_null!("X509_EXTENSION")();
	}

pragma(inline, true)
void sk_X509_EXTENSION_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("X509_EXTENSION")(st);
	}

pragma(inline, true)
int sk_X509_EXTENSION_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("X509_EXTENSION")(st);
	}

pragma(inline, true)
auto sk_X509_EXTENSION_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("X509_EXTENSION")(st, i);
	}

pragma(inline, true)
void* sk_X509_EXTENSION_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("X509_EXTENSION")(st, i, val);
	}

pragma(inline, true)
void sk_X509_EXTENSION_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("X509_EXTENSION")(st);
	}

pragma(inline, true)
int sk_X509_EXTENSION_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("X509_EXTENSION")(st, val);
	}

pragma(inline, true)
int sk_X509_EXTENSION_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("X509_EXTENSION")(st, val);
	}

pragma(inline, true)
int sk_X509_EXTENSION_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("X509_EXTENSION")(st, val);
	}

pragma(inline, true)
int sk_X509_EXTENSION_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("X509_EXTENSION")(st, val);
	}

pragma(inline, true)
auto sk_X509_EXTENSION_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("X509_EXTENSION")(st, i);
	}

pragma(inline, true)
auto sk_X509_EXTENSION_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("X509_EXTENSION")(st, ptr_);
	}

pragma(inline, true)
int sk_X509_EXTENSION_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("X509_EXTENSION")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_X509_EXTENSION_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("X509_EXTENSION")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_X509_EXTENSION_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("X509_EXTENSION")(st);
	}

pragma(inline, true)
void sk_X509_EXTENSION_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("X509_EXTENSION")(st, free_func);
	}

pragma(inline, true)
auto sk_X509_EXTENSION_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("X509_EXTENSION")(st);
	}

pragma(inline, true)
auto sk_X509_EXTENSION_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("X509_EXTENSION")(st);
	}

pragma(inline, true)
void sk_X509_EXTENSION_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("X509_EXTENSION")(st);
	}

pragma(inline, true)
int sk_X509_EXTENSION_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("X509_EXTENSION")(st);
	}

version (OPENSSL_NO_EVP) {
} else {
	pragma(inline, true)
	auto sk_X509_INFO_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("X509_INFO")(cmp);
		}

	pragma(inline, true)
	auto sk_X509_INFO_new_null()

		do
		{
			return .SKM_sk_new_null!("X509_INFO")();
		}

	pragma(inline, true)
	void sk_X509_INFO_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("X509_INFO")(st);
		}

	pragma(inline, true)
	int sk_X509_INFO_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("X509_INFO")(st);
		}

	pragma(inline, true)
	auto sk_X509_INFO_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("X509_INFO")(st, i);
		}

	pragma(inline, true)
	void* sk_X509_INFO_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("X509_INFO")(st, i, val);
		}

	pragma(inline, true)
	void sk_X509_INFO_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("X509_INFO")(st);
		}

	pragma(inline, true)
	int sk_X509_INFO_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("X509_INFO")(st, val);
		}

	pragma(inline, true)
	int sk_X509_INFO_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("X509_INFO")(st, val);
		}

	pragma(inline, true)
	int sk_X509_INFO_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("X509_INFO")(st, val);
		}

	pragma(inline, true)
	int sk_X509_INFO_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("X509_INFO")(st, val);
		}

	pragma(inline, true)
	auto sk_X509_INFO_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("X509_INFO")(st, i);
		}

	pragma(inline, true)
	auto sk_X509_INFO_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("X509_INFO")(st, ptr_);
		}

	pragma(inline, true)
	int sk_X509_INFO_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("X509_INFO")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_X509_INFO_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("X509_INFO")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_X509_INFO_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("X509_INFO")(st);
		}

	pragma(inline, true)
	void sk_X509_INFO_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("X509_INFO")(st, free_func);
		}

	pragma(inline, true)
	auto sk_X509_INFO_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("X509_INFO")(st);
		}

	pragma(inline, true)
	auto sk_X509_INFO_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("X509_INFO")(st);
		}

	pragma(inline, true)
	void sk_X509_INFO_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("X509_INFO")(st);
		}

	pragma(inline, true)
	int sk_X509_INFO_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("X509_INFO")(st);
		}
}

pragma(inline, true)
auto sk_X509_LOOKUP_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("X509_LOOKUP")(cmp);
	}

pragma(inline, true)
auto sk_X509_LOOKUP_new_null()

	do
	{
		return .SKM_sk_new_null!("X509_LOOKUP")();
	}

pragma(inline, true)
void sk_X509_LOOKUP_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("X509_LOOKUP")(st);
	}

pragma(inline, true)
int sk_X509_LOOKUP_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("X509_LOOKUP")(st);
	}

pragma(inline, true)
auto sk_X509_LOOKUP_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("X509_LOOKUP")(st, i);
	}

pragma(inline, true)
void* sk_X509_LOOKUP_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("X509_LOOKUP")(st, i, val);
	}

pragma(inline, true)
void sk_X509_LOOKUP_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("X509_LOOKUP")(st);
	}

pragma(inline, true)
int sk_X509_LOOKUP_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("X509_LOOKUP")(st, val);
	}

pragma(inline, true)
int sk_X509_LOOKUP_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("X509_LOOKUP")(st, val);
	}

pragma(inline, true)
int sk_X509_LOOKUP_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("X509_LOOKUP")(st, val);
	}

pragma(inline, true)
int sk_X509_LOOKUP_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("X509_LOOKUP")(st, val);
	}

pragma(inline, true)
auto sk_X509_LOOKUP_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("X509_LOOKUP")(st, i);
	}

pragma(inline, true)
auto sk_X509_LOOKUP_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("X509_LOOKUP")(st, ptr_);
	}

pragma(inline, true)
int sk_X509_LOOKUP_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("X509_LOOKUP")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_X509_LOOKUP_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("X509_LOOKUP")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_X509_LOOKUP_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("X509_LOOKUP")(st);
	}

pragma(inline, true)
void sk_X509_LOOKUP_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("X509_LOOKUP")(st, free_func);
	}

pragma(inline, true)
auto sk_X509_LOOKUP_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("X509_LOOKUP")(st);
	}

pragma(inline, true)
auto sk_X509_LOOKUP_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("X509_LOOKUP")(st);
	}

pragma(inline, true)
void sk_X509_LOOKUP_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("X509_LOOKUP")(st);
	}

pragma(inline, true)
int sk_X509_LOOKUP_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("X509_LOOKUP")(st);
	}

pragma(inline, true)
auto sk_X509_NAME_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("X509_NAME")(cmp);
	}

pragma(inline, true)
auto sk_X509_NAME_new_null()

	do
	{
		return .SKM_sk_new_null!("X509_NAME")();
	}

pragma(inline, true)
void sk_X509_NAME_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("X509_NAME")(st);
	}

pragma(inline, true)
int sk_X509_NAME_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("X509_NAME")(st);
	}

pragma(inline, true)
auto sk_X509_NAME_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("X509_NAME")(st, i);
	}

pragma(inline, true)
void* sk_X509_NAME_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("X509_NAME")(st, i, val);
	}

pragma(inline, true)
void sk_X509_NAME_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("X509_NAME")(st);
	}

pragma(inline, true)
int sk_X509_NAME_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("X509_NAME")(st, val);
	}

pragma(inline, true)
int sk_X509_NAME_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("X509_NAME")(st, val);
	}

pragma(inline, true)
int sk_X509_NAME_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("X509_NAME")(st, val);
	}

pragma(inline, true)
int sk_X509_NAME_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("X509_NAME")(st, val);
	}

pragma(inline, true)
auto sk_X509_NAME_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("X509_NAME")(st, i);
	}

pragma(inline, true)
auto sk_X509_NAME_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("X509_NAME")(st, ptr_);
	}

pragma(inline, true)
int sk_X509_NAME_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("X509_NAME")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_X509_NAME_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("X509_NAME")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_X509_NAME_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("X509_NAME")(st);
	}

pragma(inline, true)
void sk_X509_NAME_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("X509_NAME")(st, free_func);
	}

pragma(inline, true)
auto sk_X509_NAME_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("X509_NAME")(st);
	}

pragma(inline, true)
auto sk_X509_NAME_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("X509_NAME")(st);
	}

pragma(inline, true)
void sk_X509_NAME_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("X509_NAME")(st);
	}

pragma(inline, true)
int sk_X509_NAME_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("X509_NAME")(st);
	}

pragma(inline, true)
auto sk_X509_NAME_ENTRY_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("X509_NAME_ENTRY")(cmp);
	}

pragma(inline, true)
auto sk_X509_NAME_ENTRY_new_null()

	do
	{
		return .SKM_sk_new_null!("X509_NAME_ENTRY")();
	}

pragma(inline, true)
void sk_X509_NAME_ENTRY_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("X509_NAME_ENTRY")(st);
	}

pragma(inline, true)
int sk_X509_NAME_ENTRY_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("X509_NAME_ENTRY")(st);
	}

pragma(inline, true)
auto sk_X509_NAME_ENTRY_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("X509_NAME_ENTRY")(st, i);
	}

pragma(inline, true)
void* sk_X509_NAME_ENTRY_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("X509_NAME_ENTRY")(st, i, val);
	}

pragma(inline, true)
void sk_X509_NAME_ENTRY_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("X509_NAME_ENTRY")(st);
	}

pragma(inline, true)
int sk_X509_NAME_ENTRY_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("X509_NAME_ENTRY")(st, val);
	}

pragma(inline, true)
int sk_X509_NAME_ENTRY_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("X509_NAME_ENTRY")(st, val);
	}

pragma(inline, true)
int sk_X509_NAME_ENTRY_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("X509_NAME_ENTRY")(st, val);
	}

pragma(inline, true)
int sk_X509_NAME_ENTRY_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("X509_NAME_ENTRY")(st, val);
	}

pragma(inline, true)
auto sk_X509_NAME_ENTRY_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("X509_NAME_ENTRY")(st, i);
	}

pragma(inline, true)
auto sk_X509_NAME_ENTRY_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("X509_NAME_ENTRY")(st, ptr_);
	}

pragma(inline, true)
int sk_X509_NAME_ENTRY_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("X509_NAME_ENTRY")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_X509_NAME_ENTRY_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("X509_NAME_ENTRY")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_X509_NAME_ENTRY_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("X509_NAME_ENTRY")(st);
	}

pragma(inline, true)
void sk_X509_NAME_ENTRY_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("X509_NAME_ENTRY")(st, free_func);
	}

pragma(inline, true)
auto sk_X509_NAME_ENTRY_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("X509_NAME_ENTRY")(st);
	}

pragma(inline, true)
auto sk_X509_NAME_ENTRY_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("X509_NAME_ENTRY")(st);
	}

pragma(inline, true)
void sk_X509_NAME_ENTRY_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("X509_NAME_ENTRY")(st);
	}

pragma(inline, true)
int sk_X509_NAME_ENTRY_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("X509_NAME_ENTRY")(st);
	}

pragma(inline, true)
auto sk_X509_OBJECT_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("X509_OBJECT")(cmp);
	}

pragma(inline, true)
auto sk_X509_OBJECT_new_null()

	do
	{
		return .SKM_sk_new_null!("X509_OBJECT")();
	}

pragma(inline, true)
void sk_X509_OBJECT_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("X509_OBJECT")(st);
	}

pragma(inline, true)
int sk_X509_OBJECT_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("X509_OBJECT")(st);
	}

pragma(inline, true)
auto sk_X509_OBJECT_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("X509_OBJECT")(st, i);
	}

pragma(inline, true)
void* sk_X509_OBJECT_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("X509_OBJECT")(st, i, val);
	}

pragma(inline, true)
void sk_X509_OBJECT_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("X509_OBJECT")(st);
	}

pragma(inline, true)
int sk_X509_OBJECT_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("X509_OBJECT")(st, val);
	}

pragma(inline, true)
int sk_X509_OBJECT_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("X509_OBJECT")(st, val);
	}

pragma(inline, true)
int sk_X509_OBJECT_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("X509_OBJECT")(st, val);
	}

pragma(inline, true)
int sk_X509_OBJECT_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("X509_OBJECT")(st, val);
	}

pragma(inline, true)
auto sk_X509_OBJECT_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("X509_OBJECT")(st, i);
	}

pragma(inline, true)
auto sk_X509_OBJECT_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("X509_OBJECT")(st, ptr_);
	}

pragma(inline, true)
int sk_X509_OBJECT_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("X509_OBJECT")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_X509_OBJECT_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("X509_OBJECT")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_X509_OBJECT_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("X509_OBJECT")(st);
	}

pragma(inline, true)
void sk_X509_OBJECT_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("X509_OBJECT")(st, free_func);
	}

pragma(inline, true)
auto sk_X509_OBJECT_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("X509_OBJECT")(st);
	}

pragma(inline, true)
auto sk_X509_OBJECT_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("X509_OBJECT")(st);
	}

pragma(inline, true)
void sk_X509_OBJECT_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("X509_OBJECT")(st);
	}

pragma(inline, true)
int sk_X509_OBJECT_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("X509_OBJECT")(st);
	}

version (none) {
	pragma(inline, true)
	auto sk_X509_POLICY_DATA_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("X509_POLICY_DATA")(cmp);
		}

	pragma(inline, true)
	auto sk_X509_POLICY_DATA_new_null()

		do
		{
			return .SKM_sk_new_null!("X509_POLICY_DATA")();
		}

	pragma(inline, true)
	void sk_X509_POLICY_DATA_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("X509_POLICY_DATA")(st);
		}

	pragma(inline, true)
	int sk_X509_POLICY_DATA_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("X509_POLICY_DATA")(st);
		}

	pragma(inline, true)
	auto sk_X509_POLICY_DATA_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("X509_POLICY_DATA")(st, i);
		}

	pragma(inline, true)
	void* sk_X509_POLICY_DATA_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("X509_POLICY_DATA")(st, i, val);
		}

	pragma(inline, true)
	void sk_X509_POLICY_DATA_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("X509_POLICY_DATA")(st);
		}

	pragma(inline, true)
	int sk_X509_POLICY_DATA_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("X509_POLICY_DATA")(st, val);
		}

	pragma(inline, true)
	int sk_X509_POLICY_DATA_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("X509_POLICY_DATA")(st, val);
		}

	pragma(inline, true)
	int sk_X509_POLICY_DATA_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("X509_POLICY_DATA")(st, val);
		}

	pragma(inline, true)
	int sk_X509_POLICY_DATA_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("X509_POLICY_DATA")(st, val);
		}

	pragma(inline, true)
	auto sk_X509_POLICY_DATA_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("X509_POLICY_DATA")(st, i);
		}

	pragma(inline, true)
	auto sk_X509_POLICY_DATA_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("X509_POLICY_DATA")(st, ptr_);
		}

	pragma(inline, true)
	int sk_X509_POLICY_DATA_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("X509_POLICY_DATA")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_X509_POLICY_DATA_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("X509_POLICY_DATA")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_X509_POLICY_DATA_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("X509_POLICY_DATA")(st);
		}

	pragma(inline, true)
	void sk_X509_POLICY_DATA_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("X509_POLICY_DATA")(st, free_func);
		}

	pragma(inline, true)
	auto sk_X509_POLICY_DATA_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("X509_POLICY_DATA")(st);
		}

	pragma(inline, true)
	auto sk_X509_POLICY_DATA_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("X509_POLICY_DATA")(st);
		}

	pragma(inline, true)
	void sk_X509_POLICY_DATA_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("X509_POLICY_DATA")(st);
		}

	pragma(inline, true)
	int sk_X509_POLICY_DATA_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("X509_POLICY_DATA")(st);
		}
}

pragma(inline, true)
auto sk_X509_POLICY_NODE_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("X509_POLICY_NODE")(cmp);
	}

pragma(inline, true)
auto sk_X509_POLICY_NODE_new_null()

	do
	{
		return .SKM_sk_new_null!("X509_POLICY_NODE")();
	}

pragma(inline, true)
void sk_X509_POLICY_NODE_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("X509_POLICY_NODE")(st);
	}

pragma(inline, true)
int sk_X509_POLICY_NODE_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("X509_POLICY_NODE")(st);
	}

pragma(inline, true)
auto sk_X509_POLICY_NODE_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("X509_POLICY_NODE")(st, i);
	}

pragma(inline, true)
void* sk_X509_POLICY_NODE_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("X509_POLICY_NODE")(st, i, val);
	}

pragma(inline, true)
void sk_X509_POLICY_NODE_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("X509_POLICY_NODE")(st);
	}

pragma(inline, true)
int sk_X509_POLICY_NODE_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("X509_POLICY_NODE")(st, val);
	}

pragma(inline, true)
int sk_X509_POLICY_NODE_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("X509_POLICY_NODE")(st, val);
	}

pragma(inline, true)
int sk_X509_POLICY_NODE_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("X509_POLICY_NODE")(st, val);
	}

pragma(inline, true)
int sk_X509_POLICY_NODE_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("X509_POLICY_NODE")(st, val);
	}

pragma(inline, true)
auto sk_X509_POLICY_NODE_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("X509_POLICY_NODE")(st, i);
	}

pragma(inline, true)
auto sk_X509_POLICY_NODE_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("X509_POLICY_NODE")(st, ptr_);
	}

pragma(inline, true)
int sk_X509_POLICY_NODE_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("X509_POLICY_NODE")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_X509_POLICY_NODE_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("X509_POLICY_NODE")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_X509_POLICY_NODE_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("X509_POLICY_NODE")(st);
	}

pragma(inline, true)
void sk_X509_POLICY_NODE_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("X509_POLICY_NODE")(st, free_func);
	}

pragma(inline, true)
auto sk_X509_POLICY_NODE_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("X509_POLICY_NODE")(st);
	}

pragma(inline, true)
auto sk_X509_POLICY_NODE_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("X509_POLICY_NODE")(st);
	}

pragma(inline, true)
void sk_X509_POLICY_NODE_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("X509_POLICY_NODE")(st);
	}

pragma(inline, true)
int sk_X509_POLICY_NODE_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("X509_POLICY_NODE")(st);
	}

pragma(inline, true)
auto sk_X509_PURPOSE_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("X509_PURPOSE")(cmp);
	}

pragma(inline, true)
auto sk_X509_PURPOSE_new_null()

	do
	{
		return .SKM_sk_new_null!("X509_PURPOSE")();
	}

pragma(inline, true)
void sk_X509_PURPOSE_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("X509_PURPOSE")(st);
	}

pragma(inline, true)
int sk_X509_PURPOSE_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("X509_PURPOSE")(st);
	}

pragma(inline, true)
auto sk_X509_PURPOSE_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("X509_PURPOSE")(st, i);
	}

pragma(inline, true)
void* sk_X509_PURPOSE_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("X509_PURPOSE")(st, i, val);
	}

pragma(inline, true)
void sk_X509_PURPOSE_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("X509_PURPOSE")(st);
	}

pragma(inline, true)
int sk_X509_PURPOSE_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("X509_PURPOSE")(st, val);
	}

pragma(inline, true)
int sk_X509_PURPOSE_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("X509_PURPOSE")(st, val);
	}

pragma(inline, true)
int sk_X509_PURPOSE_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("X509_PURPOSE")(st, val);
	}

pragma(inline, true)
int sk_X509_PURPOSE_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("X509_PURPOSE")(st, val);
	}

pragma(inline, true)
auto sk_X509_PURPOSE_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("X509_PURPOSE")(st, i);
	}

pragma(inline, true)
auto sk_X509_PURPOSE_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("X509_PURPOSE")(st, ptr_);
	}

pragma(inline, true)
int sk_X509_PURPOSE_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("X509_PURPOSE")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_X509_PURPOSE_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("X509_PURPOSE")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_X509_PURPOSE_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("X509_PURPOSE")(st);
	}

pragma(inline, true)
void sk_X509_PURPOSE_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("X509_PURPOSE")(st, free_func);
	}

pragma(inline, true)
auto sk_X509_PURPOSE_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("X509_PURPOSE")(st);
	}

pragma(inline, true)
auto sk_X509_PURPOSE_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("X509_PURPOSE")(st);
	}

pragma(inline, true)
void sk_X509_PURPOSE_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("X509_PURPOSE")(st);
	}

pragma(inline, true)
int sk_X509_PURPOSE_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("X509_PURPOSE")(st);
	}

pragma(inline, true)
auto sk_X509_REVOKED_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("X509_REVOKED")(cmp);
	}

pragma(inline, true)
auto sk_X509_REVOKED_new_null()

	do
	{
		return .SKM_sk_new_null!("X509_REVOKED")();
	}

pragma(inline, true)
void sk_X509_REVOKED_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("X509_REVOKED")(st);
	}

pragma(inline, true)
int sk_X509_REVOKED_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("X509_REVOKED")(st);
	}

pragma(inline, true)
auto sk_X509_REVOKED_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("X509_REVOKED")(st, i);
	}

pragma(inline, true)
void* sk_X509_REVOKED_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("X509_REVOKED")(st, i, val);
	}

pragma(inline, true)
void sk_X509_REVOKED_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("X509_REVOKED")(st);
	}

pragma(inline, true)
int sk_X509_REVOKED_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("X509_REVOKED")(st, val);
	}

pragma(inline, true)
int sk_X509_REVOKED_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("X509_REVOKED")(st, val);
	}

pragma(inline, true)
int sk_X509_REVOKED_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("X509_REVOKED")(st, val);
	}

pragma(inline, true)
int sk_X509_REVOKED_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("X509_REVOKED")(st, val);
	}

pragma(inline, true)
auto sk_X509_REVOKED_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("X509_REVOKED")(st, i);
	}

pragma(inline, true)
auto sk_X509_REVOKED_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("X509_REVOKED")(st, ptr_);
	}

pragma(inline, true)
int sk_X509_REVOKED_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("X509_REVOKED")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_X509_REVOKED_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("X509_REVOKED")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_X509_REVOKED_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("X509_REVOKED")(st);
	}

pragma(inline, true)
void sk_X509_REVOKED_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("X509_REVOKED")(st, free_func);
	}

pragma(inline, true)
auto sk_X509_REVOKED_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("X509_REVOKED")(st);
	}

pragma(inline, true)
auto sk_X509_REVOKED_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("X509_REVOKED")(st);
	}

pragma(inline, true)
void sk_X509_REVOKED_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("X509_REVOKED")(st);
	}

pragma(inline, true)
int sk_X509_REVOKED_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("X509_REVOKED")(st);
	}

pragma(inline, true)
auto sk_X509_TRUST_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("X509_TRUST")(cmp);
	}

pragma(inline, true)
auto sk_X509_TRUST_new_null()

	do
	{
		return .SKM_sk_new_null!("X509_TRUST")();
	}

pragma(inline, true)
void sk_X509_TRUST_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("X509_TRUST")(st);
	}

pragma(inline, true)
int sk_X509_TRUST_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("X509_TRUST")(st);
	}

pragma(inline, true)
auto sk_X509_TRUST_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("X509_TRUST")(st, i);
	}

pragma(inline, true)
void* sk_X509_TRUST_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("X509_TRUST")(st, i, val);
	}

pragma(inline, true)
void sk_X509_TRUST_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("X509_TRUST")(st);
	}

pragma(inline, true)
int sk_X509_TRUST_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("X509_TRUST")(st, val);
	}

pragma(inline, true)
int sk_X509_TRUST_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("X509_TRUST")(st, val);
	}

pragma(inline, true)
int sk_X509_TRUST_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("X509_TRUST")(st, val);
	}

pragma(inline, true)
int sk_X509_TRUST_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("X509_TRUST")(st, val);
	}

pragma(inline, true)
auto sk_X509_TRUST_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("X509_TRUST")(st, i);
	}

pragma(inline, true)
auto sk_X509_TRUST_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("X509_TRUST")(st, ptr_);
	}

pragma(inline, true)
int sk_X509_TRUST_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("X509_TRUST")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_X509_TRUST_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("X509_TRUST")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_X509_TRUST_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("X509_TRUST")(st);
	}

pragma(inline, true)
void sk_X509_TRUST_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("X509_TRUST")(st, free_func);
	}

pragma(inline, true)
auto sk_X509_TRUST_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("X509_TRUST")(st);
	}

pragma(inline, true)
auto sk_X509_TRUST_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("X509_TRUST")(st);
	}

pragma(inline, true)
void sk_X509_TRUST_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("X509_TRUST")(st);
	}

pragma(inline, true)
int sk_X509_TRUST_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("X509_TRUST")(st);
	}

pragma(inline, true)
auto sk_X509_VERIFY_PARAM_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("X509_VERIFY_PARAM")(cmp);
	}

pragma(inline, true)
auto sk_X509_VERIFY_PARAM_new_null()

	do
	{
		return .SKM_sk_new_null!("X509_VERIFY_PARAM")();
	}

pragma(inline, true)
void sk_X509_VERIFY_PARAM_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("X509_VERIFY_PARAM")(st);
	}

pragma(inline, true)
int sk_X509_VERIFY_PARAM_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("X509_VERIFY_PARAM")(st);
	}

pragma(inline, true)
auto sk_X509_VERIFY_PARAM_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("X509_VERIFY_PARAM")(st, i);
	}

pragma(inline, true)
void* sk_X509_VERIFY_PARAM_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("X509_VERIFY_PARAM")(st, i, val);
	}

pragma(inline, true)
void sk_X509_VERIFY_PARAM_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("X509_VERIFY_PARAM")(st);
	}

pragma(inline, true)
int sk_X509_VERIFY_PARAM_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("X509_VERIFY_PARAM")(st, val);
	}

pragma(inline, true)
int sk_X509_VERIFY_PARAM_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("X509_VERIFY_PARAM")(st, val);
	}

pragma(inline, true)
int sk_X509_VERIFY_PARAM_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("X509_VERIFY_PARAM")(st, val);
	}

pragma(inline, true)
int sk_X509_VERIFY_PARAM_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("X509_VERIFY_PARAM")(st, val);
	}

pragma(inline, true)
auto sk_X509_VERIFY_PARAM_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("X509_VERIFY_PARAM")(st, i);
	}

pragma(inline, true)
auto sk_X509_VERIFY_PARAM_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("X509_VERIFY_PARAM")(st, ptr_);
	}

pragma(inline, true)
int sk_X509_VERIFY_PARAM_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("X509_VERIFY_PARAM")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_X509_VERIFY_PARAM_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("X509_VERIFY_PARAM")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_X509_VERIFY_PARAM_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("X509_VERIFY_PARAM")(st);
	}

pragma(inline, true)
void sk_X509_VERIFY_PARAM_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("X509_VERIFY_PARAM")(st, free_func);
	}

pragma(inline, true)
auto sk_X509_VERIFY_PARAM_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("X509_VERIFY_PARAM")(st);
	}

pragma(inline, true)
auto sk_X509_VERIFY_PARAM_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("X509_VERIFY_PARAM")(st);
	}

pragma(inline, true)
void sk_X509_VERIFY_PARAM_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("X509_VERIFY_PARAM")(st);
	}

pragma(inline, true)
int sk_X509_VERIFY_PARAM_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("X509_VERIFY_PARAM")(st);
	}

version (none) {
	pragma(inline, true)
	auto sk_nid_triple_new(CMP_TYPE)(CMP_TYPE cmp)

		do
		{
			return .SKM_sk_new!("nid_triple")(cmp);
		}

	pragma(inline, true)
	auto sk_nid_triple_new_null()

		do
		{
			return .SKM_sk_new_null!("nid_triple")();
		}

	pragma(inline, true)
	void sk_nid_triple_free(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_free!("nid_triple")(st);
		}

	pragma(inline, true)
	int sk_nid_triple_num(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_num!("nid_triple")(st);
		}

	pragma(inline, true)
	auto sk_nid_triple_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_value!("nid_triple")(st, i);
		}

	pragma(inline, true)
	void* sk_nid_triple_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

		do
		{
			return .SKM_sk_set!("nid_triple")(st, i, val);
		}

	pragma(inline, true)
	void sk_nid_triple_zero(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_zero!("nid_triple")(st);
		}

	pragma(inline, true)
	int sk_nid_triple_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_push!("nid_triple")(st, val);
		}

	pragma(inline, true)
	int sk_nid_triple_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_unshift!("nid_triple")(st, val);
		}

	pragma(inline, true)
	int sk_nid_triple_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find!("nid_triple")(st, val);
		}

	pragma(inline, true)
	int sk_nid_triple_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

		do
		{
			return .SKM_sk_find_ex!("nid_triple")(st, val);
		}

	pragma(inline, true)
	auto sk_nid_triple_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

		do
		{
			return .SKM_sk_delete!("nid_triple")(st, i);
		}

	pragma(inline, true)
	auto sk_nid_triple_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

		do
		{
			return .SKM_sk_delete_ptr!("nid_triple")(st, ptr_);
		}

	pragma(inline, true)
	int sk_nid_triple_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

		do
		{
			return .SKM_sk_insert!("nid_triple")(st, val, i);
		}

	/+
	pragma(inline, true)
	auto sk_nid_triple_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

		do
		{
			return .SKM_sk_set_cmp_func!("nid_triple")(st, cmp);
		}
	+/

	pragma(inline, true)
	auto sk_nid_triple_dup(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_dup!("nid_triple")(st);
		}

	pragma(inline, true)
	void sk_nid_triple_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

		do
		{
			.SKM_sk_pop_free!("nid_triple")(st, free_func);
		}

	pragma(inline, true)
	auto sk_nid_triple_shift(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_shift!("nid_triple")(st);
		}

	pragma(inline, true)
	auto sk_nid_triple_pop(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_pop!("nid_triple")(st);
		}

	pragma(inline, true)
	void sk_nid_triple_sort(ST_TYPE)(ST_TYPE st)

		do
		{
			.SKM_sk_sort!("nid_triple")(st);
		}

	pragma(inline, true)
	int sk_nid_triple_is_sorted(ST_TYPE)(ST_TYPE st)

		do
		{
			return .SKM_sk_is_sorted!("nid_triple")(st);
		}
}

pragma(inline, true)
auto sk_void_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return .SKM_sk_new!("void")(cmp);
	}

pragma(inline, true)
auto sk_void_new_null()

	do
	{
		return .SKM_sk_new_null!("void")();
	}

pragma(inline, true)
void sk_void_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("void")(st);
	}

pragma(inline, true)
int sk_void_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("void")(st);
	}

pragma(inline, true)
auto sk_void_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_value!("void")(st, i);
	}

pragma(inline, true)
void* sk_void_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return .SKM_sk_set!("void")(st, i, val);
	}

pragma(inline, true)
void sk_void_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("void")(st);
	}

pragma(inline, true)
int sk_void_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_push!("void")(st, val);
	}

pragma(inline, true)
int sk_void_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_unshift!("void")(st, val);
	}

pragma(inline, true)
int sk_void_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find!("void")(st, val);
	}

pragma(inline, true)
int sk_void_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return .SKM_sk_find_ex!("void")(st, val);
	}

pragma(inline, true)
auto sk_void_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("void")(st, i);
	}

pragma(inline, true)
auto sk_void_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return .SKM_sk_delete_ptr!("void")(st, ptr_);
	}

pragma(inline, true)
int sk_void_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return .SKM_sk_insert!("void")(st, val, i);
	}

/+
pragma(inline, true)
auto sk_void_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		return .SKM_sk_set_cmp_func!("void")(st, cmp);
	}
+/

pragma(inline, true)
auto sk_void_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("void")(st);
	}

pragma(inline, true)
void sk_void_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		.SKM_sk_pop_free!("void")(st, free_func);
	}

pragma(inline, true)
auto sk_void_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("void")(st);
	}

pragma(inline, true)
auto sk_void_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_pop!("void")(st);
	}

pragma(inline, true)
void sk_void_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("void")(st);
	}

pragma(inline, true)
int sk_void_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("void")(st);
	}

pragma(inline, true)
libressl.openssl.stack._STACK* sk_OPENSSL_STRING_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return cast(.stack_st_OPENSSL_STRING*)(libressl.openssl.stack.sk_new(.CHECKED_SK_CMP_FUNC!("char")(cmp)));
	}

pragma(inline, true)
.stack_st_OPENSSL_STRING* sk_OPENSSL_STRING_new_null()

	do
	{
		return cast(.stack_st_OPENSSL_STRING*)(libressl.openssl.stack.sk_new_null());
	}

pragma(inline, true)
int sk_OPENSSL_STRING_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_push(.CHECKED_STACK_OF!("OPENSSL_STRING")(st), libressl.openssl.asn1.CHECKED_PTR_OF!(char)(val));
	}

pragma(inline, true)
int sk_OPENSSL_STRING_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_find(.CHECKED_STACK_OF!("OPENSSL_STRING")(st), libressl.openssl.asn1.CHECKED_PTR_OF!(char)(val));
	}

pragma(inline, true)
void* sk_OPENSSL_STRING_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return cast(.OPENSSL_STRING)(libressl.openssl.stack.sk_value(.CHECKED_STACK_OF!("OPENSSL_STRING")(st), i));
	}

pragma(inline, true)
int sk_OPENSSL_STRING_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("OPENSSL_STRING")(st);
	}

pragma(inline, true)
void sk_OPENSSL_STRING_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		libressl.openssl.stack.sk_pop_free(.CHECKED_STACK_OF!("OPENSSL_STRING")(st), .CHECKED_SK_FREE_FUNC2!(.OPENSSL_STRING)(free_func));
	}

pragma(inline, true)
int sk_OPENSSL_STRING_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return libressl.openssl.stack.sk_insert(.CHECKED_STACK_OF!("OPENSSL_STRING")(st), libressl.openssl.asn1.CHECKED_PTR_OF!(char)(val), i);
	}

pragma(inline, true)
void sk_OPENSSL_STRING_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("OPENSSL_STRING")(st);
	}

pragma(inline, true)
void* sk_OPENSSL_STRING_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_set(.CHECKED_STACK_OF!("OPENSSL_STRING")(st), i, libressl.openssl.asn1.CHECKED_PTR_OF!(char)(val));
	}

pragma(inline, true)
void sk_OPENSSL_STRING_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("OPENSSL_STRING")(st);
	}

pragma(inline, true)
int sk_OPENSSL_STRING_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_unshift(.CHECKED_STACK_OF!("OPENSSL_STRING")(st), libressl.openssl.asn1.CHECKED_PTR_OF!(char)(val));
	}

/+
pragma(inline, true)
int sk_OPENSSL_STRING_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_find_ex(cast(libressl.openssl.stack._STACK*)(CHECKED_CONST_PTR_OF(.stack_st_OPENSSL_STRING, st)), CHECKED_CONST_PTR_OF(char, val));
	}
+/

pragma(inline, true)
auto sk_OPENSSL_STRING_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("OPENSSL_STRING")(st, i);
	}

pragma(inline, true)
void* sk_OPENSSL_STRING_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return cast(.OPENSSL_STRING*)(libressl.openssl.stack.sk_delete_ptr(.CHECKED_STACK_OF!("OPENSSL_STRING")(st), libressl.openssl.asn1.CHECKED_PTR_OF!(char)(ptr_)));
	}

pragma(inline, true)
auto sk_OPENSSL_STRING_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		alias sk_OPENSSL_STRING_set_cmp_func_temp = /* Temporary type */ extern (C) nothrow @nogc int function(const char**, const char**);

		return cast(sk_OPENSSL_STRING_set_cmp_func_temp)(libressl.openssl.stack.sk_set_cmp_func(.CHECKED_STACK_OF!("OPENSSL_STRING")(st), .CHECKED_SK_CMP_FUNC!("char")(cmp)));
	}

pragma(inline, true)
auto sk_OPENSSL_STRING_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("OPENSSL_STRING")(st);
	}

pragma(inline, true)
auto sk_OPENSSL_STRING_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("OPENSSL_STRING")(st);
	}

pragma(inline, true)
char* sk_OPENSSL_STRING_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return cast(char*)(libressl.openssl.stack.sk_pop(.CHECKED_STACK_OF!("OPENSSL_STRING")(st)));
	}

pragma(inline, true)
void sk_OPENSSL_STRING_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("OPENSSL_STRING")(st);
	}

pragma(inline, true)
int sk_OPENSSL_STRING_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("OPENSSL_STRING")(st);
	}

pragma(inline, true)
libressl.openssl.stack._STACK* sk_OPENSSL_BLOCK_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return cast(.stack_st_OPENSSL_BLOCK*)(libressl.openssl.stack.sk_new(.CHECKED_SK_CMP_FUNC!("void")(cmp)));
	}

pragma(inline, true)
.stack_st_OPENSSL_BLOCK* sk_OPENSSL_BLOCK_new_null()

	do
	{
		return cast(.stack_st_OPENSSL_BLOCK*)(libressl.openssl.stack.sk_new_null());
	}

pragma(inline, true)
int sk_OPENSSL_BLOCK_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_push(.CHECKED_STACK_OF!("OPENSSL_BLOCK")(st), libressl.openssl.asn1.CHECKED_PTR_OF!(void)(val));
	}

pragma(inline, true)
int sk_OPENSSL_BLOCK_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_find(.CHECKED_STACK_OF!("OPENSSL_BLOCK")(st), libressl.openssl.asn1.CHECKED_PTR_OF!(void)(val));
	}

pragma(inline, true)
void* sk_OPENSSL_BLOCK_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return cast(OPENSSL_BLOCK)(libressl.openssl.stack.sk_value(.CHECKED_STACK_OF!("OPENSSL_BLOCK")(st), i));
	}

pragma(inline, true)
int sk_OPENSSL_BLOCK_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("OPENSSL_BLOCK")(st);
	}

pragma(inline, true)
void sk_OPENSSL_BLOCK_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		libressl.openssl.stack.sk_pop_free(.CHECKED_STACK_OF!("OPENSSL_BLOCK")(st), .CHECKED_SK_FREE_FUNC2!(OPENSSL_BLOCK)(free_func));
	}

pragma(inline, true)
int sk_OPENSSL_BLOCK_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return libressl.openssl.stack.sk_insert(.CHECKED_STACK_OF!("OPENSSL_BLOCK")(st), libressl.openssl.asn1.CHECKED_PTR_OF!(void)(val), i);
	}

pragma(inline, true)
void sk_OPENSSL_BLOCK_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("OPENSSL_BLOCK")(st);
	}

pragma(inline, true)
void* sk_OPENSSL_BLOCK_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_set(.CHECKED_STACK_OF!("OPENSSL_BLOCK")(st), i, libressl.openssl.asn1.CHECKED_PTR_OF!(void)(val));
	}

pragma(inline, true)
void sk_OPENSSL_BLOCK_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("OPENSSL_BLOCK")(st);
	}

pragma(inline, true)
int sk_OPENSSL_BLOCK_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_unshift(.CHECKED_STACK_OF!("OPENSSL_BLOCK")(st), libressl.openssl.asn1.CHECKED_PTR_OF!(void)(val));
	}

/+
pragma(inline, true)
int sk_OPENSSL_BLOCK_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_find_ex(cast(libressl.openssl.stack._STACK*)(CHECKED_CONST_PTR_OF(.stack_st_OPENSSL_BLOCK, st)), CHECKED_CONST_PTR_OF(void, val));
	}
+/

pragma(inline, true)
auto sk_OPENSSL_BLOCK_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("OPENSSL_BLOCK")(st, i);
	}

pragma(inline, true)
void* sk_OPENSSL_BLOCK_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return cast(OPENSSL_BLOCK*)(libressl.openssl.stack.sk_delete_ptr(.CHECKED_STACK_OF!("OPENSSL_BLOCK")(st), libressl.openssl.asn1.CHECKED_PTR_OF!(void)(ptr_)));
	}

pragma(inline, true)
auto sk_OPENSSL_BLOCK_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		alias sk_OPENSSL_BLOCK_set_cmp_func_temp = /* Temporary type */ extern (C) nothrow @nogc int function(const void**, const void**);

		return cast(sk_OPENSSL_BLOCK_set_cmp_func_temp)(libressl.openssl.stack.sk_set_cmp_func(.CHECKED_STACK_OF!("OPENSSL_BLOCK")(st), .CHECKED_SK_CMP_FUNC!("void")(cmp)));
	}

pragma(inline, true)
auto sk_OPENSSL_BLOCK_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("OPENSSL_BLOCK")(st);
	}

pragma(inline, true)
auto sk_OPENSSL_BLOCK_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("OPENSSL_BLOCK")(st);
	}

pragma(inline, true)
void* sk_OPENSSL_BLOCK_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return cast(void*)(libressl.openssl.stack.sk_pop(.CHECKED_STACK_OF!("OPENSSL_BLOCK")(st)));
	}

pragma(inline, true)
void sk_OPENSSL_BLOCK_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("OPENSSL_BLOCK")(st);
	}

pragma(inline, true)
int sk_OPENSSL_BLOCK_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("OPENSSL_BLOCK")(st);
	}

pragma(inline, true)
libressl.openssl.stack._STACK* sk_OPENSSL_PSTRING_new(CMP_TYPE)(CMP_TYPE cmp)

	do
	{
		return cast(libressl.openssl.txt_db.stack_st_OPENSSL_PSTRING*)(libressl.openssl.stack.sk_new(.CHECKED_SK_CMP_FUNC!("OPENSSL_STRING")(cmp)));
	}

pragma(inline, true)
libressl.openssl.txt_db.stack_st_OPENSSL_PSTRING* sk_OPENSSL_PSTRING_new_null()

	do
	{
		return cast(libressl.openssl.txt_db.stack_st_OPENSSL_PSTRING*)(libressl.openssl.stack.sk_new_null());
	}

pragma(inline, true)
int sk_OPENSSL_PSTRING_push(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_push(.CHECKED_STACK_OF!("OPENSSL_PSTRING")(st), libressl.openssl.asn1.CHECKED_PTR_OF!(.OPENSSL_STRING)(val));
	}

pragma(inline, true)
int sk_OPENSSL_PSTRING_find(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_find(.CHECKED_STACK_OF!("OPENSSL_PSTRING")(st), libressl.openssl.asn1.CHECKED_PTR_OF!(.OPENSSL_STRING)(val));
	}

pragma(inline, true)
void* sk_OPENSSL_PSTRING_value(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return cast(OPENSSL_PSTRING)(libressl.openssl.stack.sk_value(.CHECKED_STACK_OF!("OPENSSL_PSTRING")(st), i));
	}

pragma(inline, true)
int sk_OPENSSL_PSTRING_num(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_num!("OPENSSL_PSTRING")(st);
	}

pragma(inline, true)
void sk_OPENSSL_PSTRING_pop_free(ST_TYPE, FREE_FUNC)(ST_TYPE st, FREE_FUNC free_func)

	do
	{
		libressl.openssl.stack.sk_pop_free(.CHECKED_STACK_OF!("OPENSSL_PSTRING")(st), .CHECKED_SK_FREE_FUNC2!(OPENSSL_PSTRING)(free_func));
	}

pragma(inline, true)
int sk_OPENSSL_PSTRING_insert(ST_TYPE, VAL_TYPE, I_TYPE)(ST_TYPE st, VAL_TYPE val, I_TYPE i)

	do
	{
		return libressl.openssl.stack.sk_insert(.CHECKED_STACK_OF!("OPENSSL_PSTRING")(st), libressl.openssl.asn1.CHECKED_PTR_OF!(.OPENSSL_STRING)(val), i);
	}

pragma(inline, true)
void sk_OPENSSL_PSTRING_free(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_free!("OPENSSL_PSTRING")(st);
	}

pragma(inline, true)
void* sk_OPENSSL_PSTRING_set(ST_TYPE, I_TYPE, VAL_TYPE)(ST_TYPE st, I_TYPE i, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_set(.CHECKED_STACK_OF!("OPENSSL_PSTRING")(st), i, libressl.openssl.asn1.CHECKED_PTR_OF!(.OPENSSL_STRING)(val));
	}

pragma(inline, true)
void sk_OPENSSL_PSTRING_zero(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_zero!("OPENSSL_PSTRING")(st);
	}

pragma(inline, true)
int sk_OPENSSL_PSTRING_unshift(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_unshift(.CHECKED_STACK_OF!("OPENSSL_PSTRING")(st), libressl.openssl.asn1.CHECKED_PTR_OF!(.OPENSSL_STRING)(val));
	}

/+
pragma(inline, true)
int sk_OPENSSL_PSTRING_find_ex(ST_TYPE, VAL_TYPE)(ST_TYPE st, VAL_TYPE val)

	do
	{
		return libressl.openssl.stack.sk_find_ex(cast(libressl.openssl.stack._STACK*)(CHECKED_CONST_PTR_OF(libressl.openssl.txt_db.stack_st_OPENSSL_PSTRING, st)), CHECKED_CONST_PTR_OF(.OPENSSL_STRING, val));
	}
+/

pragma(inline, true)
auto sk_OPENSSL_PSTRING_delete(ST_TYPE, I_TYPE)(ST_TYPE st, I_TYPE i)

	do
	{
		return .SKM_sk_delete!("OPENSSL_PSTRING")(st, i);
	}

pragma(inline, true)
void* sk_OPENSSL_PSTRING_delete_ptr(ST_TYPE, PTR_TYPE)(ST_TYPE st, PTR_TYPE ptr_)

	do
	{
		return cast(OPENSSL_PSTRING*)(libressl.openssl.stack.sk_delete_ptr(.CHECKED_STACK_OF!("OPENSSL_PSTRING")(st), libressl.openssl.asn1.CHECKED_PTR_OF!(.OPENSSL_STRING)(ptr_)));
	}

pragma(inline, true)
auto sk_OPENSSL_PSTRING_set_cmp_func(ST_TYPE, CMP_TYPE)(ST_TYPE st, CMP_TYPE cmp)

	do
	{
		alias sk_OPENSSL_PSTRING_set_cmp_func_temp = /* Temporary type */ extern (C) nothrow @nogc int function(const .OPENSSL_STRING**, const .OPENSSL_STRING**);

		return cast(sk_OPENSSL_PSTRING_set_cmp_func_temp)(libressl.openssl.stack.sk_set_cmp_func(.CHECKED_STACK_OF!("OPENSSL_PSTRING")(st), .CHECKED_SK_CMP_FUNC!("OPENSSL_STRING")(cmp)));
	}

pragma(inline, true)
auto sk_OPENSSL_PSTRING_dup(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_dup!("OPENSSL_PSTRING")(st);
	}

pragma(inline, true)
auto sk_OPENSSL_PSTRING_shift(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_shift!("OPENSSL_PSTRING")(st);
	}

pragma(inline, true)
.OPENSSL_STRING* sk_OPENSSL_PSTRING_pop(ST_TYPE)(ST_TYPE st)

	do
	{
		return cast(.OPENSSL_STRING*)(libressl.openssl.stack.sk_pop(.CHECKED_STACK_OF!("OPENSSL_PSTRING")(st)));
	}

pragma(inline, true)
void sk_OPENSSL_PSTRING_sort(ST_TYPE)(ST_TYPE st)

	do
	{
		.SKM_sk_sort!("OPENSSL_PSTRING")(st);
	}

pragma(inline, true)
int sk_OPENSSL_PSTRING_is_sorted(ST_TYPE)(ST_TYPE st)

	do
	{
		return .SKM_sk_is_sorted!("OPENSSL_PSTRING")(st);
	}

version (none) {
	version(none)
	pragma(inline, true)
	auto lh_ADDED_OBJ_new()

		do
		{
			return libressl.openssl.lhash.LHM_lh_new!("ADDED_OBJ")(added_obj);
		}

	pragma(inline, true)
	auto lh_ADDED_OBJ_insert(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_insert!("ADDED_OBJ")(lh, inst);
		}

	pragma(inline, true)
	auto lh_ADDED_OBJ_retrieve(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_retrieve!("ADDED_OBJ")(lh, inst);
		}

	pragma(inline, true)
	auto lh_ADDED_OBJ_delete(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_delete!("ADDED_OBJ")(lh, inst);
		}

	pragma(inline, true)
	void lh_ADDED_OBJ_doall(LH_TYPE, FN_TYPE)(LH_TYPE lh, FN_TYPE fn)

		do
		{
			libressl.openssl.lhash.LHM_lh_doall!("ADDED_OBJ")(lh, fn);
		}

	template lh_ADDED_OBJ_doall_arg(string lh, string fn, string arg_type, string arg)
	{
		enum lh_ADDED_OBJ_doall_arg = libressl.openssl.lhash.LHM_lh_doall_arg!("ADDED_OBJ", lh, fn, arg_type, arg);
	}

	pragma(inline, true)
	int lh_ADDED_OBJ_error(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_error!("ADDED_OBJ")(lh);
		}

	pragma(inline, true)
	core.stdc.config.c_ulong lh_ADDED_OBJ_num_items(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_num_items!("ADDED_OBJ")(lh);
		}

	pragma(inline, true)
	auto lh_ADDED_OBJ_down_load(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_down_load!("ADDED_OBJ")(lh);
		}

	version (OPENSSL_NO_BIO) {
	} else {
		pragma(inline, true)
		void lh_ADDED_OBJ_node_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_node_stats_bio!("ADDED_OBJ")(lh, out_);
			}

		pragma(inline, true)
		void lh_ADDED_OBJ_node_usage_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_node_usage_stats_bio!("ADDED_OBJ")(lh, out_);
			}

		pragma(inline, true)
		void lh_ADDED_OBJ_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_stats_bio!("ADDED_OBJ")(lh, out_);
			}
	}

	pragma(inline, true)
	void lh_ADDED_OBJ_free(LH_TYPE)(LH_TYPE lh)

		do
		{
			libressl.openssl.lhash.LHM_lh_free!("ADDED_OBJ")(lh);
		}
}

version (none) {
	version(none)
	pragma(inline, true)
	auto lh_APP_INFO_new()

		do
		{
			return libressl.openssl.lhash.LHM_lh_new!("APP_INFO")(app_info);
		}

	pragma(inline, true)
	auto lh_APP_INFO_insert(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_insert!("APP_INFO")(lh, inst);
		}

	pragma(inline, true)
	auto lh_APP_INFO_retrieve(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_retrieve!("APP_INFO")(lh, inst);
		}

	pragma(inline, true)
	auto lh_APP_INFO_delete(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_delete!("APP_INFO")(lh, inst);
		}

	pragma(inline, true)
	void lh_APP_INFO_doall(LH_TYPE, FN_TYPE)(LH_TYPE lh, FN_TYPE fn)

		do
		{
			libressl.openssl.lhash.LHM_lh_doall!("APP_INFO")(lh, fn);
		}

	template lh_APP_INFO_doall_arg(string lh, string fn, string arg_type, string arg)
	{
		enum lh_APP_INFO_doall_arg = libressl.openssl.lhash.LHM_lh_doall_arg!("APP_INFO", lh, fn, arg_type, arg);
	}

	pragma(inline, true)
	int lh_APP_INFO_error(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_error!("APP_INFO")(lh);
		}

	pragma(inline, true)
	core.stdc.config.c_ulong lh_APP_INFO_num_items(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_num_items!("APP_INFO")(lh);
		}

	pragma(inline, true)
	auto lh_APP_INFO_down_load(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_down_load!("APP_INFO")(lh);
		}

	version (OPENSSL_NO_BIO) {
	} else {
		pragma(inline, true)
		void lh_APP_INFO_node_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_node_stats_bio!("APP_INFO")(lh, out_);
			}

		pragma(inline, true)
		void lh_APP_INFO_node_usage_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_node_usage_stats_bio!("APP_INFO")(lh, out_);
			}

		pragma(inline, true)
		void lh_APP_INFO_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_stats_bio!("APP_INFO")(lh, out_);
			}
	}

	pragma(inline, true)
	void lh_APP_INFO_free(LH_TYPE)(LH_TYPE lh)

		do
		{
			libressl.openssl.lhash.LHM_lh_free!("APP_INFO")(lh);
		}
}

version(none)
pragma(inline, true)
auto lh_CONF_VALUE_new()

	do
	{
		return libressl.openssl.lhash.LHM_lh_new!("CONF_VALUE")(conf_value);
	}

pragma(inline, true)
auto lh_CONF_VALUE_insert(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_insert!("CONF_VALUE")(lh, inst);
	}

pragma(inline, true)
auto lh_CONF_VALUE_retrieve(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_retrieve!("CONF_VALUE")(lh, inst);
	}

pragma(inline, true)
auto lh_CONF_VALUE_delete(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_delete!("CONF_VALUE")(lh, inst);
	}

pragma(inline, true)
void lh_CONF_VALUE_doall(LH_TYPE, FN_TYPE)(LH_TYPE lh, FN_TYPE fn)

	do
	{
		libressl.openssl.lhash.LHM_lh_doall!("CONF_VALUE")(lh, fn);
	}

template lh_CONF_VALUE_doall_arg(string lh, string fn, string arg_type, string arg)
{
	enum lh_CONF_VALUE_doall_arg = libressl.openssl.lhash.LHM_lh_doall_arg!("CONF_VALUE", lh, fn, arg_type, arg);
}

pragma(inline, true)
int lh_CONF_VALUE_error(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_error!("CONF_VALUE")(lh);
	}

pragma(inline, true)
core.stdc.config.c_ulong lh_CONF_VALUE_num_items(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_num_items!("CONF_VALUE")(lh);
	}

pragma(inline, true)
auto lh_CONF_VALUE_down_load(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_down_load!("CONF_VALUE")(lh);
	}

version (OPENSSL_NO_BIO) {
} else {
	pragma(inline, true)
	void lh_CONF_VALUE_node_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_node_stats_bio!("CONF_VALUE")(lh, out_);
		}

	pragma(inline, true)
	void lh_CONF_VALUE_node_usage_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_node_usage_stats_bio!("CONF_VALUE")(lh, out_);
		}

	pragma(inline, true)
	void lh_CONF_VALUE_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_stats_bio!("CONF_VALUE")(lh, out_);
		}
}

pragma(inline, true)
void lh_CONF_VALUE_free(LH_TYPE)(LH_TYPE lh)

	do
	{
		libressl.openssl.lhash.LHM_lh_free!("CONF_VALUE")(lh);
	}

version(none) {
	version(none)
	pragma(inline, true)
	auto lh_ENGINE_PILE_new()

		do
		{
			return libressl.openssl.lhash.LHM_lh_new!("ENGINE_PILE")(engine_pile);
		}

	pragma(inline, true)
	auto lh_ENGINE_PILE_insert(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_insert!("ENGINE_PILE")(lh, inst);
		}

	pragma(inline, true)
	auto lh_ENGINE_PILE_retrieve(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_retrieve!("ENGINE_PILE")(lh, inst);
		}

	pragma(inline, true)
	auto lh_ENGINE_PILE_delete(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_delete!("ENGINE_PILE")(lh, inst);
		}

	pragma(inline, true)
	void lh_ENGINE_PILE_doall(LH_TYPE, FN_TYPE)(LH_TYPE lh, FN_TYPE fn)

		do
		{
			libressl.openssl.lhash.LHM_lh_doall!("ENGINE_PILE")(lh, fn);
		}

	template lh_ENGINE_PILE_doall_arg(string lh, string fn, string arg_type, string arg)
	{
		enum lh_ENGINE_PILE_doall_arg = libressl.openssl.lhash.LHM_lh_doall_arg!("ENGINE_PILE", lh, fn, arg_type, arg);
	}

	pragma(inline, true)
	int lh_ENGINE_PILE_error(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_error!("ENGINE_PILE")(lh);
		}

	pragma(inline, true)
	core.stdc.config.c_ulong lh_ENGINE_PILE_num_items(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_num_items!("ENGINE_PILE")(lh);
		}

	pragma(inline, true)
	auto lh_ENGINE_PILE_down_load(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_down_load!("ENGINE_PILE")(lh);
		}

	version (OPENSSL_NO_BIO) {
	} else {
		pragma(inline, true)
		void lh_ENGINE_PILE_node_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_node_stats_bio!("ENGINE_PILE")(lh, out_);
			}

		pragma(inline, true)
		void lh_ENGINE_PILE_node_usage_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_node_usage_stats_bio!("ENGINE_PILE")(lh, out_);
			}

		pragma(inline, true)
		void lh_ENGINE_PILE_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_stats_bio!("ENGINE_PILE")(lh, out_);
			}
	}

	pragma(inline, true)
	void lh_ENGINE_PILE_free(LH_TYPE)(LH_TYPE lh)

		do
		{
			libressl.openssl.lhash.LHM_lh_free!("ENGINE_PILE")(lh);
		}
}

version(none)
pragma(inline, true)
auto lh_ERR_STATE_new()

	do
	{
		return libressl.openssl.lhash.LHM_lh_new!("ERR_STATE")(err_state);
	}

pragma(inline, true)
auto lh_ERR_STATE_insert(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_insert!("ERR_STATE")(lh, inst);
	}

pragma(inline, true)
auto lh_ERR_STATE_retrieve(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_retrieve!("ERR_STATE")(lh, inst);
	}

pragma(inline, true)
auto lh_ERR_STATE_delete(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_delete!("ERR_STATE")(lh, inst);
	}

pragma(inline, true)
void lh_ERR_STATE_doall(LH_TYPE, FN_TYPE)(LH_TYPE lh, FN_TYPE fn)

	do
	{
		libressl.openssl.lhash.LHM_lh_doall!("ERR_STATE")(lh, fn);
	}

template lh_ERR_STATE_doall_arg(string lh, string fn, string arg_type, string arg)
{
	enum lh_ERR_STATE_doall_arg = libressl.openssl.lhash.LHM_lh_doall_arg!("ERR_STATE", lh, fn, arg_type, arg);
}

pragma(inline, true)
int lh_ERR_STATE_error(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_error!("ERR_STATE")(lh);
	}

pragma(inline, true)
core.stdc.config.c_ulong lh_ERR_STATE_num_items(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_num_items!("ERR_STATE")(lh);
	}

pragma(inline, true)
auto lh_ERR_STATE_down_load(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_down_load!("ERR_STATE")(lh);
	}

version (OPENSSL_NO_BIO) {
} else {
	pragma(inline, true)
	void lh_ERR_STATE_node_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_node_stats_bio!("ERR_STATE")(lh, out_);
		}

	pragma(inline, true)
	void lh_ERR_STATE_node_usage_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_node_usage_stats_bio!("ERR_STATE")(lh, out_);
		}

	pragma(inline, true)
	void lh_ERR_STATE_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_stats_bio!("ERR_STATE")(lh, out_);
		}
}

pragma(inline, true)
void lh_ERR_STATE_free(LH_TYPE)(LH_TYPE lh)

	do
	{
		libressl.openssl.lhash.LHM_lh_free!("ERR_STATE")(lh);
	}

version(none)
pragma(inline, true)
auto lh_ERR_STRING_DATA_new()

	do
	{
		return libressl.openssl.lhash.LHM_lh_new!("ERR_STRING_DATA")(err_string_data);
	}

pragma(inline, true)
auto lh_ERR_STRING_DATA_insert(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_insert!("ERR_STRING_DATA")(lh, inst);
	}

pragma(inline, true)
auto lh_ERR_STRING_DATA_retrieve(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_retrieve!("ERR_STRING_DATA")(lh, inst);
	}

pragma(inline, true)
auto lh_ERR_STRING_DATA_delete(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_delete!("ERR_STRING_DATA")(lh, inst);
	}

pragma(inline, true)
void lh_ERR_STRING_DATA_doall(LH_TYPE, FN_TYPE)(LH_TYPE lh, FN_TYPE fn)

	do
	{
		libressl.openssl.lhash.LHM_lh_doall!("ERR_STRING_DATA")(lh, fn);
	}

template lh_ERR_STRING_DATA_doall_arg(string lh, string fn, string arg_type, string arg)
{
	enum lh_ERR_STRING_DATA_doall_arg = libressl.openssl.lhash.LHM_lh_doall_arg!("ERR_STRING_DATA", lh, fn, arg_type, arg);
}

pragma(inline, true)
int lh_ERR_STRING_DATA_error(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_error!("ERR_STRING_DATA")(lh);
	}

pragma(inline, true)
core.stdc.config.c_ulong lh_ERR_STRING_DATA_num_items(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_num_items!("ERR_STRING_DATA")(lh);
	}

pragma(inline, true)
auto lh_ERR_STRING_DATA_down_load(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_down_load!("ERR_STRING_DATA")(lh);
	}

version (OPENSSL_NO_BIO) {
} else {
	pragma(inline, true)
	void lh_ERR_STRING_DATA_node_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_node_stats_bio!("ERR_STRING_DATA")(lh, out_);
		}

	pragma(inline, true)
	void lh_ERR_STRING_DATA_node_usage_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_node_usage_stats_bio!("ERR_STRING_DATA")(lh, out_);
		}

	pragma(inline, true)
	void lh_ERR_STRING_DATA_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_stats_bio!("ERR_STRING_DATA")(lh, out_);
		}
}

pragma(inline, true)
void lh_ERR_STRING_DATA_free(LH_TYPE)(LH_TYPE lh)

	do
	{
		libressl.openssl.lhash.LHM_lh_free!("ERR_STRING_DATA")(lh);
	}

version (none) {
	version(none)
	pragma(inline, true)
	auto lh_EX_CLASS_ITEM_new()

		do
		{
			return libressl.openssl.lhash.LHM_lh_new!("EX_CLASS_ITEM")(ex_class_item);
		}

	pragma(inline, true)
	auto lh_EX_CLASS_ITEM_insert(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_insert!("EX_CLASS_ITEM")(lh, inst);
		}

	pragma(inline, true)
	auto lh_EX_CLASS_ITEM_retrieve(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_retrieve!("EX_CLASS_ITEM")(lh, inst);
		}

	pragma(inline, true)
	auto lh_EX_CLASS_ITEM_delete(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_delete!("EX_CLASS_ITEM")(lh, inst);
		}

	pragma(inline, true)
	void lh_EX_CLASS_ITEM_doall(LH_TYPE, FN_TYPE)(LH_TYPE lh, FN_TYPE fn)

		do
		{
			libressl.openssl.lhash.LHM_lh_doall!("EX_CLASS_ITEM")(lh, fn);
		}

	template lh_EX_CLASS_ITEM_doall_arg(string lh, string fn, string arg_type, string arg)
	{
		enum lh_EX_CLASS_ITEM_doall_arg = libressl.openssl.lhash.LHM_lh_doall_arg!("EX_CLASS_ITEM", lh, fn, arg_type, arg);
	}

	pragma(inline, true)
	int lh_EX_CLASS_ITEM_error(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_error!("EX_CLASS_ITEM")(lh);
		}

	pragma(inline, true)
	core.stdc.config.c_ulong lh_EX_CLASS_ITEM_num_items(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_num_items!("EX_CLASS_ITEM")(lh);
		}

	pragma(inline, true)
	auto lh_EX_CLASS_ITEM_down_load(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_down_load!("EX_CLASS_ITEM")(lh);
		}

	version (OPENSSL_NO_BIO) {
	} else {
		pragma(inline, true)
		void lh_EX_CLASS_ITEM_node_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_node_stats_bio!("EX_CLASS_ITEM")(lh, out_);
			}

		pragma(inline, true)
		void lh_EX_CLASS_ITEM_node_usage_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_node_usage_stats_bio!("EX_CLASS_ITEM")(lh, out_);
			}

		pragma(inline, true)
		void lh_EX_CLASS_ITEM_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_stats_bio!("EX_CLASS_ITEM")(lh, out_);
			}
	}

	pragma(inline, true)
	void lh_EX_CLASS_ITEM_free(LH_TYPE)(LH_TYPE lh)

		do
		{
			libressl.openssl.lhash.LHM_lh_free!("EX_CLASS_ITEM")(lh);
		}
}

version (none) {
	version(none)
	pragma(inline, true)
	auto lh_FUNCTION_new()

		do
		{
			return libressl.openssl.lhash.LHM_lh_new!("FUNCTION")(function_);
		}

	pragma(inline, true)
	auto lh_FUNCTION_insert(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_insert!("FUNCTION")(lh, inst);
		}

	pragma(inline, true)
	auto lh_FUNCTION_retrieve(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_retrieve!("FUNCTION")(lh, inst);
		}

	pragma(inline, true)
	auto lh_FUNCTION_delete(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_delete!("FUNCTION")(lh, inst);
		}

	pragma(inline, true)
	void lh_FUNCTION_doall(LH_TYPE, FN_TYPE)(LH_TYPE lh, FN_TYPE fn)

		do
		{
			libressl.openssl.lhash.LHM_lh_doall!("FUNCTION")(lh, fn);
		}

	template lh_FUNCTION_doall_arg(string lh, string fn, string arg_type, string arg)
	{
		enum lh_FUNCTION_doall_arg = libressl.openssl.lhash.LHM_lh_doall_arg!("FUNCTION", lh, fn, arg_type, arg);
	}

	pragma(inline, true)
	int lh_FUNCTION_error(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_error!("FUNCTION")(lh);
		}

	pragma(inline, true)
	core.stdc.config.c_ulong lh_FUNCTION_num_items(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_num_items!("FUNCTION")(lh);
		}

	pragma(inline, true)
	auto lh_FUNCTION_down_load(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_down_load!("FUNCTION")(lh);
		}

	version (OPENSSL_NO_BIO) {
	} else {
		pragma(inline, true)
		void lh_FUNCTION_node_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_node_stats_bio!("FUNCTION")(lh, out_);
			}

		pragma(inline, true)
		void lh_FUNCTION_node_usage_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_node_usage_stats_bio!("FUNCTION")(lh, out_);
			}

		pragma(inline, true)
		void lh_FUNCTION_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_stats_bio!("FUNCTION")(lh, out_);
			}
	}

	pragma(inline, true)
	void lh_FUNCTION_free(LH_TYPE)(LH_TYPE lh)

		do
		{
			libressl.openssl.lhash.LHM_lh_free!("FUNCTION")(lh);
		}

	version(none)
	pragma(inline, true)
	auto lh_MEM_new()

		do
		{
			return libressl.openssl.lhash.LHM_lh_new!("MEM")(mem);
		}

	pragma(inline, true)
	auto lh_MEM_insert(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_insert!("MEM")(lh, inst);
		}

	pragma(inline, true)
	auto lh_MEM_retrieve(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_retrieve!("MEM")(lh, inst);
		}

	pragma(inline, true)
	auto lh_MEM_delete(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_delete!("MEM")(lh, inst);
		}

	pragma(inline, true)
	void lh_MEM_doall(LH_TYPE, FN_TYPE)(LH_TYPE lh, FN_TYPE fn)

		do
		{
			libressl.openssl.lhash.LHM_lh_doall!("MEM")(lh, fn);
		}

	template lh_MEM_doall_arg(string lh, string fn, string arg_type, string arg)
	{
		enum lh_MEM_doall_arg = libressl.openssl.lhash.LHM_lh_doall_arg!("MEM", lh, fn, arg_type, arg);
	}

	pragma(inline, true)
	int lh_MEM_error(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_error!("MEM")(lh);
		}

	pragma(inline, true)
	core.stdc.config.c_ulong lh_MEM_num_items(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_num_items!("MEM")(lh);
		}

	pragma(inline, true)
	auto lh_MEM_down_load(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_down_load!("MEM")(lh);
		}

	version (OPENSSL_NO_BIO) {
	} else {
		pragma(inline, true)
		void lh_MEM_node_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_node_stats_bio!("MEM")(lh, out_);
			}

		pragma(inline, true)
		void lh_MEM_node_usage_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_node_usage_stats_bio!("MEM")(lh, out_);
			}

		pragma(inline, true)
		void lh_MEM_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_stats_bio!("MEM")(lh, out_);
			}
	}

	pragma(inline, true)
	void lh_MEM_free(LH_TYPE)(LH_TYPE lh)

		do
		{
			libressl.openssl.lhash.LHM_lh_free!("MEM")(lh);
		}

	version(none)
	pragma(inline, true)
	auto lh_OBJ_NAME_new()

		do
		{
			return libressl.openssl.lhash.LHM_lh_new!("OBJ_NAME")(obj_name);
		}

	pragma(inline, true)
	auto lh_OBJ_NAME_insert(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_insert!("OBJ_NAME")(lh, inst);
		}

	pragma(inline, true)
	auto lh_OBJ_NAME_retrieve(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_retrieve!("OBJ_NAME")(lh, inst);
		}

	pragma(inline, true)
	auto lh_OBJ_NAME_delete(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

		do
		{
			return libressl.openssl.lhash.LHM_lh_delete!("OBJ_NAME")(lh, inst);
		}

	pragma(inline, true)
	void lh_OBJ_NAME_doall(LH_TYPE, FN_TYPE)(LH_TYPE lh, FN_TYPE fn)

		do
		{
			libressl.openssl.lhash.LHM_lh_doall!("OBJ_NAME")(lh, fn);
		}

	template lh_OBJ_NAME_doall_arg(string lh, string fn, string arg_type, string arg)
	{
		enum lh_OBJ_NAME_doall_arg = libressl.openssl.lhash.LHM_lh_doall_arg!("OBJ_NAME", lh, fn, arg_type, arg);
	}

	pragma(inline, true)
	int lh_OBJ_NAME_error(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_error!("OBJ_NAME")(lh);
		}

	pragma(inline, true)
	core.stdc.config.c_ulong lh_OBJ_NAME_num_items(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_num_items!("OBJ_NAME")(lh);
		}

	pragma(inline, true)
	auto lh_OBJ_NAME_down_load(LH_TYPE)(LH_TYPE lh)

		do
		{
			return libressl.openssl.lhash.LHM_lh_down_load!("OBJ_NAME")(lh);
		}

	version (OPENSSL_NO_BIO) {
	} else {
		pragma(inline, true)
		void lh_OBJ_NAME_node_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_node_stats_bio!("OBJ_NAME")(lh, out_);
			}

		pragma(inline, true)
		void lh_OBJ_NAME_node_usage_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_node_usage_stats_bio!("OBJ_NAME")(lh, out_);
			}

		pragma(inline, true)
		void lh_OBJ_NAME_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

			do
			{
				libressl.openssl.lhash.LHM_lh_stats_bio!("OBJ_NAME")(lh, out_);
			}
	}

	pragma(inline, true)
	void lh_OBJ_NAME_free(LH_TYPE)(LH_TYPE lh)

		do
		{
			libressl.openssl.lhash.LHM_lh_free!("OBJ_NAME")(lh);
		}
}

version(none)
pragma(inline, true)
auto lh_OPENSSL_CSTRING_new()

	do
	{
		return libressl.openssl.lhash.LHM_lh_new!("OPENSSL_CSTRING")(openssl_cstring);
	}

pragma(inline, true)
auto lh_OPENSSL_CSTRING_insert(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_insert!("OPENSSL_CSTRING")(lh, inst);
	}

pragma(inline, true)
auto lh_OPENSSL_CSTRING_retrieve(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_retrieve!("OPENSSL_CSTRING")(lh, inst);
	}

pragma(inline, true)
auto lh_OPENSSL_CSTRING_delete(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_delete!("OPENSSL_CSTRING")(lh, inst);
	}

pragma(inline, true)
void lh_OPENSSL_CSTRING_doall(LH_TYPE, FN_TYPE)(LH_TYPE lh, FN_TYPE fn)

	do
	{
		libressl.openssl.lhash.LHM_lh_doall!("OPENSSL_CSTRING")(lh, fn);
	}

template lh_OPENSSL_CSTRING_doall_arg(string lh, string fn, string arg_type, string arg)
{
	enum lh_OPENSSL_CSTRING_doall_arg = libressl.openssl.lhash.LHM_lh_doall_arg!("OPENSSL_CSTRING", lh, fn, arg_type, arg);
}

pragma(inline, true)
int lh_OPENSSL_CSTRING_error(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_error!("OPENSSL_CSTRING")(lh);
	}

pragma(inline, true)
core.stdc.config.c_ulong lh_OPENSSL_CSTRING_num_items(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_num_items!("OPENSSL_CSTRING")(lh);
	}

pragma(inline, true)
auto lh_OPENSSL_CSTRING_down_load(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_down_load!("OPENSSL_CSTRING")(lh);
	}

version (OPENSSL_NO_BIO) {
} else {
	pragma(inline, true)
	void lh_OPENSSL_CSTRING_node_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_node_stats_bio!("OPENSSL_CSTRING")(lh, out_);
		}

	pragma(inline, true)
	void lh_OPENSSL_CSTRING_node_usage_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_node_usage_stats_bio!("OPENSSL_CSTRING")(lh, out_);
		}

	pragma(inline, true)
	void lh_OPENSSL_CSTRING_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_stats_bio!("OPENSSL_CSTRING")(lh, out_);
		}
}

pragma(inline, true)
void lh_OPENSSL_CSTRING_free(LH_TYPE)(LH_TYPE lh)

	do
	{
		libressl.openssl.lhash.LHM_lh_free!("OPENSSL_CSTRING")(lh);
	}

version(none)
pragma(inline, true)
auto lh_OPENSSL_STRING_new()

	do
	{
		return libressl.openssl.lhash.LHM_lh_new!("OPENSSL_STRING")(openssl_string);
	}

pragma(inline, true)
auto lh_OPENSSL_STRING_insert(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_insert!("OPENSSL_STRING")(lh, inst);
	}

pragma(inline, true)
auto lh_OPENSSL_STRING_retrieve(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_retrieve!("OPENSSL_STRING")(lh, inst);
	}

pragma(inline, true)
auto lh_OPENSSL_STRING_delete(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_delete!("OPENSSL_STRING")(lh, inst);
	}

pragma(inline, true)
void lh_OPENSSL_STRING_doall(LH_TYPE, FN_TYPE)(LH_TYPE lh, FN_TYPE fn)

	do
	{
		libressl.openssl.lhash.LHM_lh_doall!("OPENSSL_STRING")(lh, fn);
	}

template lh_OPENSSL_STRING_doall_arg(string lh, string fn, string arg_type, string arg)
{
	enum lh_OPENSSL_STRING_doall_arg = libressl.openssl.lhash.LHM_lh_doall_arg!("OPENSSL_STRING", lh, fn, arg_type, arg);
}

pragma(inline, true)
int lh_OPENSSL_STRING_error(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_error!("OPENSSL_STRING")(lh);
	}

pragma(inline, true)
core.stdc.config.c_ulong lh_OPENSSL_STRING_num_items(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_num_items!("OPENSSL_STRING")(lh);
	}

pragma(inline, true)
auto lh_OPENSSL_STRING_down_load(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_down_load!("OPENSSL_STRING")(lh);
	}

version (OPENSSL_NO_BIO) {
} else {
	pragma(inline, true)
	void lh_OPENSSL_STRING_node_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_node_stats_bio!("OPENSSL_STRING")(lh, out_);
		}

	pragma(inline, true)
	void lh_OPENSSL_STRING_node_usage_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_node_usage_stats_bio!("OPENSSL_STRING")(lh, out_);
		}

	pragma(inline, true)
	void lh_OPENSSL_STRING_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_stats_bio!("OPENSSL_STRING")(lh, out_);
		}
}

pragma(inline, true)
void lh_OPENSSL_STRING_free(LH_TYPE)(LH_TYPE lh)

	do
	{
		libressl.openssl.lhash.LHM_lh_free!("OPENSSL_STRING")(lh);
	}

version(none)
pragma(inline, true)
auto lh_SSL_SESSION_new()

	do
	{
		return libressl.openssl.lhash.LHM_lh_new!("SSL_SESSION")(ssl_session);
	}

pragma(inline, true)
auto lh_SSL_SESSION_insert(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_insert!("SSL_SESSION")(lh, inst);
	}

pragma(inline, true)
auto lh_SSL_SESSION_retrieve(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_retrieve!("SSL_SESSION")(lh, inst);
	}

pragma(inline, true)
auto lh_SSL_SESSION_delete(LH_TYPE, INST_TYPE)(LH_TYPE lh, INST_TYPE inst)

	do
	{
		return libressl.openssl.lhash.LHM_lh_delete!("SSL_SESSION")(lh, inst);
	}

pragma(inline, true)
void lh_SSL_SESSION_doall(LH_TYPE, FN_TYPE)(LH_TYPE lh, FN_TYPE fn)

	do
	{
		libressl.openssl.lhash.LHM_lh_doall!("SSL_SESSION")(lh, fn);
	}

template lh_SSL_SESSION_doall_arg(string lh, string fn, string arg_type, string arg)
{
	enum lh_SSL_SESSION_doall_arg = libressl.openssl.lhash.LHM_lh_doall_arg!("SSL_SESSION", lh, fn, arg_type, arg);
}

pragma(inline, true)
int lh_SSL_SESSION_error(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_error!("SSL_SESSION")(lh);
	}

pragma(inline, true)
core.stdc.config.c_ulong lh_SSL_SESSION_num_items(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_num_items!("SSL_SESSION")(lh);
	}

pragma(inline, true)
auto lh_SSL_SESSION_down_load(LH_TYPE)(LH_TYPE lh)

	do
	{
		return libressl.openssl.lhash.LHM_lh_down_load!("SSL_SESSION")(lh);
	}

version (OPENSSL_NO_BIO) {
} else {
	pragma(inline, true)
	void lh_SSL_SESSION_node_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_node_stats_bio!("SSL_SESSION")(lh, out_);
		}

	pragma(inline, true)
	void lh_SSL_SESSION_node_usage_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_node_usage_stats_bio!("SSL_SESSION")(lh, out_);
		}

	pragma(inline, true)
	void lh_SSL_SESSION_stats_bio(LH_TYPE, OUT_TYPE)(LH_TYPE lh, OUT_TYPE out_)

		do
		{
			libressl.openssl.lhash.LHM_lh_stats_bio!("SSL_SESSION")(lh, out_);
		}
}

pragma(inline, true)
void lh_SSL_SESSION_free(LH_TYPE)(LH_TYPE lh)

	do
	{
		libressl.openssl.lhash.LHM_lh_free!("SSL_SESSION")(lh);
	}
