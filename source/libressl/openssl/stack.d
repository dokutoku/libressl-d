/* $OpenBSD: stack.h,v 1.9 2014/06/12 15:49:30 deraadt Exp $ */
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
module libressl.openssl.stack;


extern (C):
nothrow @nogc:

struct stack_st
{
	int num;
	char** data;
	int sorted;

	int num_alloc;
	int function(const (void)*, const (void)*) comp;
}

/* Use STACK_OF(...) instead */
alias _STACK = .stack_st;

pragma(inline, true)
pure nothrow @trusted @nogc @live
int M_sk_num(scope const ._STACK* sk)

	do
	{
		return (sk != null) ? (sk.num) : (-1);
	}

pragma(inline, true)
pure nothrow @trusted @nogc @live
char* M_sk_value(._STACK* sk, size_t n)

	do
	{
		return (sk != null) ? (sk.data[n]) : (null);
	}

int sk_num(const (._STACK)*);
void* sk_value(const (._STACK)*, int);

void* sk_set(._STACK*, int, void*);

private alias sk_new_func = /* Temporary type */ extern (C) nothrow @nogc int function(const (void)*, const (void)*);
._STACK* sk_new(.sk_new_func cmp);

._STACK* sk_new_null();
void sk_free(._STACK*);

private alias sk_pop_free_func = /* Temporary type */ extern (C) nothrow @nogc void function(void*);
void sk_pop_free(._STACK* st, .sk_pop_free_func func);

int sk_insert(._STACK* sk, void* data, int where);
void* sk_delete(._STACK* st, int loc);
void* sk_delete_ptr(._STACK* st, void* p);
int sk_find(._STACK* st, void* data);
int sk_find_ex(._STACK* st, void* data);
int sk_push(._STACK* st, void* data);
int sk_unshift(._STACK* st, void* data);
void* sk_shift(._STACK* st);
void* sk_pop(._STACK* st);
void sk_zero(._STACK* st);
//int (*sk_set_cmp_func(._STACK* sk, int function (const (void)*, const (void)*) c))(const (void)*, const (void)*);
._STACK* sk_dup(._STACK* st);
void sk_sort(._STACK* st);
int sk_is_sorted(const (._STACK)* st);