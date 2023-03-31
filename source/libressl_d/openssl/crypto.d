/* $OpenBSD: crypto.h,v 1.57 2022/09/11 17:26:51 tb Exp $ */
/* ====================================================================
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECDH support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */
module libressl_d.openssl.crypto;


private static import core.stdc.config;
public import core.stdc.stdint;
public import libressl_d.compat.stdio;
public import libressl_d.compat.stdlib;
public import libressl_d.openssl.opensslconf;
public import libressl_d.openssl.opensslv;
public import libressl_d.openssl.ossl_typ;
public import libressl_d.openssl.safestack;
public import libressl_d.openssl.stack;

extern (C):
nothrow @nogc:

/* Backward compatibility to SSLeay */
/*
 * This is more to be used to check the correct DLL is being used
 * in the MS world.
 */
enum SSLEAY_VERSION_NUMBER = libressl_d.openssl.opensslv.OPENSSL_VERSION_NUMBER;
enum SSLEAY_VERSION = 0;

/**
 * no longer supported
 */
@disable
enum SSLEAY_OPTIONS = 1;

enum SSLEAY_CFLAGS = 2;
enum SSLEAY_BUILT_ON = 3;
enum SSLEAY_PLATFORM = 4;
enum SSLEAY_DIR = 5;

/*
 * When changing the CRYPTO_LOCK_* list, be sure to maintain the text lock
 * names in cryptlib.c
 */

enum CRYPTO_LOCK_ERR = 1;
enum CRYPTO_LOCK_EX_DATA = 2;
enum CRYPTO_LOCK_X509 = 3;
enum CRYPTO_LOCK_X509_INFO = 4;
enum CRYPTO_LOCK_X509_PKEY = 5;
enum CRYPTO_LOCK_X509_CRL = 6;
enum CRYPTO_LOCK_X509_REQ = 7;
enum CRYPTO_LOCK_DSA = 8;
enum CRYPTO_LOCK_RSA = 9;
enum CRYPTO_LOCK_EVP_PKEY = 10;
enum CRYPTO_LOCK_X509_STORE = 11;
enum CRYPTO_LOCK_SSL_CTX = 12;
enum CRYPTO_LOCK_SSL_CERT = 13;
enum CRYPTO_LOCK_SSL_SESSION = 14;
enum CRYPTO_LOCK_SSL_SESS_CERT = 15;
enum CRYPTO_LOCK_SSL = 16;
enum CRYPTO_LOCK_SSL_METHOD = 17;
enum CRYPTO_LOCK_RAND = 18;
enum CRYPTO_LOCK_RAND2 = 19;
enum CRYPTO_LOCK_MALLOC = 20;
enum CRYPTO_LOCK_BIO = 21;
enum CRYPTO_LOCK_GETHOSTBYNAME = 22;
enum CRYPTO_LOCK_GETSERVBYNAME = 23;
enum CRYPTO_LOCK_READDIR = 24;
enum CRYPTO_LOCK_RSA_BLINDING = 25;
enum CRYPTO_LOCK_DH = 26;
enum CRYPTO_LOCK_MALLOC2 = 27;
enum CRYPTO_LOCK_DSO = 28;
enum CRYPTO_LOCK_DYNLOCK = 29;
enum CRYPTO_LOCK_ENGINE = 30;
enum CRYPTO_LOCK_UI = 31;
enum CRYPTO_LOCK_ECDSA = 32;
enum CRYPTO_LOCK_EC = 33;
enum CRYPTO_LOCK_ECDH = 34;
enum CRYPTO_LOCK_BN = 35;
enum CRYPTO_LOCK_EC_PRE_COMP = 36;
enum CRYPTO_LOCK_STORE = 37;
enum CRYPTO_LOCK_COMP = 38;
enum CRYPTO_LOCK_FIPS = 39;
enum CRYPTO_LOCK_FIPS2 = 40;
enum CRYPTO_NUM_LOCKS = 41;

enum CRYPTO_LOCK = 1;
enum CRYPTO_UNLOCK = 2;
enum CRYPTO_READ = 4;
enum CRYPTO_WRITE = 8;

version (CRYPTO_w_lock) {
} else {
	pragma(inline, true)
	void CRYPTO_w_lock(int type)

		do
		{
			.CRYPTO_lock(.CRYPTO_LOCK | .CRYPTO_WRITE, type, null, 0);
		}

	pragma(inline, true)
	void CRYPTO_w_unlock(int type)

		do
		{
			.CRYPTO_lock(.CRYPTO_UNLOCK | .CRYPTO_WRITE, type, null, 0);
		}

	pragma(inline, true)
	void CRYPTO_r_lock(int type)

		do
		{
			.CRYPTO_lock(.CRYPTO_LOCK | .CRYPTO_READ, type, null, 0);
		}

	pragma(inline, true)
	void CRYPTO_r_unlock(int type)

		do
		{
			.CRYPTO_lock(.CRYPTO_UNLOCK | .CRYPTO_READ, type, null, 0);
		}

	pragma(inline, true)
	int CRYPTO_add(int* addr, int amount, int type)

		do
		{
			return .CRYPTO_add_lock(addr, amount, type, null, 0);
		}
}

/**
 * Some applications as well as some parts of OpenSSL need to allocate
 * and deallocate locks in a dynamic fashion.  The following typedef
 * makes this possible in a type-safe manner.
 */
alias CRYPTO_dynlock_value = void;

/**
 * CRYPTO_dynlock_value has to be defined by the application.
 */
struct CRYPTO_dynlock
{
	int references;
	.CRYPTO_dynlock_value* data;
}

/*
 * The following can be used to detect memory leaks in the SSLeay library.
 * It used, it turns on malloc checking
 */

/**
 * an enume
 */
enum CRYPTO_MEM_CHECK_OFF = 0x00;

/**
 * a bit
 */
enum CRYPTO_MEM_CHECK_ON = 0x01;

///Ditto
enum CRYPTO_MEM_CHECK_ENABLE = 0x02;

/**
 * an enume
 */
enum CRYPTO_MEM_CHECK_DISABLE = 0x03;

/*
 * The following are bit values to turn on or off options connected to the
 * malloc checking functionality
 */

/**
 * Adds time to the memory checking information
 */
/* a bit */
enum V_CRYPTO_MDEBUG_TIME = 0x01;

/**
 * Adds thread number to the memory checking information
 */
/* a bit */
enum V_CRYPTO_MDEBUG_THREAD = 0x02;

enum V_CRYPTO_MDEBUG_ALL = .V_CRYPTO_MDEBUG_TIME | .V_CRYPTO_MDEBUG_THREAD;

/**
 * predec of the BIO type
 */
alias BIO_dummy = libressl_d.openssl.ossl_typ.bio_st;

struct crypto_ex_data_st
{
	.stack_st_void* sk;
}

//DECLARE_STACK_OF(void)
struct stack_st_void
{
	libressl_d.openssl.stack._STACK stack;
}

/**
 * This stuff is basically class callback functions
 * The current classes are SSL_CTX, SSL, SSL_SESSION, and a few more
 */
struct crypto_ex_data_func_st
{
	/**
	 * Arbitary core.stdc.config.c_long
	 */
	core.stdc.config.c_long argl;

	/**
	 * Arbitary void *
	 */
	void* argp;

	libressl_d.openssl.ossl_typ.CRYPTO_EX_new new_func;
	libressl_d.openssl.ossl_typ.CRYPTO_EX_free free_func;
	libressl_d.openssl.ossl_typ.CRYPTO_EX_dup dup_func;
}

alias CRYPTO_EX_DATA_FUNCS = .crypto_ex_data_func_st;

//DECLARE_STACK_OF(CRYPTO_EX_DATA_FUNCS)
struct stack_st_CRYPTO_EX_DATA_FUNCS
{
	libressl_d.openssl.stack._STACK stack;
}

/*
 * Per class, we have a STACK of CRYPTO_EX_DATA_FUNCS for each CRYPTO_EX_DATA
 * entry.
 */

enum CRYPTO_EX_INDEX_BIO = 0;
enum CRYPTO_EX_INDEX_SSL = 1;
enum CRYPTO_EX_INDEX_SSL_CTX = 2;
enum CRYPTO_EX_INDEX_SSL_SESSION = 3;
enum CRYPTO_EX_INDEX_X509_STORE = 4;
enum CRYPTO_EX_INDEX_X509_STORE_CTX = 5;
enum CRYPTO_EX_INDEX_RSA = 6;
enum CRYPTO_EX_INDEX_DSA = 7;
enum CRYPTO_EX_INDEX_DH = 8;
enum CRYPTO_EX_INDEX_ENGINE = 9;
enum CRYPTO_EX_INDEX_X509 = 10;
enum CRYPTO_EX_INDEX_UI = 11;
enum CRYPTO_EX_INDEX_ECDSA = 12;
enum CRYPTO_EX_INDEX_ECDH = 13;
enum CRYPTO_EX_INDEX_COMP = 14;
enum CRYPTO_EX_INDEX_STORE = 15;
enum CRYPTO_EX_INDEX_EC_KEY = 16;

/**
 * Dynamically assigned indexes start from this value (don't use directly, use
 * via CRYPTO_ex_data_new_class).
 */
enum CRYPTO_EX_INDEX_USER = 100;

version (LIBRESSL_INTERNAL) {
} else {
	pragma(inline, true)
	pure nothrow @safe @nogc @live
	int CRYPTO_malloc_init()

		do
		{
			return 0;
		}

	pragma(inline, true)
	pure nothrow @safe @nogc @live
	int CRYPTO_malloc_debug_init()

		do
		{
			return 0;
		}

	//#if defined(CRYPTO_MDEBUG_ALL) || defined(CRYPTO_MDEBUG_TIME) || defined(CRYPTO_MDEBUG_THREAD)
		/* avoid duplicate #define */
		version (CRYPTO_MDEBUG) {
		} else {
			//#define CRYPTO_MDEBUG
		}
	//#endif

	int CRYPTO_mem_ctrl(int mode);
	int CRYPTO_is_mem_check_on();

	/* for applications */
	pragma(inline, true)
	int MemCheck_start()

		do
		{
			return .CRYPTO_mem_ctrl(.CRYPTO_MEM_CHECK_ON);
		}

	pragma(inline, true)
	int MemCheck_stop()

		do
		{
			return .CRYPTO_mem_ctrl(.CRYPTO_MEM_CHECK_OFF);
		}

	pragma(inline, true)
	void* OPENSSL_malloc(int num)

		do
		{
			return .CRYPTO_malloc(num, null, 0);
		}

	pragma(inline, true)
	char* OPENSSL_strdup(const (char)* str)

		do
		{
			return .CRYPTO_strdup(str, null, 0);
		}

	pragma(inline, true)
	void* OPENSSL_realloc(char* addr, int num)

		do
		{
			return .CRYPTO_realloc(cast(char*)(addr), cast(int)(num), null, 0);
		}

	pragma(inline, true)
	void* OPENSSL_realloc_clean(void* addr, int old_num, int num)

		do
		{
			return .CRYPTO_realloc_clean(addr, old_num, num, null, 0);
		}

	pragma(inline, true)
	void* OPENSSL_remalloc(char** addr, int num)

		do
		{
			return .CRYPTO_remalloc(cast(char**)(addr), cast(int)(num), null, 0);
		}

	alias OPENSSL_freeFunc = .CRYPTO_free;
	alias OPENSSL_free = .CRYPTO_free;

	pragma(inline, true)
	void* OPENSSL_malloc_locked(int num)

		do
		{
			return .CRYPTO_malloc_locked(cast(int)(num), null, 0);
		}

	alias OPENSSL_free_locked = .CRYPTO_free_locked;
}

const (char)* OpenSSL_version(int type);
enum OPENSSL_VERSION = 0;
enum OPENSSL_CFLAGS = 1;
enum OPENSSL_BUILT_ON = 2;
enum OPENSSL_PLATFORM = 3;
enum OPENSSL_DIR = 4;
enum OPENSSL_ENGINES_DIR = 5;
core.stdc.config.c_ulong OpenSSL_version_num();

const (char)* SSLeay_version(int type);
core.stdc.config.c_ulong SSLeay();

/* An opaque type representing an implementation of "ex_data" support */
struct st_CRYPTO_EX_DATA_IMPL;
alias CRYPTO_EX_DATA_IMPL = .st_CRYPTO_EX_DATA_IMPL;

/**
 * Return an opaque pointer to the current "ex_data" implementation
 */
const (.CRYPTO_EX_DATA_IMPL)* CRYPTO_get_ex_data_implementation();

/**
 * Sets the "ex_data" implementation to be used (if it's not too late)
 */
int CRYPTO_set_ex_data_implementation(const (.CRYPTO_EX_DATA_IMPL)* i);

/**
 * Get a new "ex_data" class, and return the corresponding "class_index"
 */
int CRYPTO_ex_data_new_class();

/**
 * Within a given class, get/register a new index
 */
int CRYPTO_get_ex_new_index(int class_index, core.stdc.config.c_long argl, void* argp, libressl_d.openssl.ossl_typ.CRYPTO_EX_new new_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_dup dup_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_free free_func);

/*
 * Initialise/duplicate/free CRYPTO_EX_DATA variables corresponding to a given
 * class (invokes whatever per-class callbacks are applicable)
 */
int CRYPTO_new_ex_data(int class_index, void* obj, libressl_d.openssl.ossl_typ.CRYPTO_EX_DATA* ad);
int CRYPTO_dup_ex_data(int class_index, libressl_d.openssl.ossl_typ.CRYPTO_EX_DATA* to, libressl_d.openssl.ossl_typ.CRYPTO_EX_DATA* from);
void CRYPTO_free_ex_data(int class_index, void* obj, libressl_d.openssl.ossl_typ.CRYPTO_EX_DATA* ad);

/*
 * Get/set data in a CRYPTO_EX_DATA variable corresponding to a particular index
 * (relative to the class type involved)
 */
int CRYPTO_set_ex_data(libressl_d.openssl.ossl_typ.CRYPTO_EX_DATA* ad, int idx, void* val);
void* CRYPTO_get_ex_data(const (libressl_d.openssl.ossl_typ.CRYPTO_EX_DATA)* ad, int idx);

/**
 * This function cleans up all "ex_data" state. It mustn't be called under
 * potential race-conditions.
 */
void CRYPTO_cleanup_all_ex_data();

void CRYPTO_lock(int mode, int type, const (char)* file, int line);
int CRYPTO_add_lock(int* pointer, int amount, int type, const (char)* file, int line);

/**
 * Don't use this structure directly.
 */
struct crypto_threadid_st
{
	void* ptr_;
	core.stdc.config.c_ulong val;
}

alias CRYPTO_THREADID = .crypto_threadid_st;
void CRYPTO_THREADID_current(.CRYPTO_THREADID* id);
int CRYPTO_THREADID_cmp(const (.CRYPTO_THREADID)* a, const (.CRYPTO_THREADID)* b);
void CRYPTO_THREADID_cpy(.CRYPTO_THREADID* dest, const (.CRYPTO_THREADID)* src);
core.stdc.config.c_ulong CRYPTO_THREADID_hash(const (.CRYPTO_THREADID)* id);

version (LIBRESSL_INTERNAL) {
} else {
	/* These functions are deprecated no-op stubs */
	void CRYPTO_set_id_callback(core.stdc.config.c_ulong function() func);
	//core.stdc.config.c_ulong (*CRYPTO_get_id_callback(void))();
	core.stdc.config.c_ulong CRYPTO_thread_id();

	int CRYPTO_get_new_lockid(char* name);
	const (char)* CRYPTO_get_lock_name(int type);

	int CRYPTO_num_locks();
	void CRYPTO_set_locking_callback(void function(int mode, int type, const (char)* file, int line) func);
	//void (*CRYPTO_get_locking_callback(void))(int mode, int type, const (char)* file, int line);
	void CRYPTO_set_add_lock_callback(int function(int* num, int mount, int type, const (char)* file, int line) func);
	//int (*CRYPTO_get_add_lock_callback(void))(int* num, int mount, int type, const (char)* file, int line);

	void CRYPTO_THREADID_set_numeric(.CRYPTO_THREADID* id, core.stdc.config.c_ulong val);
	void CRYPTO_THREADID_set_pointer(.CRYPTO_THREADID* id, void* ptr_);
	int CRYPTO_THREADID_set_callback(void function(.CRYPTO_THREADID*) threadid_func);
	//void (*CRYPTO_THREADID_get_callback(void))(.CRYPTO_THREADID*);

	int CRYPTO_get_new_dynlockid();
	void CRYPTO_destroy_dynlockid(int i);
	.CRYPTO_dynlock_value* CRYPTO_get_dynlock_value(int i);
	void CRYPTO_set_dynlock_create_callback(.CRYPTO_dynlock_value* function(const (char)* file, int line) dyn_create_function);
	void CRYPTO_set_dynlock_lock_callback(void function(int mode, .CRYPTO_dynlock_value* l, const (char)* file, int line) dyn_lock_function);
	void CRYPTO_set_dynlock_destroy_callback(void function(.CRYPTO_dynlock_value* l, const (char)* file, int line) dyn_destroy_function);
	//.CRYPTO_dynlock_value* (*CRYPTO_get_dynlock_create_callback(void))(const (char)* file, int line);
	//void (*CRYPTO_get_dynlock_lock_callback(void))(int mode, .CRYPTO_dynlock_value* l, const (char)* file, int line);
	//void (*CRYPTO_get_dynlock_destroy_callback(void))(.CRYPTO_dynlock_value* l, const (char)* file, int line);
}

/*
 * CRYPTO_set_mem_functions includes CRYPTO_set_locked_mem_functions --
 * call the latter last if you need different functions
 */
private alias CRYPTO_set_mem_functions_func1 = /* Temporary type */ extern (C) nothrow @nogc void* function(size_t);
private alias CRYPTO_set_mem_functions_func2 = /* Temporary type */ extern (C) nothrow @nogc void* function(void*, size_t);
private alias CRYPTO_set_mem_functions_func3 = /* Temporary type */ extern (C) nothrow @nogc void function(void*);
int CRYPTO_set_mem_functions(.CRYPTO_set_mem_functions_func1 m, .CRYPTO_set_mem_functions_func2 r, .CRYPTO_set_mem_functions_func3 f);

private alias CRYPTO_set_locked_mem_functions_func1 = /* Temporary type */ extern (C) nothrow @nogc void* function(size_t);
private alias CRYPTO_set_locked_mem_functions_func2 = /* Temporary type */ extern (C) nothrow @nogc void function(void*);
int CRYPTO_set_locked_mem_functions(.CRYPTO_set_locked_mem_functions_func1 m, .CRYPTO_set_locked_mem_functions_func2 free_func);

private alias CRYPTO_set_mem_ex_functions_func1 = /* Temporary type */ extern (C) nothrow @nogc void* function(size_t, const (char)*, int);
private alias CRYPTO_set_mem_ex_functions_func2 = /* Temporary type */ extern (C) nothrow @nogc void* function(void*, size_t, const (char)*, int);
private alias CRYPTO_set_mem_ex_functions_func3 = /* Temporary type */ extern (C) nothrow @nogc void function(void*);
int CRYPTO_set_mem_ex_functions(.CRYPTO_set_mem_ex_functions_func1 m, .CRYPTO_set_mem_ex_functions_func2 r, .CRYPTO_set_mem_ex_functions_func3 f);

private alias CRYPTO_set_locked_mem_ex_functions_func1 = /* Temporary type */ extern (C) nothrow @nogc void* function(size_t, const (char)*, int);
private alias CRYPTO_set_locked_mem_ex_functions_func2 = /* Temporary type */ extern (C) nothrow @nogc void function(void*);
int CRYPTO_set_locked_mem_ex_functions(.CRYPTO_set_locked_mem_ex_functions_func1 m, .CRYPTO_set_locked_mem_ex_functions_func2 free_func);

private alias CRYPTO_set_mem_debug_functions_func1 = /* Temporary type */ extern (C) nothrow @nogc void function(void*, int, const (char)*, int, int);
private alias CRYPTO_set_mem_debug_functions_func2 = /* Temporary type */ extern (C) nothrow @nogc void function(void*, void*, int, const (char)*, int, int);
private alias CRYPTO_set_mem_debug_functions_func3 = /* Temporary type */ extern (C) nothrow @nogc void function(void*, int);
private alias CRYPTO_set_mem_debug_functions_func4 = /* Temporary type */ extern (C) nothrow @nogc void function(core.stdc.config.c_long);
private alias CRYPTO_set_mem_debug_functions_func5 = /* Temporary type */ extern (C) nothrow @nogc core.stdc.config.c_long function();
int CRYPTO_set_mem_debug_functions(.CRYPTO_set_mem_debug_functions_func1 m, .CRYPTO_set_mem_debug_functions_func2 r, .CRYPTO_set_mem_debug_functions_func3 f, .CRYPTO_set_mem_debug_functions_func4 so, .CRYPTO_set_mem_debug_functions_func5 go);

private alias CRYPTO_get_mem_functions_func1 = /* Temporary type */ extern (C) nothrow @nogc void* function(size_t);
private alias CRYPTO_get_mem_functions_func2 = /* Temporary type */ extern (C) nothrow @nogc void* function(void*, size_t);
private alias CRYPTO_get_mem_functions_func3 = /* Temporary type */ extern (C) nothrow @nogc void function(void*);
void CRYPTO_get_mem_functions(.CRYPTO_get_mem_functions_func1* m, .CRYPTO_get_mem_functions_func2* r, .CRYPTO_get_mem_functions_func3* f);

private alias CRYPTO_get_locked_mem_functions_func1 = /* Temporary type */ extern (C) nothrow @nogc void* function(size_t);
private alias CRYPTO_get_locked_mem_functions_func2 = /* Temporary type */ extern (C) nothrow @nogc void function(void*);
void CRYPTO_get_locked_mem_functions(.CRYPTO_get_locked_mem_functions_func1* m, .CRYPTO_get_locked_mem_functions_func2* f);

private alias CRYPTO_get_mem_ex_functions_func1 = /* Temporary type */ extern (C) nothrow @nogc void* function(size_t, const (char)*, int);
private alias CRYPTO_get_mem_ex_functions_func2 = /* Temporary type */ extern (C) nothrow @nogc void* function(void*, size_t, const (char)*, int);
private alias CRYPTO_get_mem_ex_functions_func3 = /* Temporary type */ extern (C) nothrow @nogc void function(void*);
void CRYPTO_get_mem_ex_functions(.CRYPTO_get_mem_ex_functions_func1* m, .CRYPTO_get_mem_ex_functions_func2* r, .CRYPTO_get_mem_ex_functions_func3* f);

private alias CRYPTO_get_locked_mem_ex_functions_func1 = /* Temporary type */ extern (C) nothrow @nogc void* function(size_t, const (char)*, int);
private alias CRYPTO_get_locked_mem_ex_functions_func2 = /* Temporary type */ extern (C) nothrow @nogc void function(void*);
void CRYPTO_get_locked_mem_ex_functions(.CRYPTO_get_locked_mem_ex_functions_func1* m, .CRYPTO_get_locked_mem_ex_functions_func2* f);

private alias CRYPTO_get_mem_debug_functions_func1 = /* Temporary type */ extern (C) nothrow @nogc void function(void*, int, const (char)*, int, int);
private alias CRYPTO_get_mem_debug_functions_func2 = /* Temporary type */ extern (C) nothrow @nogc void function(void*, void*, int, const (char)*, int, int);
private alias CRYPTO_get_mem_debug_functions_func3 = /* Temporary type */ extern (C) nothrow @nogc void function(void*, int);
private alias CRYPTO_get_mem_debug_functions_func4 = /* Temporary type */ extern (C) nothrow @nogc void function(core.stdc.config.c_long);
private alias CRYPTO_get_mem_debug_functions_func5 = /* Temporary type */ extern (C) nothrow @nogc core.stdc.config.c_long function();
void CRYPTO_get_mem_debug_functions(.CRYPTO_get_mem_debug_functions_func1* m, .CRYPTO_get_mem_debug_functions_func2* r, .CRYPTO_get_mem_debug_functions_func3* f, .CRYPTO_get_mem_debug_functions_func4* so, .CRYPTO_get_mem_debug_functions_func5* go);

version (LIBRESSL_INTERNAL) {
} else {
	void* CRYPTO_malloc_locked(int num, const (char)* file, int line);
	void CRYPTO_free_locked(void* ptr_);
	void* CRYPTO_malloc(int num, const (char)* file, int line);
	char* CRYPTO_strdup(const (char)* str, const (char)* file, int line);
	void CRYPTO_free(void* ptr_);
	void* CRYPTO_realloc(void* addr, int num, const (char)* file, int line);
}

void* CRYPTO_realloc_clean(void* addr, int old_num, int num, const (char)* file, int line);
void* CRYPTO_remalloc(void* addr, int num, const (char)* file, int line);

version (LIBRESSL_INTERNAL) {
} else {
	void OPENSSL_cleanse(void* ptr_, size_t len);
}

void CRYPTO_set_mem_debug_options(core.stdc.config.c_long bits);
core.stdc.config.c_long CRYPTO_get_mem_debug_options();

pragma(inline, true)
int CRYPTO_push_info(const (char)* info)

	do
	{
		return .CRYPTO_push_info_(info, null, 0);
	}

int CRYPTO_push_info_(const (char)* info, const (char)* file, int line);
int CRYPTO_pop_info();
int CRYPTO_remove_all_info();

/*
 * Default debugging functions (enabled by CRYPTO_malloc_debug_init() macro;
 * used as default in CRYPTO_MDEBUG compilations):
 */
/*
 * The last argument has the following significance:
 *
 * 0:	called before the actual memory allocation has taken place
 * 1:	called after the actual memory allocation has taken place
 */
deprecated
void CRYPTO_dbg_malloc(void* addr, int num, const (char)* file, int line, int before_p);

deprecated
void CRYPTO_dbg_realloc(void* addr1, void* addr2, int num, const (char)* file, int line, int before_p);

deprecated
void CRYPTO_dbg_free(void* addr, int before_p);

/*
 * Tell the debugging code about options.  By default, the following values
 * apply:
 *
 * 0:                           Clear all options.
 * V_CRYPTO_MDEBUG_TIME (1):    Set the "Show Time" option.
 * V_CRYPTO_MDEBUG_THREAD (2):  Set the "Show Thread Number" option.
 * V_CRYPTO_MDEBUG_ALL (3):     1 + 2
 */
deprecated
void CRYPTO_dbg_set_options(core.stdc.config.c_long bits);

deprecated
core.stdc.config.c_long CRYPTO_dbg_get_options();

int CRYPTO_mem_leaks_fp(libressl_d.compat.stdio.FILE*);
int CRYPTO_mem_leaks(libressl_d.openssl.ossl_typ.bio_st* bio);
/* core.stdc.config.c_ulong order, char* ile, int line, int num_bytes, char* ddr */
private alias CRYPTO_MEM_LEAK_CB = /* Not a function pointer type */ extern (C) nothrow @nogc int* function(core.stdc.config.c_ulong, const (char)*, int, int, void*);
int CRYPTO_mem_leaks_cb(.CRYPTO_MEM_LEAK_CB cb);

/**
 * die if we have to
 */
void OpenSSLDie(const (char)* file, int line, const (char)* assertion);
//#define OPENSSL_assert(e) cast(void)(e ? (0) : (.OpenSSLDie(&(__FILE__[0]), __LINE__, #e), 1))

core.stdc.stdint.uint64_t OPENSSL_cpu_caps();

int OPENSSL_isservice();

version (LIBRESSL_INTERNAL) {
} else {
	int FIPS_mode();
	int FIPS_mode_set(int r);

	void OPENSSL_init();

	/**
	 * CRYPTO_memcmp returns zero iff the |len| bytes at |a| and |b| are equal. It
	 * takes an amount of time dependent on |len|, but independent of the contents
	 * of |a| and |b|. Unlike memcmp, it cannot be used to put elements into a
	 * defined order as the return value when a != b is undefined, other than to be
	 * non-zero.
	 */
	int CRYPTO_memcmp(const (void)* a, const (void)* b, size_t len);
}

void ERR_load_CRYPTO_strings();

/* Error codes for the CRYPTO functions. */

/* Function codes. */
enum CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX = 100;
enum CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID = 103;
enum CRYPTO_F_CRYPTO_GET_NEW_LOCKID = 101;
enum CRYPTO_F_CRYPTO_SET_EX_DATA = 102;
enum CRYPTO_F_DEF_ADD_INDEX = 104;
enum CRYPTO_F_DEF_GET_CLASS = 105;
enum CRYPTO_F_FIPS_MODE_SET = 109;
enum CRYPTO_F_INT_DUP_EX_DATA = 106;
enum CRYPTO_F_INT_FREE_EX_DATA = 107;
enum CRYPTO_F_INT_NEW_EX_DATA = 108;

/* Reason codes. */
enum CRYPTO_R_FIPS_MODE_NOT_SUPPORTED = 101;
enum CRYPTO_R_NO_DYNLOCK_CREATE_CALLBACK = 100;

/*
 * OpenSSL compatible OPENSSL_INIT options.
 */

enum OPENSSL_INIT_NO_LOAD_CONFIG = 0x00000001L;
enum OPENSSL_INIT_LOAD_CONFIG = 0x00000002L;

/* LibreSSL specific */
enum _OPENSSL_INIT_FLAG_NOOP = 0x80000000L;

/*
 * These are provided for compatibiliy, but have no effect
 * on how LibreSSL is initialized.
 */
enum OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_LOAD_CRYPTO_STRINGS = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_ADD_ALL_CIPHERS = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_ADD_ALL_DIGESTS = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_NO_ADD_ALL_CIPHERS = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_NO_ADD_ALL_DIGESTS = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_ASYNC = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_ENGINE_RDRAND = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_ENGINE_DYNAMIC = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_ENGINE_OPENSSL = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_ENGINE_CRYPTODEV = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_ENGINE_CAPI = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_ENGINE_PADLOCK = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_ENGINE_AFALG = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_reserved_internal = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_ATFORK = ._OPENSSL_INIT_FLAG_NOOP;
enum OPENSSL_INIT_ENGINE_ALL_BUILTIN = ._OPENSSL_INIT_FLAG_NOOP;

int OPENSSL_init_crypto(core.stdc.stdint.uint64_t opts, const (void)* settings);
void OPENSSL_cleanup();
