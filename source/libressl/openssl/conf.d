/* $OpenBSD: conf.h,v 1.16 2022/07/12 14:42:48 kn Exp $ */
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
module libressl.openssl.conf;


private static import core.stdc.config;
private static import libressl.compat.stdio;
public import libressl.openssl.bio;
public import libressl.openssl.lhash;
public import libressl.openssl.opensslconf;
public import libressl.openssl.ossl_typ;
public import libressl.openssl.safestack;
public import libressl.openssl.stack;

enum HEADER_CONF_H = true;

extern (C):
nothrow @nogc:

struct CONF_VALUE
{
	char* section;
	char* name;
	char* value;
}

//DECLARE_STACK_OF(CONF_VALUE)
struct stack_st_CONF_VALUE
{
	libressl.openssl.stack._STACK stack;
}

//DECLARE_LHASH_OF(CONF_VALUE)
struct lhash_st_CONF_VALUE
{
	int dummy;
}

alias CONF_METHOD = .conf_method_st;

struct conf_method_st
{
	const (char)* name;
	libressl.openssl.ossl_typ.CONF* function(.CONF_METHOD* meth) create;
	int function(libressl.openssl.ossl_typ.CONF* conf) init;
	int function(libressl.openssl.ossl_typ.CONF* conf) destroy;
	int function(libressl.openssl.ossl_typ.CONF* conf) destroy_data;
	int function(libressl.openssl.ossl_typ.CONF* conf, libressl.openssl.ossl_typ.BIO* bp, core.stdc.config.c_long* eline) load_bio;
	int function(const (libressl.openssl.ossl_typ.CONF)* conf, libressl.openssl.ossl_typ.BIO* bp) dump;
	int function(const (libressl.openssl.ossl_typ.CONF)* conf, char c) is_number;
	int function(const (libressl.openssl.ossl_typ.CONF)* conf, char c) to_int;
	int function(libressl.openssl.ossl_typ.CONF* conf, const (char)* name, core.stdc.config.c_long* eline) load;
}

/* Module definitions */
struct conf_imodule_st;
struct conf_module_st;

alias CONF_IMODULE = .conf_imodule_st;
alias CONF_MODULE = .conf_module_st;

//DECLARE_STACK_OF(CONF_MODULE)
struct stack_st_CONF_MODULE
{
	libressl.openssl.stack._STACK stack;
}

//DECLARE_STACK_OF(CONF_IMODULE)
struct stack_st_CONF_IMODULE
{
	libressl.openssl.stack._STACK stack;
}

/* DSO module function typedefs */
private alias conf_init_func = /* Not a function pointer type */ extern (C) nothrow @nogc int function(.CONF_IMODULE* md, const (libressl.openssl.ossl_typ.CONF)* cnf);
private alias conf_finish_func = /* Not a function pointer type */ extern (C) nothrow @nogc void function(.CONF_IMODULE* md);

enum CONF_MFLAGS_IGNORE_ERRORS = 0x01;
enum CONF_MFLAGS_IGNORE_RETURN_CODES = 0x02;
enum CONF_MFLAGS_SILENT = 0x04;
enum CONF_MFLAGS_NO_DSO = 0x08;
enum CONF_MFLAGS_IGNORE_MISSING_FILE = 0x10;
enum CONF_MFLAGS_DEFAULT_SECTION = 0x20;

int CONF_set_default_method(.CONF_METHOD* meth);
void CONF_set_nconf(libressl.openssl.ossl_typ.CONF* conf, .lhash_st_CONF_VALUE * hash);
.lhash_st_CONF_VALUE* CONF_load(.lhash_st_CONF_VALUE * conf, const (char)* file, core.stdc.config.c_long* eline);
.lhash_st_CONF_VALUE* CONF_load_fp(.lhash_st_CONF_VALUE * conf, libressl.compat.stdio.FILE* fp, core.stdc.config.c_long* eline);
.lhash_st_CONF_VALUE* CONF_load_bio(.lhash_st_CONF_VALUE * conf, libressl.openssl.ossl_typ.BIO* bp, core.stdc.config.c_long* eline);
.stack_st_CONF_VALUE* CONF_get_section(.lhash_st_CONF_VALUE * conf, const (char)* section);
char* CONF_get_string(.lhash_st_CONF_VALUE * conf, const (char)* group, const (char)* name);
core.stdc.config.c_long CONF_get_number(.lhash_st_CONF_VALUE * conf, const (char)* group, const (char)* name);
void CONF_free(.lhash_st_CONF_VALUE * conf);
int CONF_dump_fp(.lhash_st_CONF_VALUE * conf, libressl.compat.stdio.FILE* out_);
int CONF_dump_bio(.lhash_st_CONF_VALUE * conf, libressl.openssl.ossl_typ.BIO* out_);

void OPENSSL_config(const (char)* config_name);
void OPENSSL_no_config();

/**
 * New conf code.  The semantics are different from the functions above.
 * If that wasn't the case, the above functions would have been replaced
 */
struct conf_st
{
	.CONF_METHOD* meth;
	void* meth_data;
	.lhash_st_CONF_VALUE* data;
}

libressl.openssl.ossl_typ.CONF* NCONF_new(.CONF_METHOD* meth);
.CONF_METHOD* NCONF_default();
.CONF_METHOD* NCONF_WIN32();
void NCONF_free(libressl.openssl.ossl_typ.CONF* conf);
void NCONF_free_data(libressl.openssl.ossl_typ.CONF* conf);

int NCONF_load(libressl.openssl.ossl_typ.CONF* conf, const (char)* file, core.stdc.config.c_long* eline);
int NCONF_load_fp(libressl.openssl.ossl_typ.CONF* conf, libressl.compat.stdio.FILE* fp, core.stdc.config.c_long* eline);
int NCONF_load_bio(libressl.openssl.ossl_typ.CONF* conf, libressl.openssl.ossl_typ.BIO* bp, core.stdc.config.c_long* eline);
.stack_st_CONF_VALUE* NCONF_get_section(const (libressl.openssl.ossl_typ.CONF)* conf, const (char)* section);
char* NCONF_get_string(const (libressl.openssl.ossl_typ.CONF)* conf, const (char)* group, const (char)* name);
int NCONF_get_number_e(const (libressl.openssl.ossl_typ.CONF)* conf, const (char)* group, const (char)* name, core.stdc.config.c_long* result);
int NCONF_dump_fp(const (libressl.openssl.ossl_typ.CONF)* conf, libressl.compat.stdio.FILE* out_);
int NCONF_dump_bio(const (libressl.openssl.ossl_typ.CONF)* conf, libressl.openssl.ossl_typ.BIO* out_);

alias NCONF_get_number = .NCONF_get_number_e;

/* Module functions */

int CONF_modules_load(const (libressl.openssl.ossl_typ.CONF)* cnf, const (char)* appname, core.stdc.config.c_ulong flags);
int CONF_modules_load_file(const (char)* filename, const (char)* appname, core.stdc.config.c_ulong flags);
void CONF_modules_unload(int all);
void CONF_modules_finish();
void CONF_modules_free();
int CONF_module_add(const (char)* name, .conf_init_func ifunc, .conf_finish_func ffunc);

const (char)* CONF_imodule_get_name(const (.CONF_IMODULE)* md);
const (char)* CONF_imodule_get_value(const (.CONF_IMODULE)* md);
void* CONF_imodule_get_usr_data(const (.CONF_IMODULE)* md);
void CONF_imodule_set_usr_data(.CONF_IMODULE* md, void* usr_data);
.CONF_MODULE* CONF_imodule_get_module(const (.CONF_IMODULE)* md);
core.stdc.config.c_ulong CONF_imodule_get_flags(const (.CONF_IMODULE)* md);
void CONF_imodule_set_flags(.CONF_IMODULE* md, core.stdc.config.c_ulong flags);
void* CONF_module_get_usr_data(.CONF_MODULE* pmod);
void CONF_module_set_usr_data(.CONF_MODULE* pmod, void* usr_data);

char* CONF_get1_default_config_file();

int CONF_parse_list(const (char)* list, int sep, int nospc, int function(const (char)* elem, int len, void* usr) nothrow @nogc list_cb, void* arg);

void OPENSSL_load_builtin_modules();

void ERR_load_CONF_strings();

/* Error codes for the CONF functions. */

/* Function codes. */
enum CONF_F_CONF_DUMP_FP = 104;
enum CONF_F_CONF_LOAD = 100;
enum CONF_F_CONF_LOAD_BIO = 102;
enum CONF_F_CONF_LOAD_FP = 103;
enum CONF_F_CONF_MODULES_LOAD = 116;
enum CONF_F_CONF_PARSE_LIST = 119;
enum CONF_F_DEF_LOAD = 120;
enum CONF_F_DEF_LOAD_BIO = 121;
enum CONF_F_MODULE_INIT = 115;
enum CONF_F_MODULE_LOAD_DSO = 117;
enum CONF_F_MODULE_RUN = 118;
enum CONF_F_NCONF_DUMP_BIO = 105;
enum CONF_F_NCONF_DUMP_FP = 106;
enum CONF_F_NCONF_GET_NUMBER = 107;
enum CONF_F_NCONF_GET_NUMBER_E = 112;
enum CONF_F_NCONF_GET_SECTION = 108;
enum CONF_F_NCONF_GET_STRING = 109;
enum CONF_F_NCONF_LOAD = 113;
enum CONF_F_NCONF_LOAD_BIO = 110;
enum CONF_F_NCONF_LOAD_FP = 114;
enum CONF_F_NCONF_NEW = 111;
enum CONF_F_STR_COPY = 101;

/* Reason codes. */
enum CONF_R_ERROR_LOADING_DSO = 110;
enum CONF_R_LIST_CANNOT_BE_NULL = 115;
enum CONF_R_MISSING_CLOSE_SQUARE_BRACKET = 100;
enum CONF_R_MISSING_EQUAL_SIGN = 101;
enum CONF_R_MISSING_FINISH_FUNCTION = 111;
enum CONF_R_MISSING_INIT_FUNCTION = 112;
enum CONF_R_MODULE_INITIALIZATION_ERROR = 109;
enum CONF_R_NO_CLOSE_BRACE = 102;
enum CONF_R_NO_CONF = 105;
enum CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE = 106;
enum CONF_R_NO_SECTION = 107;
enum CONF_R_NO_SUCH_FILE = 114;
enum CONF_R_NO_VALUE = 108;
enum CONF_R_UNABLE_TO_CREATE_NEW_SECTION = 103;
enum CONF_R_UNKNOWN_MODULE_NAME = 113;
enum CONF_R_VARIABLE_EXPANSION_TOO_LONG = 116;
enum CONF_R_VARIABLE_HAS_NO_VALUE = 104;
