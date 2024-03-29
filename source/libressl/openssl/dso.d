/* $OpenBSD: dso.h,v 1.14 2022/12/26 07:18:51 jmc Exp $ */
/* Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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
module libressl.openssl.dso;


private static import core.stdc.config;
private static import libressl.openssl.ossl_typ;
public import libressl.openssl.crypto;

extern (C):
nothrow @nogc:

/* These values are used as commands to DSO_ctrl() */
enum DSO_CTRL_GET_FLAGS = 1;
enum DSO_CTRL_SET_FLAGS = 2;
enum DSO_CTRL_OR_FLAGS = 3;

/**
 * By default, DSO_load() will translate the provided filename into a form
 * typical for the platform (more specifically the DSO_METHOD) using the
 * dso_name_converter function of the method. Eg. win32 will transform "blah"
 * into "blah.dll", and dlfcn will transform it into "libblah.so". The
 * behaviour can be overridden by setting the name_converter callback in the DSO
 * object (using DSO_set_name_converter()). This callback could even utilise
 * the DSO_METHOD's converter too if it only wants to override behaviour for
 * one or two possible DSO methods. However, the following flag can be set in a
 * DSO to prevent *any* native name-translation at all - eg. if the caller has
 * prompted the user for a path to a driver library so the filename should be
 * interpreted as-is.
 */
enum DSO_FLAG_NO_NAME_TRANSLATION = 0x01;

/**
 * An extra flag to give if only the extension should be added as
 * translation.  This is obviously only of importance on Unix and
 * other operating systems where the translation also may prefix
 * the name with something, like 'lib', and ignored everywhere else.
 * This flag is also ignored if DSO_FLAG_NO_NAME_TRANSLATION is used
 * at the same time.
 */
enum DSO_FLAG_NAME_TRANSLATION_EXT_ONLY = 0x02;

/**
 * The following flag controls the translation of symbol names to upper
 * case.  This is currently only being implemented for OpenVMS.
 */
enum DSO_FLAG_UPCASE_SYMBOL = 0x10;

/**
 * This flag loads the library with public symbols.
 * Meaning: The exported symbols of this library are public
 * to all libraries loaded after this library.
 * At the moment only implemented in unix.
 */
enum DSO_FLAG_GLOBAL_SYMBOLS = 0x20;

alias DSO_FUNC_TYPE = extern (C) nothrow @nogc void function();

alias DSO = .dso_st;

/**
 * The function prototype used for method functions (or caller-provided
 * callbacks) that transform filenames. They are passed a DSO structure pointer
 * (or null if they are to be used independently of a DSO object) and a
 * filename to transform. They should either return null (if there is an error
 * condition) or a newly allocated string containing the transformed form that
 * the caller will need to free with free() when done.
 */
alias DSO_NAME_CONVERTER_FUNC = extern (C) nothrow @nogc char* function(.DSO*, const (char)*);

/**
 * The function prototype used for method functions (or caller-provided
 * callbacks) that merge two file specifications. They are passed a
 * DSO structure pointer (or null if they are to be used independently of
 * a DSO object) and two file specifications to merge. They should
 * either return null (if there is an error condition) or a newly allocated
 * string containing the result of merging that the caller will need
 * to free with free() when done.
 * Here, merging means that bits and pieces are taken from each of the
 * file specifications and added together in whatever fashion that is
 * sensible for the DSO method in question.  The only rule that really
 * applies is that if the two specification contain pieces of the same
 * type, the copy from the first string takes priority.  One could see
 * it as the first specification is the one given by the user and the
 * second being a bunch of defaults to add on if they're missing in the
 * first.
 */
alias DSO_MERGER_FUNC = extern (C) nothrow @nogc char* function(.DSO*, const (char)*, const (char)*);

struct dso_meth_st
{
	const (char)* name;

	/**
	 * Loads a shared library, NB: new DSO_METHODs must ensure that a
	 * successful load populates the loaded_filename field, and likewise a
	 * successful unload frees and NULLs it out.
	 */
	int function(.DSO* dso) dso_load;

	/**
	 * Unloads a shared library
	 */
	int function(.DSO* dso) dso_unload;

	/**
	 * Binds a variable
	 */
	void* function(.DSO* dso, const (char)* symname) dso_bind_var;

	/**
	 * Binds a function - assumes a return type of DSO_FUNC_TYPE.
	 * This should be cast to the real function prototype by the
	 * caller. Platforms that don't have compatible representations
	 * for different prototypes (this is possible within ANSI C)
	 * are highly unlikely to have shared libraries at all, let
	 * alone a DSO_METHOD implemented for them.
	 */
	.DSO_FUNC_TYPE function(.DSO* dso, const (char)* symname) dso_bind_func;

	/**
	 * The generic (yuck) "ctrl()" function. NB: Negative return
	 * values (rather than zero) indicate errors.
	 */
	core.stdc.config.c_long function(.DSO* dso, int cmd, core.stdc.config.c_long larg, void* parg) dso_ctrl;

	/**
	 * The default DSO_METHOD-specific function for converting filenames to
	 * a canonical native form.
	 */
	.DSO_NAME_CONVERTER_FUNC dso_name_converter;

	/**
	 * The default DSO_METHOD-specific function for converting filenames to
	 * a canonical native form.
	 */
	.DSO_MERGER_FUNC dso_merger;

	/* [De]Initialisation handlers. */
	int function(.DSO* dso) init;
	int function(.DSO* dso) finish;

	/**
	 * Return pathname of the module containing location
	 */
	int function(void* addr, char* path, int sz) pathbyaddr;

	/**
	 * Perform global symbol lookup, i.e. among *all* modules
	 */
	void* function(const (char)* symname) globallookup;
}

alias DSO_METHOD = .dso_meth_st;

/* *********************************************************************/
/* The low-level handle type used to refer to a loaded shared library */

struct dso_st
{
	.DSO_METHOD* meth;

	/*
	 * Standard dlopen uses a (void *). Win32 uses a HANDLE. VMS
	 * doesn't use anything but will need to cache the filename
	 * for use in the dso_bind handler. All in all, let each
	 * method control its own destiny. "Handles" and such go in
	 * a STACK.
	 */
	libressl.openssl.crypto.stack_st_void* meth_data;
	int references;
	int flags;

	/**
	 * For use by applications etc ... use this for your bits'n'pieces,
	 * don't touch meth_data!
	 */
	libressl.openssl.ossl_typ.CRYPTO_EX_DATA ex_data;

	/**
	 * If this callback function pointer is set to non-null, then it will
	 * be used in DSO_load() in place of meth.dso_name_converter. NB: This
	 * should normally set using DSO_set_name_converter().
	 */
	.DSO_NAME_CONVERTER_FUNC name_converter;

	/**
	 * If this callback function pointer is set to non-null, then it will
	 * be used in DSO_load() in place of meth.dso_merger. NB: This
	 * should normally set using DSO_set_merger().
	 */
	.DSO_MERGER_FUNC merger;

	/**
	 * This is populated with (a copy of) the platform-independant
	 * filename used for this DSO.
	 */
	char* filename;

	/**
	 * This is populated with (a copy of) the translated filename by which
	 * the DSO was actually loaded. It is null iff the DSO is not currently
	 * loaded. NB: This is here because the filename translation process
	 * may involve a callback being invoked more than once not only to
	 * convert to a platform-specific form, but also to try different
	 * filenames in the process of trying to perform a load. As such, this
	 * variable can be used to indicate (a) whether this DSO structure
	 * corresponds to a loaded library or not, and (b) the filename with
	 * which it was actually loaded.
	 */
	char* loaded_filename;
}

.DSO* DSO_new();
.DSO* DSO_new_method(.DSO_METHOD* method);
int DSO_free(.DSO* dso);
int DSO_flags(.DSO* dso);
int DSO_up_ref(.DSO* dso);
core.stdc.config.c_long DSO_ctrl(.DSO* dso, int cmd, core.stdc.config.c_long larg, void* parg);

/**
 * This function sets the DSO's name_converter callback. If it is non-null,
 * then it will be used instead of the associated DSO_METHOD's function. If
 * oldcb is non-null then it is set to the function pointer value being
 * replaced. Return value is non-zero for success.
 */
int DSO_set_name_converter(.DSO* dso, .DSO_NAME_CONVERTER_FUNC cb, .DSO_NAME_CONVERTER_FUNC* oldcb);

/*
 * These functions can be used to get/set the platform-independant filename
 * used for a DSO. NB: set will fail if the DSO is already loaded.
 */
const (char)* DSO_get_filename(.DSO* dso);
int DSO_set_filename(.DSO* dso, const (char)* filename);

/**
 * This function will invoke the DSO's name_converter callback to translate a
 * filename, or if the callback isn't set it will instead use the DSO_METHOD's
 * converter. If "filename" is null, the "filename" in the DSO itself will be
 * used. If the DSO_FLAG_NO_NAME_TRANSLATION flag is set, then the filename is
 * simply duplicated. NB: This function is usually called from within a
 * DSO_METHOD during the processing of a DSO_load() call, and is exposed so that
 * caller-created DSO_METHODs can do the same thing. A non-null return value
 * will need to be free()'d.
 */
char* DSO_convert_filename(.DSO* dso, const (char)* filename);

/**
 * This function will invoke the DSO's merger callback to merge two file
 * specifications, or if the callback isn't set it will instead use the
 * DSO_METHOD's merger.  A non-null return value will need to be
 * free()'d.
 */
char* DSO_merge(.DSO* dso, const (char)* filespec1, const (char)* filespec2);

/**
 * If the DSO is currently loaded, this returns the filename that it was loaded
 * under, otherwise it returns null. So it is also useful as a test as to
 * whether the DSO is currently loaded. NB: This will not necessarily return
 * the same value as DSO_convert_filename(dso, dso.filename), because the
 * DSO_METHOD's load function may have tried a variety of filenames (with
 * and/or without the aid of the converters) before settling on the one it
 * actually loaded.
 */
const (char)* DSO_get_loaded_filename(.DSO* dso);

void DSO_set_default_method(.DSO_METHOD* meth);
.DSO_METHOD* DSO_get_default_method();
.DSO_METHOD* DSO_get_method(.DSO* dso);
.DSO_METHOD* DSO_set_method(.DSO* dso, .DSO_METHOD* meth);

/**
 * The all-singing all-dancing load function, you normally pass null
 * for the first and third parameters. Use DSO_up and DSO_free for
 * subsequent reference count handling. Any flags passed in will be set
 * in the constructed DSO after its init() function but before the
 * load operation. If 'dso' is non-null, 'flags' is ignored.
 */
.DSO* DSO_load(.DSO* dso, const (char)* filename, .DSO_METHOD* meth, int flags);

/**
 * This function binds to a variable inside a shared library.
 */
void* DSO_bind_var(.DSO* dso, const (char)* symname);

/**
 * This function binds to a function inside a shared library.
 */
.DSO_FUNC_TYPE DSO_bind_func(.DSO* dso, const (char)* symname);

/**
 * This method is the default, but will beg, borrow, or steal whatever
 * method should be the default on any particular platform (including
 * DSO_METH_null() if necessary).
 */
.DSO_METHOD* DSO_METHOD_openssl();

/**
 * This method is defined for all platforms - if a platform has no
 * DSO support then this will be the only method!
 */
.DSO_METHOD* DSO_METHOD_null();

/**
 * If DSO_DLFCN is defined, the standard dlfcn.h-style functions
 * (dlopen, dlclose, dlsym, etc) will be used and incorporated into
 * this method. If not, this method will return null.
 */
.DSO_METHOD* DSO_METHOD_dlfcn();

/**
 * This function writes null-terminated pathname of DSO module
 * containing 'addr' into 'sz' large caller-provided 'path' and
 * returns the number of characters [including trailing zero]
 * written to it. If 'sz' is 0 or negative, 'path' is ignored and
 * required amount of characters [including trailing zero] to
 * accommodate pathname is returned. If 'addr' is null, then
 * pathname of cryptolib itself is returned. Negative or zero
 * return value denotes error.
 */
int DSO_pathbyaddr(void* addr, char* path, int sz);

/**
 * This function should be used with caution! It looks up symbols in
 * *all* loaded modules and if module gets unloaded by somebody else
 * attempt to dereference the pointer is doomed to have fatal
 * consequences. Primary usage for this function is to probe *core*
 * system functionality, e.g. check if getnameinfo(3) is available
 * at run-time without bothering about OS-specific details such as
 * libc.so.versioning or where does it actually reside: in libc
 * itself or libsocket.
 */
void* DSO_global_lookup(const (char)* name);

void ERR_load_DSO_strings();

/* Error codes for the DSO functions. */

/* Function codes. */
enum DSO_F_BEOS_BIND_FUNC = 144;
enum DSO_F_BEOS_BIND_VAR = 145;
enum DSO_F_BEOS_LOAD = 146;
enum DSO_F_BEOS_NAME_CONVERTER = 147;
enum DSO_F_BEOS_UNLOAD = 148;
enum DSO_F_DLFCN_BIND_FUNC = 100;
enum DSO_F_DLFCN_BIND_VAR = 101;
enum DSO_F_DLFCN_LOAD = 102;
enum DSO_F_DLFCN_MERGER = 130;
enum DSO_F_DLFCN_NAME_CONVERTER = 123;
enum DSO_F_DLFCN_UNLOAD = 103;
enum DSO_F_DL_BIND_FUNC = 104;
enum DSO_F_DL_BIND_VAR = 105;
enum DSO_F_DL_LOAD = 106;
enum DSO_F_DL_MERGER = 131;
enum DSO_F_DL_NAME_CONVERTER = 124;
enum DSO_F_DL_UNLOAD = 107;
enum DSO_F_DSO_BIND_FUNC = 108;
enum DSO_F_DSO_BIND_VAR = 109;
enum DSO_F_DSO_CONVERT_FILENAME = 126;
enum DSO_F_DSO_CTRL = 110;
enum DSO_F_DSO_FREE = 111;
enum DSO_F_DSO_GET_FILENAME = 127;
enum DSO_F_DSO_GET_LOADED_FILENAME = 128;
enum DSO_F_DSO_GLOBAL_LOOKUP = 139;
enum DSO_F_DSO_LOAD = 112;
enum DSO_F_DSO_MERGE = 132;
enum DSO_F_DSO_NEW_METHOD = 113;
enum DSO_F_DSO_PATHBYADDR = 140;
enum DSO_F_DSO_SET_FILENAME = 129;
enum DSO_F_DSO_SET_NAME_CONVERTER = 122;
enum DSO_F_DSO_UP_REF = 114;
enum DSO_F_GLOBAL_LOOKUP_FUNC = 138;
enum DSO_F_PATHBYADDR = 137;
enum DSO_F_VMS_BIND_SYM = 115;
enum DSO_F_VMS_LOAD = 116;
enum DSO_F_VMS_MERGER = 133;
enum DSO_F_VMS_UNLOAD = 117;
enum DSO_F_WIN32_BIND_FUNC = 118;
enum DSO_F_WIN32_BIND_VAR = 119;
enum DSO_F_WIN32_GLOBALLOOKUP = 142;
enum DSO_F_WIN32_GLOBALLOOKUP_FUNC = 143;
enum DSO_F_WIN32_JOINER = 135;
enum DSO_F_WIN32_LOAD = 120;
enum DSO_F_WIN32_MERGER = 134;
enum DSO_F_WIN32_NAME_CONVERTER = 125;
enum DSO_F_WIN32_PATHBYADDR = 141;
enum DSO_F_WIN32_SPLITTER = 136;
enum DSO_F_WIN32_UNLOAD = 121;

/* Reason codes. */
enum DSO_R_CTRL_FAILED = 100;
enum DSO_R_DSO_ALREADY_LOADED = 110;
enum DSO_R_EMPTY_FILE_STRUCTURE = 113;
enum DSO_R_FAILURE = 114;
enum DSO_R_FILENAME_TOO_BIG = 101;
enum DSO_R_FINISH_FAILED = 102;
enum DSO_R_INCORRECT_FILE_SYNTAX = 115;
enum DSO_R_LOAD_FAILED = 103;
enum DSO_R_NAME_TRANSLATION_FAILED = 109;
enum DSO_R_NO_FILENAME = 111;
enum DSO_R_NO_FILE_SPECIFICATION = 116;
enum DSO_R_NULL_HANDLE = 104;
enum DSO_R_SET_FILENAME_FAILED = 112;
enum DSO_R_STACK_ERROR = 105;
enum DSO_R_SYM_FAILURE = 106;
enum DSO_R_UNLOAD_FAILED = 107;
enum DSO_R_UNSUPPORTED = 108;
