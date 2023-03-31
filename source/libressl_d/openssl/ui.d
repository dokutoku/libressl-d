/* $OpenBSD: ui.h,v 1.17 2023/03/10 16:41:32 tb Exp $ */
/* Written by Richard Levitte (richard@levitte.org) for the OpenSSL
 * project 2001.
 */
/* ====================================================================
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
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
module libressl.openssl.ui;


private static import core.stdc.config;
private static import libressl.openssl.stack;
public import libressl.openssl.opensslconf;
public import libressl.openssl.ossl_typ;
public import libressl.openssl.safestack;

version (OPENSSL_NO_DEPRECATED) {
} else {
	public import libressl.openssl.crypto;
}

extern (C):
nothrow @nogc:

/* Declared already in ossl_typ.h */
/* alias UI = ui_st; */
/* alias UI_METHOD = ui_method_st; */

/*
 * All the following functions return -1 or NULL on error and in some cases
 * (UI_process()) -2 if interrupted or in some other way cancelled.
 * When everything is fine, they return 0, a positive value or a non-NULL
 * pointer, all depending on their purpose.
 */

/* Creators and destructor.   */
libressl.openssl.ossl_typ.UI* UI_new();
libressl.openssl.ossl_typ.UI* UI_new_method(const (libressl.openssl.ossl_typ.UI_METHOD)* method);
void UI_free(libressl.openssl.ossl_typ.UI* ui);

/*
 * The following functions are used to add strings to be printed and prompt
 * strings to prompt for data.  The names are UI_{add,dup}_<function>_string
 * and UI_{add,dup}_input_boolean.
 *
 * UI_{add,dup}_<function>_string have the following meanings:
 *	add	add a text or prompt string.  The pointers given to these
 *		functions are used verbatim, no copying is done.
 *	dup	make a copy of the text or prompt string, then add the copy
 *		to the collection of strings in the user interface.
 *	<function>
 *		The function is a name for the functionality that the given
 *		string shall be used for.  It can be one of:
 *			input	use the string as data prompt.
 *			verify	use the string as verification prompt.  This
 *				is used to verify a previous input.
 *			info	use the string for informational output.
 *			error	use the string for error output.
 * Honestly, there's currently no difference between info and error for the
 * moment.
 *
 * UI_{add,dup}_input_boolean have the same semantics for "add" and "dup",
 * and are typically used when one wants to prompt for a yes/no response.
 *
 * All of the functions in this group take a UI and a prompt string.
 * The string input and verify addition functions also take a flag argument,
 * a buffer for the result to end up in, a minimum input size and a maximum
 * input size (the result buffer MUST be large enough to be able to contain
 * the maximum number of characters).  Additionally, the verify addition
 * functions takes another buffer to compare the result against.
 * The boolean input functions take an action description string (which should
 * be safe to ignore if the expected user action is obvious, for example with
 * a dialog box with an OK button and a Cancel button), a string of acceptable
 * characters to mean OK and to mean Cancel.  The two last strings are checked
 * to make sure they don't have common characters.  Additionally, the same
 * flag argument as for the string input is taken, as well as a result buffer.
 * The result buffer is required to be at least one byte long.  Depending on
 * the answer, the first character from the OK or the Cancel character strings
 * will be stored in the first byte of the result buffer.  No NUL will be
 * added, so the result is *not* a string.
 *
 * On success, the functions all return an index of the added information.
 * That index is useful when retrieving results with UI_get0_result().
 */
int UI_add_input_string(libressl.openssl.ossl_typ.UI* ui, const (char)* prompt, int flags, char* result_buf, int minsize, int maxsize);
int UI_dup_input_string(libressl.openssl.ossl_typ.UI* ui, const (char)* prompt, int flags, char* result_buf, int minsize, int maxsize);
int UI_add_verify_string(libressl.openssl.ossl_typ.UI* ui, const (char)* prompt, int flags, char* result_buf, int minsize, int maxsize, const (char)* test_buf);
int UI_dup_verify_string(libressl.openssl.ossl_typ.UI* ui, const (char)* prompt, int flags, char* result_buf, int minsize, int maxsize, const (char)* test_buf);
int UI_add_input_boolean(libressl.openssl.ossl_typ.UI* ui, const (char)* prompt, const (char)* action_desc, const (char)* ok_chars, const (char)* cancel_chars, int flags, char* result_buf);
int UI_dup_input_boolean(libressl.openssl.ossl_typ.UI* ui, const (char)* prompt, const (char)* action_desc, const (char)* ok_chars, const (char)* cancel_chars, int flags, char* result_buf);
int UI_add_info_string(libressl.openssl.ossl_typ.UI* ui, const (char)* text);
int UI_dup_info_string(libressl.openssl.ossl_typ.UI* ui, const (char)* text);
int UI_add_error_string(libressl.openssl.ossl_typ.UI* ui, const (char)* text);
int UI_dup_error_string(libressl.openssl.ossl_typ.UI* ui, const (char)* text);

/* These are the possible flags.  They can be or'ed together. */
/**
 * Use to have echoing of input
 */
enum UI_INPUT_FLAG_ECHO = 0x01;

/**
 * Use a default password.  Where that password is found is completely
 * up to the application, it might for example be in the user data set
 * with UI_add_user_data().  It is not recommended to have more than
 * one input in each UI being marked with this flag, or the application
 * might get confused.
 */
enum UI_INPUT_FLAG_DEFAULT_PWD = 0x02;

/**
 * Users of these routines may want to define flags of their own.  The core
 * UI won't look at those, but will pass them on to the method routines.  They
 * must use higher bits so they don't get confused with the UI bits above.
 * UI_INPUT_FLAG_USER_BASE tells which is the lowest bit to use.  A good
 * example of use is this:
 *
 *	#define MY_UI_FLAG1	(0x01 << UI_INPUT_FLAG_USER_BASE)
 */
enum UI_INPUT_FLAG_USER_BASE = 16;

/**
 * The following function helps construct a prompt.  object_desc is a
 * textual short description of the object, for example "pass phrase",
 * and object_name is the name of the object \(might be a card name or
 * a file name.
 * The returned string shall always be allocated on the heap with
 * malloc(), and need to be free'd with free().
 *
 * If the ui_method doesn't contain a pointer to a user-defined prompt
 * constructor, a default string is built, looking like this:
 *
 *	"Enter {object_desc} for {object_name}:"
 *
 * So, if object_desc has the value "pass phrase" and object_name has
 * the value "foo.key", the resulting string is:
 *
 *	"Enter pass phrase for foo.key:"
 */
char* UI_construct_prompt(libressl.openssl.ossl_typ.UI* ui_method, const (char)* object_desc, const (char)* object_name);

/**
 * The following function is used to store a pointer to user-specific data.
 * Any previous such pointer will be returned and replaced.
 *
 * For callback purposes, this function makes a lot more sense than using
 * ex_data, since the latter requires that different parts of OpenSSL or
 * applications share the same ex_data index.
 *
 * Note that the UI_OpenSSL() method completely ignores the user data.
 * Other methods may not, however.
 */
void* UI_add_user_data(libressl.openssl.ossl_typ.UI* ui, void* user_data);

/**
 * We need a user data retrieving function as well.
 */
void* UI_get0_user_data(libressl.openssl.ossl_typ.UI* ui);

/**
 * Return the result associated with a prompt given with the index i.
 */
const (char)* UI_get0_result(libressl.openssl.ossl_typ.UI* ui, int i);

/**
 * When all strings have been added, process the whole thing.
 */
int UI_process(libressl.openssl.ossl_typ.UI* ui);

/**
 * Give a user interface parametrised control commands.  This can be used to
 * send down an integer, a data pointer or a function pointer, as well as
 * be used to get information from a UI.
 */
int UI_ctrl(libressl.openssl.ossl_typ.UI* ui, int cmd, core.stdc.config.c_long i, void* p, .UI_ctrl_func f);
private alias UI_ctrl_func = /* Temporary type */ extern (C) nothrow @nogc void function();

/* The commands */
/**
 * Use UI_CONTROL_PRINT_ERRORS with the value 1 to have UI_process print the
 * OpenSSL error stack before printing any info or added error messages and
 * before any prompting.
 */
enum UI_CTRL_PRINT_ERRORS = 1;

/**
 * Check if a UI_process() is possible to do again with the same instance of
 * a user interface.  This makes UI_ctrl() return 1 if it is redoable, and 0
 * if not.
 */
enum UI_CTRL_IS_REDOABLE = 2;

/* Some methods may use extra data */
pragma(inline, true)
int UI_set_app_data(libressl.openssl.ossl_typ.UI* s, void* arg)

	do
	{
		return .UI_set_ex_data(s, 0, arg);
	}

pragma(inline, true)
void* UI_get_app_data(libressl.openssl.ossl_typ.UI* s)

	do
	{
		return .UI_get_ex_data(s, 0);
	}

int UI_get_ex_new_index(core.stdc.config.c_long argl, void* argp, libressl.openssl.ossl_typ.CRYPTO_EX_new new_func, libressl.openssl.ossl_typ.CRYPTO_EX_dup dup_func, libressl.openssl.ossl_typ.CRYPTO_EX_free free_func);
int UI_set_ex_data(libressl.openssl.ossl_typ.UI* r, int idx, void* arg);
void* UI_get_ex_data(libressl.openssl.ossl_typ.UI* r, int idx);

/* Use specific methods instead of the built-in one */
void UI_set_default_method(const (libressl.openssl.ossl_typ.UI_METHOD)* meth);
const (libressl.openssl.ossl_typ.UI_METHOD)* UI_get_default_method();
const (libressl.openssl.ossl_typ.UI_METHOD)* UI_get_method(libressl.openssl.ossl_typ.UI* ui);
const (libressl.openssl.ossl_typ.UI_METHOD)* UI_set_method(libressl.openssl.ossl_typ.UI* ui, const (libressl.openssl.ossl_typ.UI_METHOD)* meth);

/**
 * The method with all the built-in thingies
 */
libressl.openssl.ossl_typ.UI_METHOD* UI_OpenSSL();

const (libressl.openssl.ossl_typ.UI_METHOD)* UI_null();

/*
 * ---------- For method writers ----------
 * A method contains a number of functions that implement the low level
 * of the User Interface.  The functions are:
 *
 *	an opener	This function starts a session, maybe by opening
 *			a channel to a tty, or by opening a window.
 *	a writer	This function is called to write a given string,
 *			maybe to the tty, maybe as a field label in a
 *			window.
 *	a flusher	This function is called to flush everything that
 *			has been output so far.  It can be used to actually
 *			display a dialog box after it has been built.
 *	a reader	This function is called to read a given prompt,
 *			maybe from the tty, maybe from a field in a
 *			window.  Note that it's called with all string
 *			structures, not only the prompt ones, so it must
 *			check such things itself.
 *	a closer	This function closes the session, maybe by closing
 *			the channel to the tty, or closing the window.
 *
 * All these functions are expected to return:
 *
 *	 0	on error.
 *	 1	on success.
 *	-1	on out-of-band events, for example if some prompting has
 *		been canceled (by pressing Ctrl-C, for example).  This is
 *		only checked when returned by the flusher or the reader.
 *
 * The way this is used, the opener is first called, then the writer for all
 * strings, then the flusher, then the reader for all strings and finally the
 * closer.  Note that if you want to prompt from a terminal or other command
 * line interface, the best is to have the reader also write the prompts
 * instead of having the writer do it.  If you want to prompt from a dialog
 * box, the writer can be used to build up the contents of the box, and the
 * flusher to actually display the box and run the event loop until all data
 * has been given, after which the reader only grabs the given data and puts
 * them back into the UI strings.
 *
 * All method functions take a UI as argument.  Additionally, the writer and
 * the reader take a UI_STRING.
 */

/*
 * The UI_STRING type is the data structure that contains all the needed info
 * about a string or a prompt, including test data for a verification prompt.
 */
struct ui_string_st;
alias UI_STRING = .ui_string_st;

//DECLARE_STACK_OF(UI_STRING)
struct stack_st_UI_STRING
{
	libressl.openssl.stack._STACK stack;
}

/**
 * The different types of strings that are currently supported.
 * This is only needed by method authors.
 */
enum UI_string_types
{
	UIT_NONE = 0,

	/**
	 * Prompt for a string
	 */
	UIT_PROMPT,

	/**
	 * Prompt for a string and verify
	 */
	UIT_VERIFY,

	/**
	 * Prompt for a yes/no response
	 */
	UIT_BOOLEAN,

	/**
	 * Send info to the user
	 */
	UIT_INFO,

	/**
	 * Send an error message to the user
	 */
	UIT_ERROR,
}

//Declaration name in C language
enum
{
	UIT_NONE = .UI_string_types.UIT_NONE,
	UIT_PROMPT = .UI_string_types.UIT_PROMPT,
	UIT_VERIFY = .UI_string_types.UIT_VERIFY,
	UIT_BOOLEAN = .UI_string_types.UIT_BOOLEAN,
	UIT_INFO = .UI_string_types.UIT_INFO,
	UIT_ERROR = .UI_string_types.UIT_ERROR,
}

/* Create and manipulate methods */
libressl.openssl.ossl_typ.UI_METHOD* UI_create_method(const (char)* name);
void UI_destroy_method(libressl.openssl.ossl_typ.UI_METHOD* ui_method);

private alias UI_method_set_opener_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl.openssl.ossl_typ.UI* ui);
int UI_method_set_opener(libressl.openssl.ossl_typ.UI_METHOD* method, .UI_method_set_opener_func opener);

private alias UI_method_set_writer_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl.openssl.ossl_typ.UI* ui, .UI_STRING* uis);
int UI_method_set_writer(libressl.openssl.ossl_typ.UI_METHOD* method, .UI_method_set_writer_func writer);

private alias UI_method_set_flusher_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl.openssl.ossl_typ.UI* ui);
int UI_method_set_flusher(libressl.openssl.ossl_typ.UI_METHOD* method, .UI_method_set_flusher_func flusher);

private alias UI_method_set_reader_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl.openssl.ossl_typ.UI* ui, .UI_STRING* uis);
int UI_method_set_reader(libressl.openssl.ossl_typ.UI_METHOD* method, .UI_method_set_reader_func reader);

private alias UI_method_set_closer_func = /* Temporary type */ extern (C) nothrow @nogc int function(libressl.openssl.ossl_typ.UI* ui);
int UI_method_set_closer(libressl.openssl.ossl_typ.UI_METHOD* method, .UI_method_set_closer_func closer);

private alias UI_method_set_prompt_constructor_func = /* Temporary type */ extern (C) nothrow @nogc char* function(libressl.openssl.ossl_typ.UI* ui, const (char)* object_desc, const (char)* object_name);
int UI_method_set_prompt_constructor(libressl.openssl.ossl_typ.UI_METHOD* method, .UI_method_set_prompt_constructor_func prompt_constructor);

//int (*UI_method_get_opener(const (libressl.openssl.ossl_typ.UI_METHOD)* method))(libressl.openssl.ossl_typ.UI*);
//int (*UI_method_get_writer(const (libressl.openssl.ossl_typ.UI_METHOD)* method))(libressl.openssl.ossl_typ.UI*, .UI_STRING*);
//int (*UI_method_get_flusher(const (libressl.openssl.ossl_typ.UI_METHOD)* method))(libressl.openssl.ossl_typ.UI*);
//int (*UI_method_get_reader(const (libressl.openssl.ossl_typ.UI_METHOD)* method))(libressl.openssl.ossl_typ.UI*, .UI_STRING*);
//int (*UI_method_get_closer(const (libressl.openssl.ossl_typ.UI_METHOD)* method))(libressl.openssl.ossl_typ.UI*);
//char* (*UI_method_get_prompt_constructor(const (libressl.openssl.ossl_typ.UI_METHOD)* method))(libressl.openssl.ossl_typ.UI*, const (char)*, const (char)*);

/*
 * The following functions are helpers for method writers to access relevant
 * data from a UI_STRING.
 */

/**
 * Return type of the UI_STRING
 */
enum .UI_string_types UI_get_string_type(.UI_STRING* uis);

/**
 * Return input flags of the UI_STRING
 */
int UI_get_input_flags(.UI_STRING* uis);

/**
 * Return the actual string to output (the prompt, info or error)
 */
const (char)* UI_get0_output_string(.UI_STRING* uis);

/**
 * Return the optional action string to output (boolean prompt instruction)
 */
const (char)* UI_get0_action_string(.UI_STRING* uis);

/**
 * Return the result of a prompt
 */
const (char)* UI_get0_result_string(.UI_STRING* uis);

/**
 * Return the string to test the result against.  Only useful with verifies.
 */
const (char)* UI_get0_test_string(.UI_STRING* uis);

/**
 * Return the required minimum size of the result
 */
int UI_get_result_minsize(.UI_STRING* uis);

/**
 * Return the required maximum size of the result
 */
int UI_get_result_maxsize(.UI_STRING* uis);

/**
 * Set the result of a UI_STRING.
 */
int UI_set_result(libressl.openssl.ossl_typ.UI* ui, .UI_STRING* uis, const (char)* result);

/* A couple of popular utility functions */
int UI_UTIL_read_pw_string(char* buf, int length_, const (char)* prompt, int verify);
int UI_UTIL_read_pw(char* buf, char* buff, int size, const (char)* prompt, int verify);

void ERR_load_UI_strings();

/* Error codes for the UI functions. */

/* Function codes. */
enum UI_F_GENERAL_ALLOCATE_BOOLEAN = 108;
enum UI_F_GENERAL_ALLOCATE_PROMPT = 109;
enum UI_F_GENERAL_ALLOCATE_STRING = 100;
enum UI_F_UI_CTRL = 111;
enum UI_F_UI_DUP_ERROR_STRING = 101;
enum UI_F_UI_DUP_INFO_STRING = 102;
enum UI_F_UI_DUP_INPUT_BOOLEAN = 110;
enum UI_F_UI_DUP_INPUT_STRING = 103;
enum UI_F_UI_DUP_VERIFY_STRING = 106;
enum UI_F_UI_GET0_RESULT = 107;
enum UI_F_UI_NEW_METHOD = 104;
enum UI_F_UI_SET_RESULT = 105;

/* Reason codes. */
enum UI_R_COMMON_OK_AND_CANCEL_CHARACTERS = 104;
enum UI_R_INDEX_TOO_LARGE = 102;
enum UI_R_INDEX_TOO_SMALL = 103;
enum UI_R_NO_RESULT_BUFFER = 105;
enum UI_R_RESULT_TOO_LARGE = 100;
enum UI_R_RESULT_TOO_SMALL = 101;
enum UI_R_UNKNOWN_CONTROL_COMMAND = 106;
