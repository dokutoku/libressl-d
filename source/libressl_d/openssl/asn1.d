/* $OpenBSD: asn1.h,v 1.54 2020/12/08 15:06:42 tb Exp $ */
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
module libressl_d.openssl.asn1;


private static import core.stdc.config;
private static import libressl_d.compat.stdio;
private static import libressl_d.openssl.asn1t;
public import libressl_d.compat.time;
public import libressl_d.openssl.bio;
public import libressl_d.openssl.bn;
public import libressl_d.openssl.opensslconf;
public import libressl_d.openssl.ossl_typ;
public import libressl_d.openssl.safestack;
public import libressl_d.openssl.stack;

//#if !defined(OPENSSL_NO_BIO)
	//public import libressl_d.openssl.bio;
//#endif

//#if !defined(OPENSSL_NO_DEPRECATED)
	//public import libressl_d.openssl.bn;
//#endif

extern (C):
nothrow @nogc:

enum V_ASN1_UNIVERSAL = 0x00;
enum V_ASN1_APPLICATION = 0x40;
enum V_ASN1_CONTEXT_SPECIFIC = 0x80;
enum V_ASN1_PRIVATE = 0xC0;

enum V_ASN1_CONSTRUCTED = 0x20;
enum V_ASN1_PRIMITIVE_TAG = 0x1F;
enum V_ASN1_PRIMATIVE_TAG = 0x1F;

/**
 *  let the recipient choose
 */
enum V_ASN1_APP_CHOOSE = -2;

/**
 *  used in ASN1_TYPE
 */
enum V_ASN1_OTHER = -3;

/**
 *  used in ASN1 template code
 */
enum V_ASN1_ANY = -4;

/**
 *  negative flag
 */
enum V_ASN1_NEG = 0x0100;

enum V_ASN1_UNDEF = -1;
enum V_ASN1_EOC = 0;

/*
 *
 */
enum V_ASN1_BOOLEAN = 1;

enum V_ASN1_INTEGER = 2;
enum V_ASN1_NEG_INTEGER = 2 | .V_ASN1_NEG;
enum V_ASN1_BIT_STRING = 3;
enum V_ASN1_OCTET_STRING = 4;
enum V_ASN1_NULL = 5;
enum V_ASN1_OBJECT = 6;
enum V_ASN1_OBJECT_DESCRIPTOR = 7;
enum V_ASN1_EXTERNAL = 8;
enum V_ASN1_REAL = 9;
enum V_ASN1_ENUMERATED = 10;
enum V_ASN1_NEG_ENUMERATED = 10 | .V_ASN1_NEG;
enum V_ASN1_UTF8STRING = 12;
enum V_ASN1_SEQUENCE = 16;
enum V_ASN1_SET = 17;

/*
 *
 */
enum V_ASN1_NUMERICSTRING = 18;

enum V_ASN1_PRINTABLESTRING = 19;
enum V_ASN1_T61STRING = 20;

/**
 *  alias
 */
enum V_ASN1_TELETEXSTRING = 20;

/*
 *
 */
enum V_ASN1_VIDEOTEXSTRING = 21;

enum V_ASN1_IA5STRING = 22;
enum V_ASN1_UTCTIME = 23;

/*
 *
 */
enum V_ASN1_GENERALIZEDTIME = 24;

/*
 *
 */
enum V_ASN1_GRAPHICSTRING = 25;

/*
 *
 */
enum V_ASN1_ISO64STRING = 26;

/**
 *  alias
 */
enum V_ASN1_VISIBLESTRING = 26;

/*
 *
 */
enum V_ASN1_GENERALSTRING = 27;

/*
 *
 */
enum V_ASN1_UNIVERSALSTRING = 28;

enum V_ASN1_BMPSTRING = 30;

enum B_ASN1_NUMERICSTRING = 0x0001;
enum B_ASN1_PRINTABLESTRING = 0x0002;
enum B_ASN1_T61STRING = 0x0004;
enum B_ASN1_TELETEXSTRING = 0x0004;
enum B_ASN1_VIDEOTEXSTRING = 0x0008;
enum B_ASN1_IA5STRING = 0x0010;
enum B_ASN1_GRAPHICSTRING = 0x0020;
enum B_ASN1_ISO64STRING = 0x0040;
enum B_ASN1_VISIBLESTRING = 0x0040;
enum B_ASN1_GENERALSTRING = 0x0080;
enum B_ASN1_UNIVERSALSTRING = 0x0100;
enum B_ASN1_OCTET_STRING = 0x0200;
enum B_ASN1_BIT_STRING = 0x0400;
enum B_ASN1_BMPSTRING = 0x0800;
enum B_ASN1_UNKNOWN = 0x1000;
enum B_ASN1_UTF8STRING = 0x2000;
enum B_ASN1_UTCTIME = 0x4000;
enum B_ASN1_GENERALIZEDTIME = 0x8000;
enum B_ASN1_SEQUENCE = 0x010000;

/* For use with ASN1_mbstring_copy() */
enum MBSTRING_FLAG = 0x1000;
enum MBSTRING_UTF8 = .MBSTRING_FLAG;
enum MBSTRING_ASC = .MBSTRING_FLAG | 1;
enum MBSTRING_BMP = .MBSTRING_FLAG | 2;
enum MBSTRING_UNIV = .MBSTRING_FLAG | 4;

enum SMIME_OLDMIME = 0x0400;
enum SMIME_CRLFEOL = 0x0800;
enum SMIME_STREAM = 0x1000;

//DECLARE_STACK_OF(X509_ALGOR)
struct stack_st_X509_ALGOR
{
	libressl_d.openssl.stack._STACK stack;
}

//#define DECLARE_ASN1_SET_OF(type) /* filled in by mkstack.pl */
//#define IMPLEMENT_ASN1_SET_OF(type) /* nothing, no longer needed */

/**
 * We MUST make sure that, except for constness, asn1_ctx_st and
 * asn1_const_ctx are exactly the same.  Fortunately, as soon as
 * the old ASN1 parsing macros are gone, we can throw this away
 * as well...
 */
struct asn1_ctx_st
{
	/**
	 * work char pointer
	 */
	ubyte* p;

	/**
	 * end of sequence read for indefinite encoding
	 */
	int eos;

	/**
	 * error code to use when returning an error
	 */
	int error;

	/**
	 * constructed if 0x20, indefinite is 0x21
	 */
	int inf;

	/**
	 * tag from last 'get object'
	 */
	int tag;

	/**
	 * class from last 'get object'
	 */
	int xclass;

	/**
	 * length of last 'get object'
	 */
	core.stdc.config.c_long slen;

	/**
	 * largest value of p allowed
	 */
	ubyte* max;

	/**
	 * temporary variable
	 */
	ubyte* q;

	/**
	 * variable
	 */
	ubyte** pp;

	/**
	 * used in error processing
	 */
	int line;
}

alias ASN1_CTX = .asn1_ctx_st;

struct asn1_const_ctx_st
{
	/**
	 * work char pointer
	 */
	const (ubyte)* p;

	/**
	 * end of sequence read for indefinite encoding
	 */
	int eos;

	/**
	 * error code to use when returning an error
	 */
	int error;

	/**
	 * constructed if 0x20, indefinite is 0x21
	 */
	int inf;

	/**
	 * tag from last 'get object'
	 */
	int tag;

	/**
	 * class from last 'get object'
	 */
	int xclass;

	/**
	 * length of last 'get object'
	 */
	core.stdc.config.c_long slen;

	/**
	 * largest value of p allowed
	 */
	const (ubyte)* max;

	/**
	 * temporary variable
	 */
	const (ubyte)* q;

	/**
	 * variable
	 */
	const (ubyte)** pp;

	/**
	 * used in error processing
	 */
	int line;
}

alias ASN1_const_CTX = .asn1_const_ctx_st;

/*
 * These are used internally in the ASN1_OBJECT to keep track of
 * whether the names and data need to be free()ed
 */

/**
 *  internal use
 */
enum ASN1_OBJECT_FLAG_DYNAMIC = 0x01;

/**
 *  critical x509v3 object id
 */
enum ASN1_OBJECT_FLAG_CRITICAL = 0x02;

/**
 *  internal use
 */
enum ASN1_OBJECT_FLAG_DYNAMIC_STRINGS = 0x04;

/**
 *  internal use
 */
enum ASN1_OBJECT_FLAG_DYNAMIC_DATA = 0x08;

struct asn1_object_st
{
	const (char)* sn;
	const (char)* ln;

	int nid;
	int length_;

	/**
	 * data remains const after init
	 */
	const (ubyte)* data;

	/**
	 * Should we free this one
	 */
	int flags;
}

alias ASN1_OBJECT = .asn1_object_st;

/**
 *  Set if 0x07 has bits left value
 */
enum ASN1_STRING_FLAG_BITS_LEFT = 0x08;

/**
 * This indicates that the ASN1_STRING is not a real value but just a place
 * holder for the location where indefinite length constructed data should
 * be inserted in the memory buffer
 */
enum ASN1_STRING_FLAG_NDEF = 0x0010;

/**
 * This flag is used by the CMS code to indicate that a string is not
 * complete and is a place holder for content when it had all been
 * accessed. The flag will be reset when content has been written to it.
 */
enum ASN1_STRING_FLAG_CONT = 0x0020;

/**
 * This flag is used by ASN1 code to indicate an ASN1_STRING is an MSTRING
 * type.
 */
enum ASN1_STRING_FLAG_MSTRING = 0x0040;

/**
 * This is the base type that holds just about everything :-)
 */
struct asn1_string_st
{
	int length_;
	int type;
	ubyte* data;

	/**
	 * The value of the following field depends on the type being
	 * held.  It is mostly being used for BIT_STRING so if the
	 * input data has a non-zero 'unused bits' value, it will be
	 * handled correctly
	 */
	core.stdc.config.c_long flags;
}

/**
 * ASN1_ENCODING structure: this is used to save the received
 * encoding of an ASN1 type. This is useful to get round
 * problems with invalid encodings which can break signatures.
 */
struct ASN1_ENCODING_st
{
	/**
	 * DER encoding
	 */
	ubyte* enc;

	/**
	 * Length of encoding
	 */
	core.stdc.config.c_long len;

	/**
	 * set to 1 if 'enc' is invalid
	 */
	int modified;
}

alias ASN1_ENCODING = .ASN1_ENCODING_st;

/**
 * Used with ASN1 LONG type: if a core.stdc.config.c_long is set to this it is omitted
 */
enum ASN1_LONG_UNDEF = 0x7FFFFFFFL;

enum STABLE_FLAGS_MALLOC = 0x01;
enum STABLE_NO_MASK = 0x02;
enum DIRSTRING_TYPE = .B_ASN1_PRINTABLESTRING | .B_ASN1_T61STRING | .B_ASN1_BMPSTRING | .B_ASN1_UTF8STRING;
enum PKCS9STRING_TYPE = .DIRSTRING_TYPE | .B_ASN1_IA5STRING;

struct asn1_string_table_st
{
	int nid;
	core.stdc.config.c_long minsize;
	core.stdc.config.c_long maxsize;
	core.stdc.config.c_ulong mask;
	core.stdc.config.c_ulong flags;
}

alias ASN1_STRING_TABLE = .asn1_string_table_st;

//DECLARE_STACK_OF(ASN1_STRING_TABLE)
struct stack_st_ASN1_STRING_TABLE
{
	libressl_d.openssl.stack._STACK stack;
}

/* size limits: this stuff is taken straight from RFC2459 */

enum ub_name = 32768;
enum ub_common_name = 64;
enum ub_locality_name = 128;
enum ub_state_name = 128;
enum ub_organization_name = 64;
enum ub_organization_unit_name = 64;
enum ub_title = 64;
enum ub_email_address = 128;

/*
 * Declarations for template structures: for full definitions
 * see asn1t.h
 */
alias ASN1_TEMPLATE = libressl_d.openssl.asn1t.ASN1_TEMPLATE_st;
alias ASN1_TLC = libressl_d.openssl.asn1t.ASN1_TLC_st;
/* This is just an opaque pointer */
//alias ASN1_VALUE = ASN1_VALUE_st;
package alias ASN1_VALUE = void;

//#if !defined(LIBRESSL_INTERNAL)
/* Declare ASN1 functions: the implement macro in in asn1t.h */

//#define DECLARE_ASN1_FUNCTIONS(type) .DECLARE_ASN1_FUNCTIONS_name(type, type)

//#define DECLARE_ASN1_ALLOC_FUNCTIONS(type) .DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, type)

//#define DECLARE_ASN1_FUNCTIONS_name(type, name) .DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) .DECLARE_ASN1_ENCODE_FUNCTIONS(type, name, name)

//#define DECLARE_ASN1_FUNCTIONS_fname(type, itname, name) .DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) .DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name)

//#define DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name) type* d2i_##name(type** a, const (ubyte)** in_, core.stdc.config.c_long len); int i2d_##name(type* a, ubyte** out_); .DECLARE_ASN1_ITEM(itname)

//#define DECLARE_ASN1_ENCODE_FUNCTIONS_const(type, name) type* d2i_##name(type** a, const (ubyte)** in_, core.stdc.config.c_long len); int i2d_##name(const (type)* a, ubyte** out_); .DECLARE_ASN1_ITEM(name)

//#define DECLARE_ASN1_NDEF_FUNCTION(name) int i2d_##name##_NDEF(name* a, ubyte** out_);

//#define DECLARE_ASN1_FUNCTIONS_const(name) .DECLARE_ASN1_ALLOC_FUNCTIONS(name) .DECLARE_ASN1_ENCODE_FUNCTIONS_const(name, name)

//#define DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) type* name##_new(); void name##_free(type* a);

//#define DECLARE_ASN1_PRINT_FUNCTION(stname) .DECLARE_ASN1_PRINT_FUNCTION_fname(stname, stname)

//#define DECLARE_ASN1_PRINT_FUNCTION_fname(stname, fname) int fname##_print_ctx(libressl_d.openssl.bio.BIO* out_, stname* x, int indent, const (libressl_d.openssl.ossl_typ.ASN1_PCTX)* pctx);
//#endif /* !LIBRESSL_INTERNAL */

//#define D2I_OF(type) type* (*) (type**, const (ubyte)**, core.stdc.config.c_long)
//#define I2D_OF(type) int (*)(type*, ubyte**)
//#define I2D_OF_const(type) int (*)(const (type)*, ubyte**)

//#define CHECKED_D2I_OF(type, d2i) ((d2i_of_void*) ((1) ? (d2i) : ((.D2I_OF(type)) 0)))
//#define CHECKED_I2D_OF(type, i2d) ((i2d_of_void*) ((1) ? (i2d) : ((.I2D_OF(type)) 0)))
//#define CHECKED_NEW_OF(type, xnew) ((void* (*) (void) )((1) ? (xnew) : ((type * (*) (void) ) 0)))
//#define CHECKED_PTR_OF(type, p) ((void*) ((1) ? (p) : (cast(type*)(0))))
//#define CHECKED_PPTR_OF(type, p) ((void**) ((1) ? (p) : (cast(type**)(0))))

//#define TYPEDEF_D2I_OF(type) typedef type* d2i_of_##type(type**, const (ubyte)**, core.stdc.config.c_long)
//#define TYPEDEF_I2D_OF(type) typedef int i2d_of_##type(type*, ubyte**)
//#define TYPEDEF_D2I2D_OF(type) .TYPEDEF_D2I_OF(type); .TYPEDEF_I2D_OF(type)

//TYPEDEF_D2I2D_OF();

/*
 * The following macros and typedefs allow an ASN1_ITEM
 * to be embedded in a structure and referenced. Since
 * the ASN1_ITEM pointers need to be globally accessible
 * (possibly from shared libraries) they may exist in
 * different forms. On platforms that support it the
 * libressl_d.openssl.ossl_typ.ASN1_ITEM structure itself will be globally exported.
 * Other platforms will export a function that returns
 * an ASN1_ITEM pointer.
 *
 * To handle both cases transparently the macros below
 * should be used instead of hard coding an ASN1_ITEM
 * pointer in a structure.
 *
 * The structure will look like this:
 *
 * typedef struct SOMETHING_st {
 *      ...
 *      ASN1_ITEM_EXP* ptr;
 *      ...
 * } SOMETHING;
 *
 * It would be initialised as e.g.:
 *
 * SOMETHING somevar = {...,ASN1_ITEM_ref(X509),...};
 *
 * and the actual pointer extracted with:
 *
 * const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it = ASN1_ITEM_ptr(somevar.iptr);
 *
 * Finally an ASN1_ITEM pointer can be extracted from an
 * appropriate reference with: ASN1_ITEM_rptr(X509). This
 * would be used when a function takes an ASN1_ITEM * argument.
 *
 */

/**
 * ASN1_ITEM pointer exported type
 */
alias ASN1_ITEM_EXP = const libressl_d.openssl.ossl_typ.ASN1_ITEM;

//#if !defined(LIBRESSL_INTERNAL)
/*
 * Macro to obtain ASN1_ITEM pointer from exported type
 */
//#define ASN1_ITEM_ptr(iptr) (iptr)

/*
 * Macro to include ASN1_ITEM pointer from base type
 */
//#define ASN1_ITEM_ref(iptr) (&(iptr##_it))

//#define ASN1_ITEM_rptr(ref_) (&(ref##_it))

//#define DECLARE_ASN1_ITEM(name) extern const libressl_d.openssl.ossl_typ.ASN1_ITEM name##_it;
//#endif /* !LIBRESSL_INTERNAL */

/* Parameters used by ASN1_STRING_print_ex() */

/*
 * These determine which characters to escape:
 * RFC2253 special characters, control characters and
 * MSB set characters
 */

enum ASN1_STRFLGS_ESC_2253 = 1;
enum ASN1_STRFLGS_ESC_CTRL = 2;
enum ASN1_STRFLGS_ESC_MSB = 4;

/**
 * This flag determines how we do escaping: normally
 * RC2253 backslash only, set this to use backslash and
 * quote.
 */
enum ASN1_STRFLGS_ESC_QUOTE = 8;

/* These three flags are internal use only. */

/**
 * Character is a valid PrintableString character
 */
enum CHARTYPE_PRINTABLESTRING = 0x10;

/**
 * Character needs escaping if it is the first character
 */
enum CHARTYPE_FIRST_ESC_2253 = 0x20;

/**
 * Character needs escaping if it is the last character
 */
enum CHARTYPE_LAST_ESC_2253 = 0x40;

/*
 * NB the internal flags are safely reused below by flags
 * handled at the top level.
 */

/**
 * If this is set we convert all character strings
 * to UTF8 first
 */
enum ASN1_STRFLGS_UTF8_CONVERT = 0x10;

/**
 * If this is set we don't attempt to interpret content:
 * just assume all strings are 1 byte per character. This
 * will produce some pretty odd looking output!
 */
enum ASN1_STRFLGS_IGNORE_TYPE = 0x20;

/**
 * If this is set we include the string type in the output
 */
enum ASN1_STRFLGS_SHOW_TYPE = 0x40;

/*
 * This determines which strings to display and which to
 * 'dump' (hex dump of content octets or DER encoding). We can
 * only dump non character strings or everything. If we
 * don't dump 'unknown' they are interpreted as character
 * strings with 1 octet per character and are subject to
 * the usual escaping options.
 */
enum ASN1_STRFLGS_DUMP_ALL = 0x80;
enum ASN1_STRFLGS_DUMP_UNKNOWN = 0x0100;

/*
 * These determine what 'dumping' does, we can dump the
 * content octets or the DER encoding: both use the
 * RFC2253 #NNNNN notation.
 */
enum ASN1_STRFLGS_DUMP_DER = 0x0200;

/**
 * All the string flags consistent with RFC2253,
 * escaping control characters isn't essential in
 * RFC2253 but it is advisable anyway.
 */
enum ASN1_STRFLGS_RFC2253 = .ASN1_STRFLGS_ESC_2253 | .ASN1_STRFLGS_ESC_CTRL | .ASN1_STRFLGS_ESC_MSB | .ASN1_STRFLGS_UTF8_CONVERT | .ASN1_STRFLGS_DUMP_UNKNOWN | .ASN1_STRFLGS_DUMP_DER;

//DECLARE_STACK_OF(ASN1_INTEGER)
struct stack_st_ASN1_INTEGER
{
	libressl_d.openssl.stack._STACK stack;
}

//DECLARE_STACK_OF(ASN1_GENERALSTRING)
struct stack_st_ASN1_GENERALSTRING
{
	libressl_d.openssl.stack._STACK stack;
}

struct asn1_type_st
{
	int type;

	union value_
	{
		char* ptr_;
		libressl_d.openssl.ossl_typ.ASN1_BOOLEAN boolean;
		libressl_d.openssl.ossl_typ.ASN1_STRING* asn1_string;
		.ASN1_OBJECT* object;
		libressl_d.openssl.ossl_typ.ASN1_INTEGER* integer;
		libressl_d.openssl.ossl_typ.ASN1_ENUMERATED* enumerated;
		libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* bit_string;
		libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* octet_string;
		libressl_d.openssl.ossl_typ.ASN1_PRINTABLESTRING* printablestring;
		libressl_d.openssl.ossl_typ.ASN1_T61STRING* t61string;
		libressl_d.openssl.ossl_typ.ASN1_IA5STRING* ia5string;
		libressl_d.openssl.ossl_typ.ASN1_GENERALSTRING* generalstring;
		libressl_d.openssl.ossl_typ.ASN1_BMPSTRING* bmpstring;
		libressl_d.openssl.ossl_typ.ASN1_UNIVERSALSTRING* universalstring;
		libressl_d.openssl.ossl_typ.ASN1_UTCTIME* utctime;
		libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME* generalizedtime;
		libressl_d.openssl.ossl_typ.ASN1_VISIBLESTRING* visiblestring;
		libressl_d.openssl.ossl_typ.ASN1_UTF8STRING* utf8string;
		/*
		 * set and sequence are left complete and still
		 * contain the set or sequence bytes
		 */
		libressl_d.openssl.ossl_typ.ASN1_STRING* set;
		libressl_d.openssl.ossl_typ.ASN1_STRING* sequence;
		.ASN1_VALUE* asn1_value;
	}

	value_ value;
}

alias ASN1_TYPE = .asn1_type_st;

//DECLARE_STACK_OF(ASN1_TYPE)
struct stack_st_ASN1_TYPE
{
	libressl_d.openssl.stack._STACK stack;
}

alias ASN1_SEQUENCE_ANY = .stack_st_ASN1_TYPE;

.ASN1_SEQUENCE_ANY* d2i_ASN1_SEQUENCE_ANY(.ASN1_SEQUENCE_ANY** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_SEQUENCE_ANY(const (.ASN1_SEQUENCE_ANY)* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_SEQUENCE_ANY_it;
.ASN1_SEQUENCE_ANY* d2i_ASN1_SET_ANY(.ASN1_SEQUENCE_ANY** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_SET_ANY(const (.ASN1_SEQUENCE_ANY)* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_SET_ANY_it;

struct NETSCAPE_X509_st
{
	libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* header;
	libressl_d.openssl.ossl_typ.X509* cert;
}

alias NETSCAPE_X509 = .NETSCAPE_X509_st;

/**
 * This is used to contain a list of bit names
 */
struct BIT_STRING_BITNAME_st
{
	int bitnum;
	const (char)* lname;
	const (char)* sname;
}

alias BIT_STRING_BITNAME = .BIT_STRING_BITNAME_st;

enum B_ASN1_TIME = .B_ASN1_UTCTIME | .B_ASN1_GENERALIZEDTIME;

enum B_ASN1_PRINTABLE = .B_ASN1_NUMERICSTRING | .B_ASN1_PRINTABLESTRING | .B_ASN1_T61STRING | .B_ASN1_IA5STRING | .B_ASN1_BIT_STRING | .B_ASN1_UNIVERSALSTRING | .B_ASN1_BMPSTRING | .B_ASN1_UTF8STRING | .B_ASN1_SEQUENCE | .B_ASN1_UNKNOWN;

enum B_ASN1_DIRECTORYSTRING = .B_ASN1_PRINTABLESTRING | .B_ASN1_TELETEXSTRING | .B_ASN1_BMPSTRING | .B_ASN1_UNIVERSALSTRING | .B_ASN1_UTF8STRING;

enum B_ASN1_DISPLAYTEXT = .B_ASN1_IA5STRING | .B_ASN1_VISIBLESTRING | .B_ASN1_BMPSTRING | .B_ASN1_UTF8STRING;

//#if !defined(LIBRESSL_INTERNAL)
alias M_ASN1_IA5STRING_new = .ASN1_IA5STRING_new;

alias M_ASN1_INTEGER_free = .ASN1_INTEGER_free;
alias M_ASN1_ENUMERATED_free = .ASN1_ENUMERATED_free;
alias M_ASN1_OCTET_STRING_free = .ASN1_OCTET_STRING_free;

alias M_ASN1_OCTET_STRING_print = .ASN1_STRING_print;

alias M_ASN1_STRING_data = .ASN1_STRING_data;
alias M_ASN1_STRING_length = .ASN1_STRING_length;
//#endif

.ASN1_TYPE* ASN1_TYPE_new();
void ASN1_TYPE_free(.ASN1_TYPE* a);
.ASN1_TYPE* d2i_ASN1_TYPE(.ASN1_TYPE** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_TYPE(.ASN1_TYPE* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_ANY_it;

int ASN1_TYPE_get(const (.ASN1_TYPE)* a);
void ASN1_TYPE_set(.ASN1_TYPE* a, int type, void* value);
int ASN1_TYPE_set1(.ASN1_TYPE* a, int type, const (void)* value);
int ASN1_TYPE_cmp(const (.ASN1_TYPE)* a, const (.ASN1_TYPE)* b);

.ASN1_OBJECT* ASN1_OBJECT_new();
void ASN1_OBJECT_free(.ASN1_OBJECT* a);
int i2d_ASN1_OBJECT(const (.ASN1_OBJECT)* a, ubyte** pp);
.ASN1_OBJECT* c2i_ASN1_OBJECT(.ASN1_OBJECT** a, const (ubyte)** pp, core.stdc.config.c_long length_);
.ASN1_OBJECT* d2i_ASN1_OBJECT(.ASN1_OBJECT** a, const (ubyte)** pp, core.stdc.config.c_long length_);

extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_OBJECT_it;

//DECLARE_STACK_OF(ASN1_OBJECT)
struct stack_st_ASN1_OBJECT
{
	libressl_d.openssl.stack._STACK stack;
}

libressl_d.openssl.ossl_typ.ASN1_STRING* ASN1_STRING_new();
void ASN1_STRING_free(libressl_d.openssl.ossl_typ.ASN1_STRING* a);
int ASN1_STRING_copy(libressl_d.openssl.ossl_typ.ASN1_STRING* dst, const (libressl_d.openssl.ossl_typ.ASN1_STRING)* str);
libressl_d.openssl.ossl_typ.ASN1_STRING* ASN1_STRING_dup(const (libressl_d.openssl.ossl_typ.ASN1_STRING)* a);
libressl_d.openssl.ossl_typ.ASN1_STRING* ASN1_STRING_type_new(int type);
int ASN1_STRING_cmp(const (libressl_d.openssl.ossl_typ.ASN1_STRING)* a, const (libressl_d.openssl.ossl_typ.ASN1_STRING)* b);
/*
 * Since this is used to store all sorts of things, via macros, for now, make
 * its data void*
 */
int ASN1_STRING_set(libressl_d.openssl.ossl_typ.ASN1_STRING* str, const (void)* data, int len);
void ASN1_STRING_set0(libressl_d.openssl.ossl_typ.ASN1_STRING* str, void* data, int len);
int ASN1_STRING_length(const (libressl_d.openssl.ossl_typ.ASN1_STRING)* x);
void ASN1_STRING_length_set(libressl_d.openssl.ossl_typ.ASN1_STRING* x, int n);
int ASN1_STRING_type(const (libressl_d.openssl.ossl_typ.ASN1_STRING)* x);
ubyte* ASN1_STRING_data(libressl_d.openssl.ossl_typ.ASN1_STRING* x);
const (ubyte)* ASN1_STRING_get0_data(const (libressl_d.openssl.ossl_typ.ASN1_STRING)* x);

libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* ASN1_BIT_STRING_new();
void ASN1_BIT_STRING_free(libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* a);
libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* d2i_ASN1_BIT_STRING(libressl_d.openssl.ossl_typ.ASN1_BIT_STRING** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_BIT_STRING(libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_BIT_STRING_it;
int i2c_ASN1_BIT_STRING(libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* a, ubyte** pp);
libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* c2i_ASN1_BIT_STRING(libressl_d.openssl.ossl_typ.ASN1_BIT_STRING** a, const (ubyte)** pp, core.stdc.config.c_long length_);
int ASN1_BIT_STRING_set(libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* a, ubyte* d, int length_);
int ASN1_BIT_STRING_set_bit(libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* a, int n, int value);
int ASN1_BIT_STRING_get_bit(const (libressl_d.openssl.ossl_typ.ASN1_BIT_STRING)* a, int n);
int ASN1_BIT_STRING_check(const (libressl_d.openssl.ossl_typ.ASN1_BIT_STRING)* a, const (ubyte)* flags, int flags_len);

//#if !defined(OPENSSL_NO_BIO)
int ASN1_BIT_STRING_name_print(libressl_d.openssl.bio.BIO* out_, libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* bs, .BIT_STRING_BITNAME* tbl, int indent);
//#endif

int ASN1_BIT_STRING_num_asc(const (char)* name, .BIT_STRING_BITNAME* tbl);
int ASN1_BIT_STRING_set_asc(libressl_d.openssl.ossl_typ.ASN1_BIT_STRING* bs, const (char)* name, int value, .BIT_STRING_BITNAME* tbl);

int i2d_ASN1_BOOLEAN(int a, ubyte** pp);
int d2i_ASN1_BOOLEAN(int* a, const (ubyte)** pp, core.stdc.config.c_long length_);

libressl_d.openssl.ossl_typ.ASN1_INTEGER* ASN1_INTEGER_new();
void ASN1_INTEGER_free(libressl_d.openssl.ossl_typ.ASN1_INTEGER* a);
libressl_d.openssl.ossl_typ.ASN1_INTEGER* d2i_ASN1_INTEGER(libressl_d.openssl.ossl_typ.ASN1_INTEGER** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_INTEGER(libressl_d.openssl.ossl_typ.ASN1_INTEGER* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_INTEGER_it;
int i2c_ASN1_INTEGER(libressl_d.openssl.ossl_typ.ASN1_INTEGER* a, ubyte** pp);
libressl_d.openssl.ossl_typ.ASN1_INTEGER* c2i_ASN1_INTEGER(libressl_d.openssl.ossl_typ.ASN1_INTEGER** a, const (ubyte)** pp, core.stdc.config.c_long length_);
libressl_d.openssl.ossl_typ.ASN1_INTEGER* d2i_ASN1_UINTEGER(libressl_d.openssl.ossl_typ.ASN1_INTEGER** a, const (ubyte)** pp, core.stdc.config.c_long length_);
libressl_d.openssl.ossl_typ.ASN1_INTEGER* ASN1_INTEGER_dup(const (libressl_d.openssl.ossl_typ.ASN1_INTEGER)* x);
int ASN1_INTEGER_cmp(const (libressl_d.openssl.ossl_typ.ASN1_INTEGER)* x, const (libressl_d.openssl.ossl_typ.ASN1_INTEGER)* y);

libressl_d.openssl.ossl_typ.ASN1_ENUMERATED* ASN1_ENUMERATED_new();
void ASN1_ENUMERATED_free(libressl_d.openssl.ossl_typ.ASN1_ENUMERATED* a);
libressl_d.openssl.ossl_typ.ASN1_ENUMERATED* d2i_ASN1_ENUMERATED(libressl_d.openssl.ossl_typ.ASN1_ENUMERATED** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_ENUMERATED(libressl_d.openssl.ossl_typ.ASN1_ENUMERATED* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_ENUMERATED_it;

int ASN1_UTCTIME_check(const (libressl_d.openssl.ossl_typ.ASN1_UTCTIME)* a);
libressl_d.openssl.ossl_typ.ASN1_UTCTIME* ASN1_UTCTIME_set(libressl_d.openssl.ossl_typ.ASN1_UTCTIME* s, libressl_d.compat.time.time_t t);
libressl_d.openssl.ossl_typ.ASN1_UTCTIME* ASN1_UTCTIME_adj(libressl_d.openssl.ossl_typ.ASN1_UTCTIME* s, libressl_d.compat.time.time_t t, int offset_day, core.stdc.config.c_long offset_sec);
int ASN1_UTCTIME_set_string(libressl_d.openssl.ossl_typ.ASN1_UTCTIME* s, const (char)* str);

//#if !defined(LIBRESSL_INTERNAL)
int ASN1_UTCTIME_cmp_time_t(const (libressl_d.openssl.ossl_typ.ASN1_UTCTIME)* s, libressl_d.compat.time.time_t t);
//#endif /* !LIBRESSL_INTERNAL */

int ASN1_GENERALIZEDTIME_check(const (libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME)* a);
libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME* ASN1_GENERALIZEDTIME_set(libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME* s, libressl_d.compat.time.time_t t);
libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME* ASN1_GENERALIZEDTIME_adj(libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME* s, libressl_d.compat.time.time_t t, int offset_day, core.stdc.config.c_long offset_sec);
int ASN1_GENERALIZEDTIME_set_string(libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME* s, const (char)* str);

libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* ASN1_OCTET_STRING_new();
void ASN1_OCTET_STRING_free(libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* a);
libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* d2i_ASN1_OCTET_STRING(libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_OCTET_STRING(libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_OCTET_STRING_it;
libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* ASN1_OCTET_STRING_dup(const (libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING)* a);
int ASN1_OCTET_STRING_cmp(const (libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING)* a, const (libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING)* b);
int ASN1_OCTET_STRING_set(libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* str, const (ubyte)* data, int len);

libressl_d.openssl.ossl_typ.ASN1_VISIBLESTRING* ASN1_VISIBLESTRING_new();
void ASN1_VISIBLESTRING_free(libressl_d.openssl.ossl_typ.ASN1_VISIBLESTRING* a);
libressl_d.openssl.ossl_typ.ASN1_VISIBLESTRING* d2i_ASN1_VISIBLESTRING(libressl_d.openssl.ossl_typ.ASN1_VISIBLESTRING** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_VISIBLESTRING(libressl_d.openssl.ossl_typ.ASN1_VISIBLESTRING* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_VISIBLESTRING_it;
libressl_d.openssl.ossl_typ.ASN1_UNIVERSALSTRING* ASN1_UNIVERSALSTRING_new();
void ASN1_UNIVERSALSTRING_free(libressl_d.openssl.ossl_typ.ASN1_UNIVERSALSTRING* a);
libressl_d.openssl.ossl_typ.ASN1_UNIVERSALSTRING* d2i_ASN1_UNIVERSALSTRING(libressl_d.openssl.ossl_typ.ASN1_UNIVERSALSTRING** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_UNIVERSALSTRING(libressl_d.openssl.ossl_typ.ASN1_UNIVERSALSTRING* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_UNIVERSALSTRING_it;
libressl_d.openssl.ossl_typ.ASN1_UTF8STRING* ASN1_UTF8STRING_new();
void ASN1_UTF8STRING_free(libressl_d.openssl.ossl_typ.ASN1_UTF8STRING* a);
libressl_d.openssl.ossl_typ.ASN1_UTF8STRING* d2i_ASN1_UTF8STRING(libressl_d.openssl.ossl_typ.ASN1_UTF8STRING** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_UTF8STRING(libressl_d.openssl.ossl_typ.ASN1_UTF8STRING* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_UTF8STRING_it;
libressl_d.openssl.ossl_typ.ASN1_NULL* ASN1_NULL_new();
void ASN1_NULL_free(libressl_d.openssl.ossl_typ.ASN1_NULL* a);
libressl_d.openssl.ossl_typ.ASN1_NULL* d2i_ASN1_NULL(libressl_d.openssl.ossl_typ.ASN1_NULL** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_NULL(libressl_d.openssl.ossl_typ.ASN1_NULL* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_NULL_it;
libressl_d.openssl.ossl_typ.ASN1_BMPSTRING* ASN1_BMPSTRING_new();
void ASN1_BMPSTRING_free(libressl_d.openssl.ossl_typ.ASN1_BMPSTRING* a);
libressl_d.openssl.ossl_typ.ASN1_BMPSTRING* d2i_ASN1_BMPSTRING(libressl_d.openssl.ossl_typ.ASN1_BMPSTRING** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_BMPSTRING(libressl_d.openssl.ossl_typ.ASN1_BMPSTRING* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_BMPSTRING_it;

libressl_d.openssl.ossl_typ.ASN1_STRING* ASN1_PRINTABLE_new();
void ASN1_PRINTABLE_free(libressl_d.openssl.ossl_typ.ASN1_STRING* a);
libressl_d.openssl.ossl_typ.ASN1_STRING* d2i_ASN1_PRINTABLE(libressl_d.openssl.ossl_typ.ASN1_STRING** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_PRINTABLE(libressl_d.openssl.ossl_typ.ASN1_STRING* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_PRINTABLE_it;

libressl_d.openssl.ossl_typ.ASN1_STRING* DIRECTORYSTRING_new();
void DIRECTORYSTRING_free(libressl_d.openssl.ossl_typ.ASN1_STRING* a);
libressl_d.openssl.ossl_typ.ASN1_STRING* d2i_DIRECTORYSTRING(libressl_d.openssl.ossl_typ.ASN1_STRING** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_DIRECTORYSTRING(libressl_d.openssl.ossl_typ.ASN1_STRING* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM DIRECTORYSTRING_it;
libressl_d.openssl.ossl_typ.ASN1_STRING* DISPLAYTEXT_new();
void DISPLAYTEXT_free(libressl_d.openssl.ossl_typ.ASN1_STRING* a);
libressl_d.openssl.ossl_typ.ASN1_STRING* d2i_DISPLAYTEXT(libressl_d.openssl.ossl_typ.ASN1_STRING** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_DISPLAYTEXT(libressl_d.openssl.ossl_typ.ASN1_STRING* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM DISPLAYTEXT_it;
libressl_d.openssl.ossl_typ.ASN1_PRINTABLESTRING* ASN1_PRINTABLESTRING_new();
void ASN1_PRINTABLESTRING_free(libressl_d.openssl.ossl_typ.ASN1_PRINTABLESTRING* a);
libressl_d.openssl.ossl_typ.ASN1_PRINTABLESTRING* d2i_ASN1_PRINTABLESTRING(libressl_d.openssl.ossl_typ.ASN1_PRINTABLESTRING** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_PRINTABLESTRING(libressl_d.openssl.ossl_typ.ASN1_PRINTABLESTRING* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_PRINTABLESTRING_it;
libressl_d.openssl.ossl_typ.ASN1_T61STRING* ASN1_T61STRING_new();
void ASN1_T61STRING_free(libressl_d.openssl.ossl_typ.ASN1_T61STRING* a);
libressl_d.openssl.ossl_typ.ASN1_T61STRING* d2i_ASN1_T61STRING(libressl_d.openssl.ossl_typ.ASN1_T61STRING** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_T61STRING(libressl_d.openssl.ossl_typ.ASN1_T61STRING* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_T61STRING_it;
libressl_d.openssl.ossl_typ.ASN1_IA5STRING* ASN1_IA5STRING_new();
void ASN1_IA5STRING_free(libressl_d.openssl.ossl_typ.ASN1_IA5STRING* a);
libressl_d.openssl.ossl_typ.ASN1_IA5STRING* d2i_ASN1_IA5STRING(libressl_d.openssl.ossl_typ.ASN1_IA5STRING** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_IA5STRING(libressl_d.openssl.ossl_typ.ASN1_IA5STRING* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_IA5STRING_it;
libressl_d.openssl.ossl_typ.ASN1_GENERALSTRING* ASN1_GENERALSTRING_new();
void ASN1_GENERALSTRING_free(libressl_d.openssl.ossl_typ.ASN1_GENERALSTRING* a);
libressl_d.openssl.ossl_typ.ASN1_GENERALSTRING* d2i_ASN1_GENERALSTRING(libressl_d.openssl.ossl_typ.ASN1_GENERALSTRING** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_GENERALSTRING(libressl_d.openssl.ossl_typ.ASN1_GENERALSTRING* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_GENERALSTRING_it;
libressl_d.openssl.ossl_typ.ASN1_UTCTIME* ASN1_UTCTIME_new();
void ASN1_UTCTIME_free(libressl_d.openssl.ossl_typ.ASN1_UTCTIME* a);
libressl_d.openssl.ossl_typ.ASN1_UTCTIME* d2i_ASN1_UTCTIME(libressl_d.openssl.ossl_typ.ASN1_UTCTIME** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_UTCTIME(libressl_d.openssl.ossl_typ.ASN1_UTCTIME* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_UTCTIME_it;
libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME* ASN1_GENERALIZEDTIME_new();
void ASN1_GENERALIZEDTIME_free(libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME* a);
libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME* d2i_ASN1_GENERALIZEDTIME(libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_GENERALIZEDTIME(libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_GENERALIZEDTIME_it;
libressl_d.openssl.ossl_typ.ASN1_TIME* ASN1_TIME_new();
void ASN1_TIME_free(libressl_d.openssl.ossl_typ.ASN1_TIME* a);
libressl_d.openssl.ossl_typ.ASN1_TIME* d2i_ASN1_TIME(libressl_d.openssl.ossl_typ.ASN1_TIME** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ASN1_TIME(libressl_d.openssl.ossl_typ.ASN1_TIME* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_TIME_it;

extern const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_OCTET_STRING_NDEF_it;

libressl_d.openssl.ossl_typ.ASN1_TIME* ASN1_TIME_set(libressl_d.openssl.ossl_typ.ASN1_TIME* s, libressl_d.compat.time.time_t t);
libressl_d.openssl.ossl_typ.ASN1_TIME* ASN1_TIME_set_tm(libressl_d.openssl.ossl_typ.ASN1_TIME* s, libressl_d.compat.time.tm* tm);
libressl_d.openssl.ossl_typ.ASN1_TIME* ASN1_TIME_adj(libressl_d.openssl.ossl_typ.ASN1_TIME* s, libressl_d.compat.time.time_t t, int offset_day, core.stdc.config.c_long offset_sec);
int ASN1_TIME_check(const (libressl_d.openssl.ossl_typ.ASN1_TIME)* t);
libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME* ASN1_TIME_to_generalizedtime(const (libressl_d.openssl.ossl_typ.ASN1_TIME)* t, libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME** out_);
int ASN1_TIME_set_string(libressl_d.openssl.ossl_typ.ASN1_TIME* s, const (char)* str);

//#if !defined(OPENSSL_NO_BIO)
int i2a_ASN1_INTEGER(libressl_d.openssl.bio.BIO* bp, const (libressl_d.openssl.ossl_typ.ASN1_INTEGER)* a);
int a2i_ASN1_INTEGER(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.ASN1_INTEGER* bs, char* buf, int size);
int i2a_ASN1_ENUMERATED(libressl_d.openssl.bio.BIO* bp, const (libressl_d.openssl.ossl_typ.ASN1_ENUMERATED)* a);
int a2i_ASN1_ENUMERATED(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.ASN1_ENUMERATED* bs, char* buf, int size);
int i2a_ASN1_OBJECT(libressl_d.openssl.bio.BIO* bp, const (.ASN1_OBJECT)* a);
int a2i_ASN1_STRING(libressl_d.openssl.bio.BIO* bp, libressl_d.openssl.ossl_typ.ASN1_STRING* bs, char* buf, int size);
int i2a_ASN1_STRING(libressl_d.openssl.bio.BIO* bp, const (libressl_d.openssl.ossl_typ.ASN1_STRING)* a, int type);
//#endif

int i2t_ASN1_OBJECT(char* buf, int buf_len, const (.ASN1_OBJECT)* a);

int a2d_ASN1_OBJECT(ubyte* out_, int olen, const (char)* buf, int num);
.ASN1_OBJECT* ASN1_OBJECT_create(int nid, ubyte* data, int len, const (char)* sn, const (char)* ln);

int ASN1_INTEGER_set(libressl_d.openssl.ossl_typ.ASN1_INTEGER* a, core.stdc.config.c_long v);
core.stdc.config.c_long ASN1_INTEGER_get(const (libressl_d.openssl.ossl_typ.ASN1_INTEGER)* a);
libressl_d.openssl.ossl_typ.ASN1_INTEGER* BN_to_ASN1_INTEGER(const (libressl_d.openssl.ossl_typ.BIGNUM)* bn, libressl_d.openssl.ossl_typ.ASN1_INTEGER* ai);
libressl_d.openssl.ossl_typ.BIGNUM* ASN1_INTEGER_to_BN(const (libressl_d.openssl.ossl_typ.ASN1_INTEGER)* ai, libressl_d.openssl.ossl_typ.BIGNUM* bn);

int ASN1_ENUMERATED_set(libressl_d.openssl.ossl_typ.ASN1_ENUMERATED* a, core.stdc.config.c_long v);
core.stdc.config.c_long ASN1_ENUMERATED_get(const (libressl_d.openssl.ossl_typ.ASN1_ENUMERATED)* a);
libressl_d.openssl.ossl_typ.ASN1_ENUMERATED* BN_to_ASN1_ENUMERATED(const (libressl_d.openssl.ossl_typ.BIGNUM)* bn, libressl_d.openssl.ossl_typ.ASN1_ENUMERATED* ai);
libressl_d.openssl.ossl_typ.BIGNUM* ASN1_ENUMERATED_to_BN(const (libressl_d.openssl.ossl_typ.ASN1_ENUMERATED)* ai, libressl_d.openssl.ossl_typ.BIGNUM* bn);

/* General */
/**
 * given a string, return the correct type, max is the maximum length
 */
int ASN1_PRINTABLE_type(const (ubyte)* s, int max);

/* SPECIALS */
int ASN1_get_object(const (ubyte)** pp, core.stdc.config.c_long* plength, int* ptag, int* pclass, core.stdc.config.c_long omax);
int ASN1_check_infinite_end(ubyte** p, core.stdc.config.c_long len);
int ASN1_const_check_infinite_end(const (ubyte)** p, core.stdc.config.c_long len);
void ASN1_put_object(ubyte** pp, int constructed, int length_, int tag, int xclass);
int ASN1_put_eoc(ubyte** pp);
int ASN1_object_size(int constructed, int length_, int tag);

void* ASN1_item_dup(const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, void* x);

package alias d2i_of_void = void;
package alias i2d_of_void = void;

//#if !defined(LIBRESSL_INTERNAL)
void* ASN1_dup(i2d_of_void* i2d, d2i_of_void* d2i, void* x);
//#endif /* !LIBRESSL_INTERNAL */

void* ASN1_d2i_fp(void* function() xnew, d2i_of_void* d2i, libressl_d.compat.stdio.FILE* in_, void** x);

//#define ASN1_d2i_fp_of(type, xnew, d2i, in_, x) ((type*) .ASN1_d2i_fp(.CHECKED_NEW_OF(type, xnew), .CHECKED_D2I_OF(type, d2i), in_, .CHECKED_PPTR_OF(type, x)))

void* ASN1_item_d2i_fp(const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, libressl_d.compat.stdio.FILE* in_, void* x);
int ASN1_i2d_fp(i2d_of_void* i2d, libressl_d.compat.stdio.FILE* out_, void* x);

//#define ASN1_i2d_fp_of(type, i2d, out_, x) (.ASN1_i2d_fp(.CHECKED_I2D_OF(type, i2d), out_, .CHECKED_PTR_OF(type, x)))

//#define ASN1_i2d_fp_of_const(type, i2d, out_, x) (.ASN1_i2d_fp(.CHECKED_I2D_OF(const type, i2d), out_, .CHECKED_PTR_OF(const type, x)))

int ASN1_item_i2d_fp(const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, libressl_d.compat.stdio.FILE* out_, void* x);
int ASN1_STRING_print_ex_fp(libressl_d.compat.stdio.FILE* fp, const (libressl_d.openssl.ossl_typ.ASN1_STRING)* str, core.stdc.config.c_ulong flags);

int ASN1_STRING_to_UTF8(ubyte** out_, const (libressl_d.openssl.ossl_typ.ASN1_STRING)* in_);

//#if !defined(OPENSSL_NO_BIO)
void* ASN1_d2i_bio(void* function() xnew, d2i_of_void* d2i, libressl_d.openssl.bio.BIO* in_, void** x);

//#define ASN1_d2i_bio_of(type, xnew, d2i, in_, x) ((type*) .ASN1_d2i_bio(.CHECKED_NEW_OF(type, xnew), .CHECKED_D2I_OF(type, d2i), in_, .CHECKED_PPTR_OF(type, x)))

void* ASN1_item_d2i_bio(const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, libressl_d.openssl.bio.BIO* in_, void* x);
int ASN1_i2d_bio(i2d_of_void* i2d, libressl_d.openssl.bio.BIO* out_, ubyte* x);

//#define ASN1_i2d_bio_of(type, i2d, out_, x) (.ASN1_i2d_bio(.CHECKED_I2D_OF(type, i2d), out_, .CHECKED_PTR_OF(type, x)))

//#define ASN1_i2d_bio_of_const(type, i2d, out_, x) (.ASN1_i2d_bio(.CHECKED_I2D_OF(const type, i2d), out_, .CHECKED_PTR_OF(const type, x)))

int ASN1_item_i2d_bio(const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, libressl_d.openssl.bio.BIO* out_, void* x);
int ASN1_UTCTIME_print(libressl_d.openssl.bio.BIO* fp, const (libressl_d.openssl.ossl_typ.ASN1_UTCTIME)* a);
int ASN1_GENERALIZEDTIME_print(libressl_d.openssl.bio.BIO* fp, const (libressl_d.openssl.ossl_typ.ASN1_GENERALIZEDTIME)* a);
int ASN1_TIME_print(libressl_d.openssl.bio.BIO* fp, const (libressl_d.openssl.ossl_typ.ASN1_TIME)* a);
int ASN1_STRING_print(libressl_d.openssl.bio.BIO* bp, const (libressl_d.openssl.ossl_typ.ASN1_STRING)* v);
int ASN1_STRING_print_ex(libressl_d.openssl.bio.BIO* out_, const (libressl_d.openssl.ossl_typ.ASN1_STRING)* str, core.stdc.config.c_ulong flags);
int ASN1_bn_print(libressl_d.openssl.bio.BIO* bp, const (char)* number, const (libressl_d.openssl.ossl_typ.BIGNUM)* num, ubyte* buf, int off);
int ASN1_parse(libressl_d.openssl.bio.BIO* bp, const (ubyte)* pp, core.stdc.config.c_long len, int indent);
int ASN1_parse_dump(libressl_d.openssl.bio.BIO* bp, const (ubyte)* pp, core.stdc.config.c_long len, int indent, int dump);
//#endif

core.stdc.config.c_ulong ASN1_tag2bit(int tag);
const (char)* ASN1_tag2str(int tag);

/* Used to load and write netscape format cert */

.NETSCAPE_X509* NETSCAPE_X509_new();
void NETSCAPE_X509_free(.NETSCAPE_X509* a);
.NETSCAPE_X509* d2i_NETSCAPE_X509(.NETSCAPE_X509** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_NETSCAPE_X509(.NETSCAPE_X509* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM NETSCAPE_X509_it;

int ASN1_UNIVERSALSTRING_to_string(libressl_d.openssl.ossl_typ.ASN1_UNIVERSALSTRING* s);

int ASN1_TYPE_set_octetstring(.ASN1_TYPE* a, const (ubyte)* data, int len);
int ASN1_TYPE_get_octetstring(const (.ASN1_TYPE)* a, ubyte* data, int max_len);
int ASN1_TYPE_set_int_octetstring(.ASN1_TYPE* a, core.stdc.config.c_long num, const (ubyte)* data, int len);
int ASN1_TYPE_get_int_octetstring(const (.ASN1_TYPE)* a, core.stdc.config.c_long* num, ubyte* data, int max_len);

libressl_d.openssl.ossl_typ.ASN1_STRING* ASN1_item_pack(void* obj, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING** oct);
void* ASN1_item_unpack(const (libressl_d.openssl.ossl_typ.ASN1_STRING)* oct, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);

void ASN1_STRING_set_default_mask(core.stdc.config.c_ulong mask);
int ASN1_STRING_set_default_mask_asc(const (char)* p);
core.stdc.config.c_ulong ASN1_STRING_get_default_mask();
int ASN1_mbstring_copy(libressl_d.openssl.ossl_typ.ASN1_STRING** out_, const (ubyte)* in_, int len, int inform, core.stdc.config.c_ulong mask);
int ASN1_mbstring_ncopy(libressl_d.openssl.ossl_typ.ASN1_STRING** out_, const (ubyte)* in_, int len, int inform, core.stdc.config.c_ulong mask, core.stdc.config.c_long minsize, core.stdc.config.c_long maxsize);

libressl_d.openssl.ossl_typ.ASN1_STRING* ASN1_STRING_set_by_NID(libressl_d.openssl.ossl_typ.ASN1_STRING** out_, const (ubyte)* in_, int inlen, int inform, int nid);
.ASN1_STRING_TABLE* ASN1_STRING_TABLE_get(int nid);
int ASN1_STRING_TABLE_add(int, core.stdc.config.c_long, core.stdc.config.c_long, core.stdc.config.c_ulong, core.stdc.config.c_ulong);
void ASN1_STRING_TABLE_cleanup();

/* ASN1 template functions */

/* Old API compatible functions */
.ASN1_VALUE* ASN1_item_new(const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
void ASN1_item_free(.ASN1_VALUE* val, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
.ASN1_VALUE* ASN1_item_d2i(.ASN1_VALUE** val, const (ubyte)** in_, core.stdc.config.c_long len, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
int ASN1_item_i2d(.ASN1_VALUE* val, ubyte** out_, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
int ASN1_item_ndef_i2d(.ASN1_VALUE* val, ubyte** out_, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);

void ASN1_add_oid_module();

.ASN1_TYPE* ASN1_generate_nconf(const (char)* str, libressl_d.openssl.ossl_typ.CONF* nconf);
.ASN1_TYPE* ASN1_generate_v3(const (char)* str, libressl_d.openssl.ossl_typ.X509V3_CTX* cnf);

/* ASN1 Print flags */

/**
 * Indicate missing OPTIONAL fields
 */
enum ASN1_PCTX_FLAGS_SHOW_ABSENT = 0x0001;

/**
 * Mark start and end of SEQUENCE
 */
enum ASN1_PCTX_FLAGS_SHOW_SEQUENCE = 0x0002;

/**
 * Mark start and end of SEQUENCE/SET OF
 */
enum ASN1_PCTX_FLAGS_SHOW_SSOF = 0x0004;

/**
 * Show the ASN1 type of primitives
 */
enum ASN1_PCTX_FLAGS_SHOW_TYPE = 0x0008;

/**
 * Don't show ASN1 type of ANY
 */
enum ASN1_PCTX_FLAGS_NO_ANY_TYPE = 0x0010;

/**
 * Don't show ASN1 type of MSTRINGs
 */
enum ASN1_PCTX_FLAGS_NO_MSTRING_TYPE = 0x0020;

/**
 * Don't show field names in SEQUENCE
 */
enum ASN1_PCTX_FLAGS_NO_FIELD_NAME = 0x0040;

/**
 * Show structure names of each SEQUENCE field
 */
enum ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME = 0x0080;

/**
 * Don't show structure name even at top level
 */
enum ASN1_PCTX_FLAGS_NO_STRUCT_NAME = 0x0100;

int ASN1_item_print(libressl_d.openssl.bio.BIO* out_, .ASN1_VALUE* ifld, int indent, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, const (libressl_d.openssl.ossl_typ.ASN1_PCTX)* pctx);
libressl_d.openssl.ossl_typ.ASN1_PCTX* ASN1_PCTX_new();
void ASN1_PCTX_free(libressl_d.openssl.ossl_typ.ASN1_PCTX* p);
core.stdc.config.c_ulong ASN1_PCTX_get_flags(const (libressl_d.openssl.ossl_typ.ASN1_PCTX)* p);
void ASN1_PCTX_set_flags(libressl_d.openssl.ossl_typ.ASN1_PCTX* p, core.stdc.config.c_ulong flags);
core.stdc.config.c_ulong ASN1_PCTX_get_nm_flags(const (libressl_d.openssl.ossl_typ.ASN1_PCTX)* p);
void ASN1_PCTX_set_nm_flags(libressl_d.openssl.ossl_typ.ASN1_PCTX* p, core.stdc.config.c_ulong flags);
core.stdc.config.c_ulong ASN1_PCTX_get_cert_flags(const (libressl_d.openssl.ossl_typ.ASN1_PCTX)* p);
void ASN1_PCTX_set_cert_flags(libressl_d.openssl.ossl_typ.ASN1_PCTX* p, core.stdc.config.c_ulong flags);
core.stdc.config.c_ulong ASN1_PCTX_get_oid_flags(const (libressl_d.openssl.ossl_typ.ASN1_PCTX)* p);
void ASN1_PCTX_set_oid_flags(libressl_d.openssl.ossl_typ.ASN1_PCTX* p, core.stdc.config.c_ulong flags);
core.stdc.config.c_ulong ASN1_PCTX_get_str_flags(const (libressl_d.openssl.ossl_typ.ASN1_PCTX)* p);
void ASN1_PCTX_set_str_flags(libressl_d.openssl.ossl_typ.ASN1_PCTX* p, core.stdc.config.c_ulong flags);

const (libressl_d.openssl.bio.BIO_METHOD)* BIO_f_asn1();

libressl_d.openssl.bio.BIO* BIO_new_NDEF(libressl_d.openssl.bio.BIO* out_, .ASN1_VALUE* val, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);

int i2d_ASN1_bio_stream(libressl_d.openssl.bio.BIO* out_, .ASN1_VALUE* val, libressl_d.openssl.bio.BIO* in_, int flags, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
int PEM_write_bio_ASN1_stream(libressl_d.openssl.bio.BIO* out_, .ASN1_VALUE* val, libressl_d.openssl.bio.BIO* in_, int flags, const (char)* hdr, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
int SMIME_write_ASN1(libressl_d.openssl.bio.BIO* bio, .ASN1_VALUE* val, libressl_d.openssl.bio.BIO* data, int flags, int ctype_nid, int econt_nid, .stack_st_X509_ALGOR * mdalgs, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
.ASN1_VALUE* SMIME_read_ASN1(libressl_d.openssl.bio.BIO* bio, libressl_d.openssl.bio.BIO** bcont, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
int SMIME_crlf_copy(libressl_d.openssl.bio.BIO* in_, libressl_d.openssl.bio.BIO* out_, int flags);
int SMIME_text(libressl_d.openssl.bio.BIO* in_, libressl_d.openssl.bio.BIO* out_);

/* BEGIN ERROR CODES */
/**
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_ASN1_strings();

/* Error codes for the ASN1 functions. */

/* Function codes. */
enum ASN1_F_A2D_ASN1_OBJECT = 100;
enum ASN1_F_A2I_ASN1_ENUMERATED = 101;
enum ASN1_F_A2I_ASN1_INTEGER = 102;
enum ASN1_F_A2I_ASN1_STRING = 103;
enum ASN1_F_APPEND_EXP = 176;
enum ASN1_F_ASN1_BIT_STRING_SET_BIT = 183;
enum ASN1_F_ASN1_CB = 177;
enum ASN1_F_ASN1_CHECK_TLEN = 104;
enum ASN1_F_ASN1_COLLATE_PRIMITIVE = 105;
enum ASN1_F_ASN1_COLLECT = 106;
enum ASN1_F_ASN1_D2I_EX_PRIMITIVE = 108;
enum ASN1_F_ASN1_D2I_FP = 109;
enum ASN1_F_ASN1_D2I_READ_BIO = 107;
enum ASN1_F_ASN1_DIGEST = 184;
enum ASN1_F_ASN1_DO_ADB = 110;
enum ASN1_F_ASN1_DUP = 111;
enum ASN1_F_ASN1_ENUMERATED_SET = 112;
enum ASN1_F_ASN1_ENUMERATED_TO_BN = 113;
enum ASN1_F_ASN1_EX_C2I = 204;
enum ASN1_F_ASN1_FIND_END = 190;
enum ASN1_F_ASN1_GENERALIZEDTIME_ADJ = 216;
enum ASN1_F_ASN1_GENERALIZEDTIME_SET = 185;
enum ASN1_F_ASN1_GENERATE_V3 = 178;
enum ASN1_F_ASN1_GET_OBJECT = 114;
enum ASN1_F_ASN1_HEADER_NEW = 115;
enum ASN1_F_ASN1_I2D_BIO = 116;
enum ASN1_F_ASN1_I2D_FP = 117;
enum ASN1_F_ASN1_INTEGER_SET = 118;
enum ASN1_F_ASN1_INTEGER_TO_BN = 119;
enum ASN1_F_ASN1_ITEM_D2I_FP = 206;
enum ASN1_F_ASN1_ITEM_DUP = 191;
enum ASN1_F_ASN1_ITEM_EX_COMBINE_NEW = 121;
enum ASN1_F_ASN1_ITEM_EX_D2I = 120;
enum ASN1_F_ASN1_ITEM_I2D_BIO = 192;
enum ASN1_F_ASN1_ITEM_I2D_FP = 193;
enum ASN1_F_ASN1_ITEM_PACK = 198;
enum ASN1_F_ASN1_ITEM_SIGN = 195;
enum ASN1_F_ASN1_ITEM_SIGN_CTX = 220;
enum ASN1_F_ASN1_ITEM_UNPACK = 199;
enum ASN1_F_ASN1_ITEM_VERIFY = 197;
enum ASN1_F_ASN1_MBSTRING_NCOPY = 122;
enum ASN1_F_ASN1_OBJECT_NEW = 123;
enum ASN1_F_ASN1_OUTPUT_DATA = 214;
enum ASN1_F_ASN1_PACK_STRING = 124;
enum ASN1_F_ASN1_PCTX_NEW = 205;
enum ASN1_F_ASN1_PKCS5_PBE_SET = 125;
enum ASN1_F_ASN1_SEQ_PACK = 126;
enum ASN1_F_ASN1_SEQ_UNPACK = 127;
enum ASN1_F_ASN1_SIGN = 128;
enum ASN1_F_ASN1_STR2TYPE = 179;
enum ASN1_F_ASN1_STRING_SET = 186;
enum ASN1_F_ASN1_STRING_TABLE_ADD = 129;
enum ASN1_F_ASN1_STRING_TYPE_NEW = 130;
enum ASN1_F_ASN1_TEMPLATE_EX_D2I = 132;
enum ASN1_F_ASN1_TEMPLATE_NEW = 133;
enum ASN1_F_ASN1_TEMPLATE_NOEXP_D2I = 131;
enum ASN1_F_ASN1_TIME_ADJ = 217;
enum ASN1_F_ASN1_TIME_SET = 175;
enum ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING = 134;
enum ASN1_F_ASN1_TYPE_GET_OCTETSTRING = 135;
enum ASN1_F_ASN1_UNPACK_STRING = 136;
enum ASN1_F_ASN1_UTCTIME_ADJ = 218;
enum ASN1_F_ASN1_UTCTIME_SET = 187;
enum ASN1_F_ASN1_VERIFY = 137;
enum ASN1_F_B64_READ_ASN1 = 209;
enum ASN1_F_B64_WRITE_ASN1 = 210;
enum ASN1_F_BIO_NEW_NDEF = 208;
enum ASN1_F_BITSTR_CB = 180;
enum ASN1_F_BN_TO_ASN1_ENUMERATED = 138;
enum ASN1_F_BN_TO_ASN1_INTEGER = 139;
enum ASN1_F_C2I_ASN1_BIT_STRING = 189;
enum ASN1_F_C2I_ASN1_INTEGER = 194;
enum ASN1_F_C2I_ASN1_OBJECT = 196;
enum ASN1_F_COLLECT_DATA = 140;
enum ASN1_F_D2I_ASN1_BIT_STRING = 141;
enum ASN1_F_D2I_ASN1_BOOLEAN = 142;
enum ASN1_F_D2I_ASN1_BYTES = 143;
enum ASN1_F_D2I_ASN1_GENERALIZEDTIME = 144;
enum ASN1_F_D2I_ASN1_HEADER = 145;
enum ASN1_F_D2I_ASN1_INTEGER = 146;
enum ASN1_F_D2I_ASN1_OBJECT = 147;
enum ASN1_F_D2I_ASN1_SET = 148;
enum ASN1_F_D2I_ASN1_TYPE_BYTES = 149;
enum ASN1_F_D2I_ASN1_UINTEGER = 150;
enum ASN1_F_D2I_ASN1_UTCTIME = 151;
enum ASN1_F_D2I_AUTOPRIVATEKEY = 207;
enum ASN1_F_D2I_NETSCAPE_RSA = 152;
enum ASN1_F_D2I_NETSCAPE_RSA_2 = 153;
enum ASN1_F_D2I_PRIVATEKEY = 154;
enum ASN1_F_D2I_PUBLICKEY = 155;
enum ASN1_F_D2I_RSA_NET = 200;
enum ASN1_F_D2I_RSA_NET_2 = 201;
enum ASN1_F_D2I_X509 = 156;
enum ASN1_F_D2I_X509_CINF = 157;
enum ASN1_F_D2I_X509_PKEY = 159;
enum ASN1_F_I2D_ASN1_BIO_STREAM = 211;
enum ASN1_F_I2D_ASN1_SET = 188;
enum ASN1_F_I2D_ASN1_TIME = 160;
enum ASN1_F_I2D_DSA_PUBKEY = 161;
enum ASN1_F_I2D_EC_PUBKEY = 181;
enum ASN1_F_I2D_PRIVATEKEY = 163;
enum ASN1_F_I2D_PUBLICKEY = 164;
enum ASN1_F_I2D_RSA_NET = 162;
enum ASN1_F_I2D_RSA_PUBKEY = 165;
enum ASN1_F_LONG_C2I = 166;
enum ASN1_F_OID_MODULE_INIT = 174;
enum ASN1_F_PARSE_TAGGING = 182;
enum ASN1_F_PKCS5_PBE2_SET_IV = 167;
enum ASN1_F_PKCS5_PBE_SET = 202;
enum ASN1_F_PKCS5_PBE_SET0_ALGOR = 215;
enum ASN1_F_PKCS5_PBKDF2_SET = 219;
enum ASN1_F_SMIME_READ_ASN1 = 212;
enum ASN1_F_SMIME_TEXT = 213;
enum ASN1_F_X509_CINF_NEW = 168;
enum ASN1_F_X509_CRL_ADD0_REVOKED = 169;
enum ASN1_F_X509_INFO_NEW = 170;
enum ASN1_F_X509_NAME_ENCODE = 203;
enum ASN1_F_X509_NAME_EX_D2I = 158;
enum ASN1_F_X509_NAME_EX_NEW = 171;
enum ASN1_F_X509_NEW = 172;
enum ASN1_F_X509_PKEY_NEW = 173;

/* Reason codes. */
enum ASN1_R_ADDING_OBJECT = 171;
enum ASN1_R_ASN1_PARSE_ERROR = 203;
enum ASN1_R_ASN1_SIG_PARSE_ERROR = 204;
enum ASN1_R_AUX_ERROR = 100;
enum ASN1_R_BAD_CLASS = 101;
enum ASN1_R_BAD_OBJECT_HEADER = 102;
enum ASN1_R_BAD_PASSWORD_READ = 103;
enum ASN1_R_BAD_TAG = 104;
enum ASN1_R_BAD_TEMPLATE = 230;
enum ASN1_R_BMPSTRING_IS_WRONG_LENGTH = 214;
enum ASN1_R_BN_LIB = 105;
enum ASN1_R_BOOLEAN_IS_WRONG_LENGTH = 106;
enum ASN1_R_BUFFER_TOO_SMALL = 107;
enum ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER = 108;
enum ASN1_R_CONTEXT_NOT_INITIALISED = 217;
enum ASN1_R_DATA_IS_WRONG = 109;
enum ASN1_R_DECODE_ERROR = 110;
enum ASN1_R_DECODING_ERROR = 111;
enum ASN1_R_DEPTH_EXCEEDED = 174;
enum ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED = 198;
enum ASN1_R_ENCODE_ERROR = 112;
enum ASN1_R_ERROR_GETTING_TIME = 173;
enum ASN1_R_ERROR_LOADING_SECTION = 172;
enum ASN1_R_ERROR_PARSING_SET_ELEMENT = 113;
enum ASN1_R_ERROR_SETTING_CIPHER_PARAMS = 114;
enum ASN1_R_EXPECTING_AN_INTEGER = 115;
enum ASN1_R_EXPECTING_AN_OBJECT = 116;
enum ASN1_R_EXPECTING_A_BOOLEAN = 117;
enum ASN1_R_EXPECTING_A_TIME = 118;
enum ASN1_R_EXPLICIT_LENGTH_MISMATCH = 119;
enum ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED = 120;
enum ASN1_R_FIELD_MISSING = 121;
enum ASN1_R_FIRST_NUM_TOO_LARGE = 122;
enum ASN1_R_HEADER_TOO_LONG = 123;
enum ASN1_R_ILLEGAL_BITSTRING_FORMAT = 175;
enum ASN1_R_ILLEGAL_BOOLEAN = 176;
enum ASN1_R_ILLEGAL_CHARACTERS = 124;
enum ASN1_R_ILLEGAL_FORMAT = 177;
enum ASN1_R_ILLEGAL_HEX = 178;
enum ASN1_R_ILLEGAL_IMPLICIT_TAG = 179;
enum ASN1_R_ILLEGAL_INTEGER = 180;
enum ASN1_R_ILLEGAL_NESTED_TAGGING = 181;
enum ASN1_R_ILLEGAL_NULL = 125;
enum ASN1_R_ILLEGAL_NULL_VALUE = 182;
enum ASN1_R_ILLEGAL_OBJECT = 183;
enum ASN1_R_ILLEGAL_OPTIONAL_ANY = 126;
enum ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE = 170;
enum ASN1_R_ILLEGAL_TAGGED_ANY = 127;
enum ASN1_R_ILLEGAL_TIME_VALUE = 184;
enum ASN1_R_INTEGER_NOT_ASCII_FORMAT = 185;
enum ASN1_R_INTEGER_TOO_LARGE_FOR_LONG = 128;
enum ASN1_R_INVALID_BIT_STRING_BITS_LEFT = 220;
enum ASN1_R_INVALID_BMPSTRING_LENGTH = 129;
enum ASN1_R_INVALID_DIGIT = 130;
enum ASN1_R_INVALID_MIME_TYPE = 205;
enum ASN1_R_INVALID_MODIFIER = 186;
enum ASN1_R_INVALID_NUMBER = 187;
enum ASN1_R_INVALID_OBJECT_ENCODING = 216;
enum ASN1_R_INVALID_SEPARATOR = 131;
enum ASN1_R_INVALID_TIME_FORMAT = 132;
enum ASN1_R_INVALID_UNIVERSALSTRING_LENGTH = 133;
enum ASN1_R_INVALID_UTF8STRING = 134;
enum ASN1_R_IV_TOO_LARGE = 135;
enum ASN1_R_LENGTH_ERROR = 136;
enum ASN1_R_LIST_ERROR = 188;
enum ASN1_R_MIME_NO_CONTENT_TYPE = 206;
enum ASN1_R_MIME_PARSE_ERROR = 207;
enum ASN1_R_MIME_SIG_PARSE_ERROR = 208;
enum ASN1_R_MISSING_EOC = 137;
enum ASN1_R_MISSING_SECOND_NUMBER = 138;
enum ASN1_R_MISSING_VALUE = 189;
enum ASN1_R_MSTRING_NOT_UNIVERSAL = 139;
enum ASN1_R_MSTRING_WRONG_TAG = 140;
enum ASN1_R_NESTED_ASN1_STRING = 197;
enum ASN1_R_NESTED_TOO_DEEP = 219;
enum ASN1_R_NON_HEX_CHARACTERS = 141;
enum ASN1_R_NOT_ASCII_FORMAT = 190;
enum ASN1_R_NOT_ENOUGH_DATA = 142;
enum ASN1_R_NO_CONTENT_TYPE = 209;
enum ASN1_R_NO_DEFAULT_DIGEST = 201;
enum ASN1_R_NO_MATCHING_CHOICE_TYPE = 143;
enum ASN1_R_NO_MULTIPART_BODY_FAILURE = 210;
enum ASN1_R_NO_MULTIPART_BOUNDARY = 211;
enum ASN1_R_NO_SIG_CONTENT_TYPE = 212;
enum ASN1_R_NULL_IS_WRONG_LENGTH = 144;
enum ASN1_R_OBJECT_NOT_ASCII_FORMAT = 191;
enum ASN1_R_ODD_NUMBER_OF_CHARS = 145;
enum ASN1_R_PRIVATE_KEY_HEADER_MISSING = 146;
enum ASN1_R_SECOND_NUMBER_TOO_LARGE = 147;
enum ASN1_R_SEQUENCE_LENGTH_MISMATCH = 148;
enum ASN1_R_SEQUENCE_NOT_CONSTRUCTED = 149;
enum ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG = 192;
enum ASN1_R_SHORT_LINE = 150;
enum ASN1_R_SIG_INVALID_MIME_TYPE = 213;
enum ASN1_R_STREAMING_NOT_SUPPORTED = 202;
enum ASN1_R_STRING_TOO_LONG = 151;
enum ASN1_R_STRING_TOO_SHORT = 152;
enum ASN1_R_TAG_VALUE_TOO_HIGH = 153;
enum ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 154;
enum ASN1_R_TIME_NOT_ASCII_FORMAT = 193;
enum ASN1_R_TOO_LONG = 155;
enum ASN1_R_TYPE_NOT_CONSTRUCTED = 156;
enum ASN1_R_UNABLE_TO_DECODE_RSA_KEY = 157;
enum ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY = 158;
enum ASN1_R_UNEXPECTED_EOC = 159;
enum ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH = 215;
enum ASN1_R_UNKNOWN_FORMAT = 160;
enum ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM = 161;
enum ASN1_R_UNKNOWN_OBJECT_TYPE = 162;
enum ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE = 163;
enum ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM = 199;
enum ASN1_R_UNKNOWN_TAG = 194;
enum ASN1_R_UNKOWN_FORMAT = 195;
enum ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE = 164;
enum ASN1_R_UNSUPPORTED_CIPHER = 165;
enum ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM = 166;
enum ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE = 167;
enum ASN1_R_UNSUPPORTED_TYPE = 196;
enum ASN1_R_WRONG_PUBLIC_KEY_TYPE = 200;
enum ASN1_R_WRONG_TAG = 168;
enum ASN1_R_WRONG_TYPE = 169;

int ASN1_time_parse(const (char)* _bytes, size_t _len, libressl_d.compat.time.tm* _tm, int _mode);
int ASN1_time_tm_cmp(libressl_d.compat.time.tm* _tm1, libressl_d.compat.time.tm* _tm2);
