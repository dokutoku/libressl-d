/* $OpenBSD: asn1t.h,v 1.15 2019/08/20 13:10:09 inoguchi Exp $ */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000-2005 The OpenSSL Project.  All rights reserved.
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
module libressl_d.openssl.asn1t;


private static import core.stdc.config;
private static import libressl_d.openssl.stack;
private static import libressl_d.openssl.ossl_typ;
private static import libressl_d.openssl.bio;
public import libressl_d.openssl.opensslconf;
public import libressl_d.openssl.asn1;
public import core.stdc.stddef;

/* ASN1 template defines, structures and functions */

extern (C):
nothrow @nogc:

version (LIBRESSL_INTERNAL) {
} else {
	/*
	 * Macro to obtain ASN1_ADB pointer from a type (only used internally)
	 */
	//#define ASN1_ADB_ptr(iptr) ((const (.ASN1_ADB)*) (iptr))

	/* Macros for start and end of ASN1_ITEM definition */

	//#define ASN1_ITEM_start(itname) const libressl_d.openssl.ossl_typ.ASN1_ITEM itname##_it = {
	//#define static_ASN1_ITEM_start(itname) static const libressl_d.openssl.ossl_typ.ASN1_ITEM itname##_it = {
	//#define ASN1_ITEM_end(itname) } ;

	/* Macros to aid ASN1 template writing */

	//#define ASN1_ITEM_TEMPLATE(tname) static const libressl_d.openssl.asn1.ASN1_TEMPLATE tname##_item_tt

	//#define ASN1_ITEM_TEMPLATE_END(tname) ; .ASN1_ITEM_start(tname) .ASN1_ITYPE_PRIMITIVE, -1, &tname##_item_tt, 0, null, 0, #tname .ASN1_ITEM_end(tname)

	//#define static_ASN1_ITEM_TEMPLATE_END(tname) ; .static_ASN1_ITEM_start(tname) .ASN1_ITYPE_PRIMITIVE, -1, &tname##_item_tt, 0, null, 0, #tname .ASN1_ITEM_end(tname)

	/* This is a ASN1 type which just embeds a template */

	/*
	 * This pair helps declare a SEQUENCE. We can do:
	 *
	 *     ASN1_SEQUENCE(stname) = {
	 *         ... SEQUENCE components ...
	 *     } ASN1_SEQUENCE_END(stname)
	 *
	 *     This will produce an ASN1_ITEM called stname_it
	 *     for a structure called stname.
	 *
	 *     If you want the same structure but a different
	 *     name then use:
	 *
	 *     ASN1_SEQUENCE(itname) = {
	 *         ... SEQUENCE components ...
	 *     } ASN1_SEQUENCE_END_name(stname, itname)
	 *
	 *     This will create an item called itname_it using
	 *     a structure called stname.
	 */

	//#define ASN1_SEQUENCE(tname) static const libressl_d.openssl.asn1.ASN1_TEMPLATE tname##_seq_tt[]

	//#define ASN1_SEQUENCE_END(stname) .ASN1_SEQUENCE_END_name(stname, stname)

	//#define static_ASN1_SEQUENCE_END(stname) .static_ASN1_SEQUENCE_END_name(stname, stname)

	//#define ASN1_SEQUENCE_END_name(stname, tname) ; .ASN1_ITEM_start(tname) .ASN1_ITYPE_SEQUENCE, libressl_d.openssl.asn1.V_ASN1_SEQUENCE, tname##_seq_tt, (tname##_seq_tt).sizeof / libressl_d.openssl.asn1.ASN1_TEMPLATE.sizeof, null, stname.sizeof, #stname .ASN1_ITEM_end(tname)

	//#define static_ASN1_SEQUENCE_END_name(stname, tname) ; .static_ASN1_ITEM_start(tname) .ASN1_ITYPE_SEQUENCE, libressl_d.openssl.asn1.V_ASN1_SEQUENCE, tname##_seq_tt, (tname##_seq_tt).sizeof / libressl_d.openssl.asn1.ASN1_TEMPLATE.sizeof, null, stname.sizeof, #stname .ASN1_ITEM_end(tname)

	//#define ASN1_NDEF_SEQUENCE(tname) .ASN1_SEQUENCE(tname)

	//#define ASN1_NDEF_SEQUENCE_cb(tname, cb) .ASN1_SEQUENCE_cb(tname, cb)

	//#define ASN1_SEQUENCE_cb(tname, cb) static const .ASN1_AUX tname##_aux = {null, 0, 0, 0, cb, 0}; .ASN1_SEQUENCE(tname)

	//#define ASN1_BROKEN_SEQUENCE(tname) static const .ASN1_AUX tname##_aux = {null, .ASN1_AFLG_BROKEN, 0, 0, 0, 0}; .ASN1_SEQUENCE(tname)

	//#define ASN1_SEQUENCE_ref(tname, cb, lck) static const .ASN1_AUX tname##_aux = {null, .ASN1_AFLG_REFCOUNT, offsetof(tname, references), lck, cb, 0}; .ASN1_SEQUENCE(tname)

	//#define ASN1_SEQUENCE_enc(tname, enc, cb) static const .ASN1_AUX tname##_aux = {null, .ASN1_AFLG_ENCODING, 0, 0, cb, offsetof(tname, enc)}; .ASN1_SEQUENCE(tname)

	//#define ASN1_NDEF_SEQUENCE_END(tname) ; .ASN1_ITEM_start(tname) .ASN1_ITYPE_NDEF_SEQUENCE, libressl_d.openssl.asn1.V_ASN1_SEQUENCE, tname##_seq_tt, (tname##_seq_tt).sizeof / libressl_d.openssl.asn1.ASN1_TEMPLATE.sizeof, null, tname.sizeof, #tname .ASN1_ITEM_end(tname)

	//#define static_ASN1_NDEF_SEQUENCE_END(tname) ; .static_ASN1_ITEM_start(tname) .ASN1_ITYPE_NDEF_SEQUENCE, libressl_d.openssl.asn1.V_ASN1_SEQUENCE, tname##_seq_tt, (tname##_seq_tt).sizeof / libressl_d.openssl.asn1.ASN1_TEMPLATE.sizeof, null, tname.sizeof, #tname .ASN1_ITEM_end(tname)

	//#define ASN1_BROKEN_SEQUENCE_END(stname) .ASN1_SEQUENCE_END_ref(stname, stname)

	//#define ASN1_SEQUENCE_END_enc(stname, tname) .ASN1_SEQUENCE_END_ref(stname, tname)

	//#define ASN1_SEQUENCE_END_cb(stname, tname) .ASN1_SEQUENCE_END_ref(stname, tname)

	//#define static_ASN1_SEQUENCE_END_cb(stname, tname) .static_ASN1_SEQUENCE_END_ref(stname, tname)

	//#define ASN1_SEQUENCE_END_ref(stname, tname) ; .ASN1_ITEM_start(tname) .ASN1_ITYPE_SEQUENCE, libressl_d.openssl.asn1.V_ASN1_SEQUENCE, tname##_seq_tt, (tname##_seq_tt).sizeof / libressl_d.openssl.asn1.ASN1_TEMPLATE.sizeof, &tname##_aux, stname.sizeof, #stname .ASN1_ITEM_end(tname)

	//#define static_ASN1_SEQUENCE_END_ref(stname, tname) ; .static_ASN1_ITEM_start(tname) .ASN1_ITYPE_SEQUENCE, libressl_d.openssl.asn1.V_ASN1_SEQUENCE, tname##_seq_tt, (tname##_seq_tt).sizeof / libressl_d.openssl.asn1.ASN1_TEMPLATE.sizeof, &tname##_aux, stname.sizeof, #stname .ASN1_ITEM_end(tname)

	//#define ASN1_NDEF_SEQUENCE_END_cb(stname, tname) ; .ASN1_ITEM_start(tname) .ASN1_ITYPE_NDEF_SEQUENCE, libressl_d.openssl.asn1.V_ASN1_SEQUENCE, tname##_seq_tt, (tname##_seq_tt).sizeof / libressl_d.openssl.asn1.ASN1_TEMPLATE.sizeof, &tname##_aux, stname.sizeof, #stname .ASN1_ITEM_end(tname)

	/*
	 * This pair helps declare a CHOICE type. We can do:
	 *
	 *     ASN1_CHOICE(chname) = {
	 *         ... CHOICE options ...
	 *     ASN1_CHOICE_END(chname)
	 *
	 *     This will produce an ASN1_ITEM called chname_it
	 *     for a structure called chname. The structure
	 *     definition must look like this:
	 *     typedef struct {
	 *         int type;
	 *
	 *         union value
	 *         {
	 *             ASN1_SOMETHING* pt1;
	 *             ASN1_SOMEOTHER* pt2;
	 *         }
	 *     } chname;
	 *
	 *     the name of the selector must be 'type'.
	 *     to use an alternative selector name use the
	 *      ASN1_CHOICE_END_selector() version.
	 */

	//#define ASN1_CHOICE(tname) static const libressl_d.openssl.asn1.ASN1_TEMPLATE tname##_ch_tt[]

	//#define ASN1_CHOICE_cb(tname, cb) static const .ASN1_AUX tname##_aux = {null, 0, 0, 0, cb, 0}; .ASN1_CHOICE(tname)

	//#define ASN1_CHOICE_END(stname) .ASN1_CHOICE_END_name(stname, stname)

	//#define static_ASN1_CHOICE_END(stname) .static_ASN1_CHOICE_END_name(stname, stname)

	//#define ASN1_CHOICE_END_name(stname, tname) .ASN1_CHOICE_END_selector(stname, tname, type)

	//#define static_ASN1_CHOICE_END_name(stname, tname) .static_ASN1_CHOICE_END_selector(stname, tname, type)

	//#define ASN1_CHOICE_END_selector(stname, tname, selname) ; .ASN1_ITEM_start(tname) .ASN1_ITYPE_CHOICE, offsetof(stname, selname), tname##_ch_tt, (tname##_ch_tt).sizeof / libressl_d.openssl.asn1.ASN1_TEMPLATE.sizeof, null, stname.sizeof, #stname .ASN1_ITEM_end(tname)

	//#define static_ASN1_CHOICE_END_selector(stname, tname, selname) ; .static_ASN1_ITEM_start(tname) .ASN1_ITYPE_CHOICE, offsetof(stname, selname), tname##_ch_tt, (tname##_ch_tt).sizeof / libressl_d.openssl.asn1.ASN1_TEMPLATE.sizeof, null, stname.sizeof, #stname .ASN1_ITEM_end(tname)

	//#define ASN1_CHOICE_END_cb(stname, tname, selname) ; .ASN1_ITEM_start(tname) .ASN1_ITYPE_CHOICE, offsetof(stname, selname), tname##_ch_tt, (tname##_ch_tt).sizeof / libressl_d.openssl.asn1.ASN1_TEMPLATE.sizeof, &tname##_aux, stname.sizeof, #stname .ASN1_ITEM_end(tname)

	/* This helps with the template wrapper form of ASN1_ITEM */

	//#define ASN1_EX_TEMPLATE_TYPE(flags, tag, name, type) { (flags), (tag), 0, #name, libressl_d.openssl.asn1.ASN1_ITEM_ref(type) }

	/* These help with SEQUENCE or CHOICE components */

	/* used to declare other types */

	//#define ASN1_EX_TYPE(flags, tag, stname, field, type) { (flags), (tag), offsetof(stname, field), #field, libressl_d.openssl.asn1.ASN1_ITEM_ref(type) }

	/* used when the structure is combined with the parent */

	//#define ASN1_EX_COMBINE(flags, tag, type) { (flags) | .ASN1_TFLG_COMBINE, (tag), 0, null, libressl_d.openssl.asn1.ASN1_ITEM_ref(type) }

	/* implicit and explicit helper macros */

	//#define ASN1_IMP_EX(stname, field, type, tag, ex) .ASN1_EX_TYPE(.ASN1_TFLG_IMPLICIT | ex, tag, stname, field, type)

	//#define ASN1_EXP_EX(stname, field, type, tag, ex) .ASN1_EX_TYPE(.ASN1_TFLG_EXPLICIT | ex, tag, stname, field, type)

	/* Any defined by macros: the field used is in the table itself */

	//#define ASN1_ADB_OBJECT(tblname) { .ASN1_TFLG_ADB_OID, -1, 0, #tblname, (const (libressl_d.openssl.ossl_typ.ASN1_ITEM)*) &(tblname##_adb) }
	//#define ASN1_ADB_INTEGER(tblname) { .ASN1_TFLG_ADB_INT, -1, 0, #tblname, (const (libressl_d.openssl.ossl_typ.ASN1_ITEM)*) &(tblname##_adb) }
	/* Plain simple type */
	//#define ASN1_SIMPLE(stname, field, type) .ASN1_EX_TYPE(0, 0, stname, field, type)

	/* OPTIONAL simple type */
	//#define ASN1_OPT(stname, field, type) .ASN1_EX_TYPE(.ASN1_TFLG_OPTIONAL, 0, stname, field, type)

	/* IMPLICIT tagged simple type */
	//#define ASN1_IMP(stname, field, type, tag) .ASN1_IMP_EX(stname, field, type, tag, 0)

	/* IMPLICIT tagged OPTIONAL simple type */
	//#define ASN1_IMP_OPT(stname, field, type, tag) .ASN1_IMP_EX(stname, field, type, tag, .ASN1_TFLG_OPTIONAL)

	/* Same as above but EXPLICIT */

	//#define ASN1_EXP(stname, field, type, tag) .ASN1_EXP_EX(stname, field, type, tag, 0)
	//#define ASN1_EXP_OPT(stname, field, type, tag) .ASN1_EXP_EX(stname, field, type, tag, .ASN1_TFLG_OPTIONAL)

	/* SEQUENCE OF type */
	//#define ASN1_SEQUENCE_OF(stname, field, type) .ASN1_EX_TYPE(.ASN1_TFLG_SEQUENCE_OF, 0, stname, field, type)

	/* OPTIONAL SEQUENCE OF */
	//#define ASN1_SEQUENCE_OF_OPT(stname, field, type) .ASN1_EX_TYPE(.ASN1_TFLG_SEQUENCE_OF | .ASN1_TFLG_OPTIONAL, 0, stname, field, type)

	/* Same as above but for SET OF */

	//#define ASN1_SET_OF(stname, field, type) .ASN1_EX_TYPE(.ASN1_TFLG_SET_OF, 0, stname, field, type)

	//#define ASN1_SET_OF_OPT(stname, field, type) .ASN1_EX_TYPE(.ASN1_TFLG_SET_OF | .ASN1_TFLG_OPTIONAL, 0, stname, field, type)

	/* Finally compound types of SEQUENCE, SET, IMPLICIT, EXPLICIT and OPTIONAL */

	//#define ASN1_IMP_SET_OF(stname, field, type, tag) .ASN1_IMP_EX(stname, field, type, tag, .ASN1_TFLG_SET_OF)

	//#define ASN1_EXP_SET_OF(stname, field, type, tag) .ASN1_EXP_EX(stname, field, type, tag, .ASN1_TFLG_SET_OF)

	//#define ASN1_IMP_SET_OF_OPT(stname, field, type, tag) .ASN1_IMP_EX(stname, field, type, tag, .ASN1_TFLG_SET_OF | .ASN1_TFLG_OPTIONAL)

	//#define ASN1_EXP_SET_OF_OPT(stname, field, type, tag) .ASN1_EXP_EX(stname, field, type, tag, .ASN1_TFLG_SET_OF | .ASN1_TFLG_OPTIONAL)

	//#define ASN1_IMP_SEQUENCE_OF(stname, field, type, tag) .ASN1_IMP_EX(stname, field, type, tag, .ASN1_TFLG_SEQUENCE_OF)

	//#define ASN1_IMP_SEQUENCE_OF_OPT(stname, field, type, tag) .ASN1_IMP_EX(stname, field, type, tag, .ASN1_TFLG_SEQUENCE_OF | .ASN1_TFLG_OPTIONAL)

	//#define ASN1_EXP_SEQUENCE_OF(stname, field, type, tag) .ASN1_EXP_EX(stname, field, type, tag, .ASN1_TFLG_SEQUENCE_OF)

	//#define ASN1_EXP_SEQUENCE_OF_OPT(stname, field, type, tag) .ASN1_EXP_EX(stname, field, type, tag, .ASN1_TFLG_SEQUENCE_OF | .ASN1_TFLG_OPTIONAL)

	/* EXPLICIT using indefinite length constructed form */
	//#define ASN1_NDEF_EXP(stname, field, type, tag) .ASN1_EXP_EX(stname, field, type, tag, .ASN1_TFLG_NDEF)

	/* EXPLICIT OPTIONAL using indefinite length constructed form */
	//#define ASN1_NDEF_EXP_OPT(stname, field, type, tag) .ASN1_EXP_EX(stname, field, type, tag, .ASN1_TFLG_OPTIONAL | .ASN1_TFLG_NDEF)

	/* Macros for the ASN1_ADB structure */

	//#define ASN1_ADB(name) static const .ASN1_ADB_TABLE name##_adbtbl[]

	//#define ASN1_ADB_END(name, flags, field, app_table, def, none) ; static const .ASN1_ADB name##_adb = {flags, offsetof(name, field), app_table, name##_adbtbl, (name##_adbtbl).sizeof / .ASN1_ADB_TABLE.sizeof, def, none}

	//#define ADB_ENTRY(val, template) { val, template }

	//#define ASN1_ADB_TEMPLATE(name) static const libressl_d.openssl.asn1.ASN1_TEMPLATE name##_tt
}

/**
 * This is the ASN1 template structure that defines
 * a wrapper round the actual type. It determines the
 * actual position of the field in the value structure,
 * various flags such as OPTIONAL and the field name.
 */
struct ASN1_TEMPLATE_st
{
	/**
	 * Various flags
	 */
	core.stdc.config.c_ulong flags;

	/**
	 * tag, not used if no tagging
	 */
	core.stdc.config.c_long tag;

	/**
	 * Offset of this field in structure
	 */
	core.stdc.config.c_ulong offset;

	version (NO_ASN1_FIELD_NAMES) {
	} else {
		/**
		 * Field name
		 */
		const (char)* field_name;
	}

	/**
	 * Relevant ASN1_ITEM or ASN1_ADB
	 */
	libressl_d.openssl.asn1.ASN1_ITEM_EXP* item;
}

/* Macro to extract ASN1_ITEM and ASN1_ADB pointer from ASN1_TEMPLATE */

//#define ASN1_TEMPLATE_item(t) (t.item_ptr)
//#define ASN1_TEMPLATE_adb(t) (t.item_ptr)

alias ASN1_ADB_TABLE = .ASN1_ADB_TABLE_st;
alias ASN1_ADB = .ASN1_ADB_st;

package alias stack_st_ASN1_ADB_TABLE = void;

struct ASN1_ADB_st
{
	/**
	 * Various flags
	 */
	core.stdc.config.c_ulong flags;

	/**
	 * Offset of selector field
	 */
	core.stdc.config.c_ulong offset;

	/**
	 * Application defined items
	 */
	stack_st_ASN1_ADB_TABLE** app_items;

	/**
	 * Table of possible types
	 */
	const (.ASN1_ADB_TABLE)* tbl;

	/**
	 * Number of entries in tbl
	 */
	core.stdc.config.c_long tblcount;

	/**
	 * Type to use if no match
	 */
	const (libressl_d.openssl.asn1.ASN1_TEMPLATE)* default_tt;

	/**
	 * Type to use if selector is null
	 */
	const (libressl_d.openssl.asn1.ASN1_TEMPLATE)* null_tt;
}

struct ASN1_ADB_TABLE_st
{
	/**
	 * NID for an object or value for an int
	 */
	core.stdc.config.c_long value;

	/**
	 * item for this value
	 */
	const libressl_d.openssl.asn1.ASN1_TEMPLATE tt;
}

/* template flags */

/**
 * Field is optional
 */
enum ASN1_TFLG_OPTIONAL = 0x01;

/**
 * Field is a SET OF
 */
enum ASN1_TFLG_SET_OF = 0x01 << 1;

/**
 * Field is a SEQUENCE OF
 */
enum ASN1_TFLG_SEQUENCE_OF = 0x02 << 1;

/**
 * Special case: this refers to a SET OF that
 * will be sorted into DER order when encoded *and*
 * the corresponding STACK will be modified to match
 * the new order.
 */
enum ASN1_TFLG_SET_ORDER = 0x03 << 1;

/* Mask for SET OF or SEQUENCE OF */
enum ASN1_TFLG_SK_MASK = 0x03 << 1;

/*
 * These flags mean the tag should be taken from the
 * tag field. If EXPLICIT then the underlying type
 * is used for the inner tag.
 */

/**
 * IMPLICIT tagging
 */
enum ASN1_TFLG_IMPTAG = 0x01 << 3;

/**
 * EXPLICIT tagging, inner tag from underlying type
 */
enum ASN1_TFLG_EXPTAG = 0x02 << 3;

enum ASN1_TFLG_TAG_MASK = 0x03 << 3;

/**
 * context specific IMPLICIT
 */
enum ASN1_TFLG_IMPLICIT = .ASN1_TFLG_IMPTAG | .ASN1_TFLG_CONTEXT;

/**
 * context specific EXPLICIT
 */
enum ASN1_TFLG_EXPLICIT = .ASN1_TFLG_EXPTAG | .ASN1_TFLG_CONTEXT;

/*
 * If tagging is in force these determine the
 * type of tag to use. Otherwise the tag is
 * determined by the underlying type. These
 * values reflect the actual octet format.
 */

/**
 * Universal tag
 */
enum ASN1_TFLG_UNIVERSAL = 0x00 << 6;

/**
 * Application tag
 */
enum ASN1_TFLG_APPLICATION = 0x01 << 6;

/**
 * Context specific tag
 */
enum ASN1_TFLG_CONTEXT = 0x02 << 6;

/**
 * Private tag
 */
enum ASN1_TFLG_PRIVATE = 0x03 << 6;

enum ASN1_TFLG_TAG_CLASS = 0x03 << 6;

/*
 * These are for ANY DEFINED BY type. In this case
 * the 'item' field points to an ASN1_ADB structure
 * which contains a table of values to decode the
 * relevant type
 */

enum ASN1_TFLG_ADB_MASK = 0x03 << 8;

enum ASN1_TFLG_ADB_OID = 0x01 << 8;

enum ASN1_TFLG_ADB_INT = 0x01 << 9;

/**
 * This flag means a parent structure is passed
 * instead of the field: this is useful is a
 * SEQUENCE is being combined with a CHOICE for
 * example. Since this means the structure and
 * item name will differ we need to use the
 * ASN1_CHOICE_END_name() macro for example.
 */
enum ASN1_TFLG_COMBINE = 0x01 << 10;

/**
 * This flag when present in a SEQUENCE OF, SET OF
 * or EXPLICIT causes indefinite length constructed
 * encoding to be used if required.
 */
enum ASN1_TFLG_NDEF = 0x01 << 11;

/**
 * This is the actual ASN1 item itself
 */
struct ASN1_ITEM_st
{
	/**
	 * The item type, primitive, SEQUENCE, CHOICE or extern
	 */
	char itype;

	/**
	 * underlying type
	 */
	core.stdc.config.c_long utype;

	/**
	 * If SEQUENCE or CHOICE this contains the contents
	 */
	const (libressl_d.openssl.asn1.ASN1_TEMPLATE)* templates;

	/**
	 * Number of templates if SEQUENCE or CHOICE
	 */
	core.stdc.config.c_long tcount;

	/**
	 * functions that handle this type
	 */
	const (void)* funcs;

	/**
	 * Structure size (usually)
	 */
	core.stdc.config.c_long size;

	version (NO_ASN1_FIELD_NAMES) {
	} else {
		/**
		 * Structure name
		 */
		const (char)* sname;
	}
}

/*
 * These are values for the itype field and
 * determine how the type is interpreted.
 *
 * For PRIMITIVE types the underlying type
 * determines the behaviour if items is null.
 *
 * Otherwise templates must contain a single
 * template and the type is treated in the
 * same way as the type specified in the template.
 *
 * For SEQUENCE types the templates field points
 * to the members, the size field is the
 * structure size.
 *
 * For CHOICE types the templates field points
 * to each possible member (typically a union)
 * and the 'size' field is the offset of the
 * selector.
 *
 * The 'funcs' field is used for application
 * specific functions.
 *
 * The EXTERN type uses a new style d2i/i2d.
 * The new style should be used where possible
 * because it avoids things like the d2i IMPLICIT
 * hack.
 *
 * MSTRING is a multiple string type, it is used
 * for a CHOICE of character strings where the
 * actual strings all occupy an ASN1_STRING
 * structure. In this case the 'utype' field
 * has a special meaning, it is used as a mask
 * of acceptable types using the B_ASN1 constants.
 *
 * NDEF_SEQUENCE is the same as SEQUENCE except
 * that it will use indefinite length constructed
 * encoding if requested.
 *
 */

enum ASN1_ITYPE_PRIMITIVE = 0x00;

enum ASN1_ITYPE_SEQUENCE = 0x01;

enum ASN1_ITYPE_CHOICE = 0x02;

enum ASN1_ITYPE_EXTERN = 0x04;

enum ASN1_ITYPE_MSTRING = 0x05;

enum ASN1_ITYPE_NDEF_SEQUENCE = 0x06;

/**
 * Cache for ASN1 tag and length, so we
 * don't keep re-reading it for things
 * like CHOICE
 */
struct ASN1_TLC_st
{
	/**
	 * Values below are valid
	 */
	char valid;

	/**
	 * return value
	 */
	int ret;

	/**
	 * length
	 */
	core.stdc.config.c_long plen;

	/**
	 * class value
	 */
	int ptag;

	///Ditto
	int pclass;

	/**
	 * header length
	 */
	int hdrlen;
}

/* Typedefs for ASN1 function pointers */

alias ASN1_new_func = extern (C) nothrow @nogc libressl_d.openssl.asn1.ASN1_VALUE* function();
alias ASN1_free_func = extern (C) nothrow @nogc void function(libressl_d.openssl.asn1.ASN1_VALUE* a);
alias ASN1_d2i_func = extern (C) nothrow @nogc libressl_d.openssl.asn1.ASN1_VALUE* function(libressl_d.openssl.asn1.ASN1_VALUE** a, const (ubyte)** in_, core.stdc.config.c_long length_);
alias ASN1_i2d_func = extern (C) nothrow @nogc int function(libressl_d.openssl.asn1.ASN1_VALUE* a, ubyte** in_);

alias ASN1_ex_d2i = extern (C) nothrow @nogc int function(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (ubyte)** in_, core.stdc.config.c_long len, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, int tag, int aclass, char opt, libressl_d.openssl.asn1.ASN1_TLC* ctx);

alias ASN1_ex_i2d = extern (C) nothrow @nogc int function(libressl_d.openssl.asn1.ASN1_VALUE** pval, ubyte** out_, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, int tag, int aclass);
alias ASN1_ex_new_func = extern (C) nothrow @nogc int function(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
alias ASN1_ex_free_func = extern (C) nothrow @nogc void function(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);

alias ASN1_ex_print_func = extern (C) nothrow @nogc int function(libressl_d.openssl.bio.BIO* out_, libressl_d.openssl.asn1.ASN1_VALUE** pval, int indent, const (char)* fname, const (libressl_d.openssl.ossl_typ.ASN1_PCTX)* pctx);

alias ASN1_primitive_i2c = extern (C) nothrow @nogc int function(libressl_d.openssl.asn1.ASN1_VALUE** pval, ubyte* cont, int* putype, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
alias ASN1_primitive_c2i = extern (C) nothrow @nogc int function(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (ubyte)* cont, int len, int utype, char* free_cont, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
alias ASN1_primitive_print = extern (C) nothrow @nogc int function(libressl_d.openssl.bio.BIO* out_, libressl_d.openssl.asn1.ASN1_VALUE** pval, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, int indent, const (libressl_d.openssl.ossl_typ.ASN1_PCTX)* pctx);

struct ASN1_EXTERN_FUNCS_st
{
	void* app_data;
	.ASN1_ex_new_func* asn1_ex_new;
	.ASN1_ex_free_func* asn1_ex_free;
	.ASN1_ex_free_func* asn1_ex_clear;
	.ASN1_ex_d2i* asn1_ex_d2i;
	.ASN1_ex_i2d* asn1_ex_i2d;
	.ASN1_ex_print_func* asn1_ex_print;
}

alias ASN1_EXTERN_FUNCS = .ASN1_EXTERN_FUNCS_st;

struct ASN1_PRIMITIVE_FUNCS_st
{
	void* app_data;
	core.stdc.config.c_ulong flags;
	.ASN1_ex_new_func* prim_new;
	.ASN1_ex_free_func* prim_free;
	.ASN1_ex_free_func* prim_clear;
	.ASN1_primitive_c2i* prim_c2i;
	.ASN1_primitive_i2c* prim_i2c;
	.ASN1_primitive_print* prim_print;
}

alias ASN1_PRIMITIVE_FUNCS = .ASN1_PRIMITIVE_FUNCS_st;

/*
 * This is the ASN1_AUX structure: it handles various
 * miscellaneous requirements. For example the use of
 * reference counts and an informational callback.
 *
 * The "informational callback" is called at various
 * points during the ASN1 encoding and decoding. It can
 * be used to provide minor customisation of the structures
 * used. This is most useful where the supplied routines
 * *almost* do the right thing but need some extra help
 * at a few points. If the callback returns zero then
 * it is assumed a fatal error has occurred and the
 * main operation should be abandoned.
 *
 * If major changes in the default behaviour are required
 * then an external type is more appropriate.
 */

alias ASN1_aux_cb = extern (C) nothrow @nogc int function(int operation, libressl_d.openssl.asn1.ASN1_VALUE** in_, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, void* exarg);

struct ASN1_AUX_st
{
	void* app_data;
	int flags;

	/**
	 * Offset of reference value
	 */
	int ref_offset;

	/**
	 * Lock type to use
	 */
	int ref_lock;

	.ASN1_aux_cb* asn1_cb;

	/**
	 * Offset of ASN1_ENCODING structure
	 */
	int enc_offset;
}

alias ASN1_AUX = .ASN1_AUX_st;

/**
 * For print related callbacks exarg points to this structure
 */
struct ASN1_PRINT_ARG_st
{
	libressl_d.openssl.bio.BIO* out_;
	int indent;
	const (libressl_d.openssl.ossl_typ.ASN1_PCTX)* pctx;
}

alias ASN1_PRINT_ARG = .ASN1_PRINT_ARG_st;

/**
 * For streaming related callbacks exarg points to this structure
 */
struct ASN1_STREAM_ARG_st
{
	/**
	 * BIO to stream through
	 */
	libressl_d.openssl.bio.BIO* out_;

	/**
	 * BIO with filters appended
	 */
	libressl_d.openssl.bio.BIO* ndef_bio;

	/**
	 * Streaming I/O boundary
	 */
	ubyte** boundary;
}

alias ASN1_STREAM_ARG = .ASN1_STREAM_ARG_st;

/* Flags in ASN1_AUX */

/**
 * Use a reference count
 */
enum ASN1_AFLG_REFCOUNT = 1;

/**
 * Save the encoding of structure (useful for signatures)
 */
enum ASN1_AFLG_ENCODING = 2;

/**
 * The Sequence length is invalid
 */
enum ASN1_AFLG_BROKEN = 4;

/* operation values for asn1_cb */

enum ASN1_OP_NEW_PRE = 0;
enum ASN1_OP_NEW_POST = 1;
enum ASN1_OP_FREE_PRE = 2;
enum ASN1_OP_FREE_POST = 3;
enum ASN1_OP_D2I_PRE = 4;
enum ASN1_OP_D2I_POST = 5;
enum ASN1_OP_I2D_PRE = 6;
enum ASN1_OP_I2D_POST = 7;
enum ASN1_OP_PRINT_PRE = 8;
enum ASN1_OP_PRINT_POST = 9;
enum ASN1_OP_STREAM_PRE = 10;
enum ASN1_OP_STREAM_POST = 11;
enum ASN1_OP_DETACHED_PRE = 12;
enum ASN1_OP_DETACHED_POST = 13;

version (LIBRESSL_INTERNAL) {
} else {
	/* Macro to implement a primitive type */
	//#define IMPLEMENT_ASN1_TYPE(stname) .IMPLEMENT_ASN1_TYPE_ex(stname, stname, 0)
	//#define IMPLEMENT_ASN1_TYPE_ex(itname, vname, ex) .ASN1_ITEM_start(itname) .ASN1_ITYPE_PRIMITIVE, V_##vname, null, 0, null, ex, #itname .ASN1_ITEM_end(itname)

	/* Macro to implement a multi string type */
	//#define IMPLEMENT_ASN1_MSTRING(itname, mask) .ASN1_ITEM_start(itname) .ASN1_ITYPE_MSTRING, mask, null, 0, null, libressl_d.openssl.ossl_typ.ASN1_STRING.sizeof, #itname .ASN1_ITEM_end(itname)
	//#define IMPLEMENT_EXTERN_ASN1(sname, tag, fptrs) .ASN1_ITEM_start(sname) .ASN1_ITYPE_EXTERN, tag, null, 0, &fptrs, 0, #sname .ASN1_ITEM_end(sname)

	/* Macro to implement standard functions in terms of ASN1_ITEM structures */

	//#define IMPLEMENT_ASN1_FUNCTIONS(stname) .IMPLEMENT_ASN1_FUNCTIONS_fname(stname, stname, stname)

	//#define IMPLEMENT_ASN1_FUNCTIONS_name(stname, itname) .IMPLEMENT_ASN1_FUNCTIONS_fname(stname, itname, itname)

	//#define IMPLEMENT_ASN1_FUNCTIONS_ENCODE_name(stname, itname) IMPLEMENT_ASN1_FUNCTIONS_ENCODE_fname(stname, itname, itname)

	//#define IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(stname) .IMPLEMENT_ASN1_ALLOC_FUNCTIONS_pfname(static, stname, stname, stname)

	//#define IMPLEMENT_ASN1_ALLOC_FUNCTIONS(stname) .IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname(stname, stname, stname)

	//#define IMPLEMENT_ASN1_ALLOC_FUNCTIONS_pfname(pre, stname, itname, fname) pre stname* fname##_new(void) { return (stname*) libressl_d.openssl.asn1.ASN1_item_new(libressl_d.openssl.asn1.ASN1_ITEM_rptr(itname)); } pre void fname##_free(stname* a) { libressl_d.openssl.asn1.ASN1_item_free(cast(libressl_d.openssl.asn1.ASN1_VALUE*)(a), libressl_d.openssl.asn1.ASN1_ITEM_rptr(itname)); }

	//#define IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname(stname, itname, fname) stname* fname##_new(void) { return (stname*) libressl_d.openssl.asn1.ASN1_item_new(libressl_d.openssl.asn1.ASN1_ITEM_rptr(itname)); } void fname##_free(stname* a) { libressl_d.openssl.asn1.ASN1_item_free(cast(libressl_d.openssl.asn1.ASN1_VALUE*)(a), libressl_d.openssl.asn1.ASN1_ITEM_rptr(itname)); }

	//#define IMPLEMENT_ASN1_FUNCTIONS_fname(stname, itname, fname) .IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(stname, itname, fname) .IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname(stname, itname, fname)

	//#define IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(stname, itname, fname) stname* d2i_##fname(stname** a, const (ubyte)** in_, core.stdc.config.c_long len) { return (stname*) libressl_d.openssl.asn1.ASN1_item_d2i(cast(libressl_d.openssl.asn1.ASN1_VALUE**)(a), in_, len, libressl_d.openssl.asn1.ASN1_ITEM_rptr(itname)); } int i2d_##fname(stname* a, ubyte** out_) { return libressl_d.openssl.asn1.ASN1_item_i2d(cast(libressl_d.openssl.asn1.ASN1_VALUE*)(a), out_, libressl_d.openssl.asn1.ASN1_ITEM_rptr(itname)); }

	//#define IMPLEMENT_ASN1_NDEF_FUNCTION(stname) int i2d_##stname##_NDEF(stname* a, ubyte** out_) { return libressl_d.openssl.asn1.ASN1_item_ndef_i2d(cast(libressl_d.openssl.asn1.ASN1_VALUE*)(a), out_, libressl_d.openssl.asn1.ASN1_ITEM_rptr(stname)); }

	/*
	 * This includes evil casts to remove const: they will go away when full
	 * ASN1 constification is done.
	 */
	//#define IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(stname, itname, fname) stname* d2i_##fname(stname** a, const (ubyte)** in_, core.stdc.config.c_long len) { return (stname*) libressl_d.openssl.asn1.ASN1_item_d2i(cast(libressl_d.openssl.asn1.ASN1_VALUE**)(a), in_, len, libressl_d.openssl.asn1.ASN1_ITEM_rptr(itname)); } int i2d_##fname(const (stname)* a, ubyte** out_) { return libressl_d.openssl.asn1.ASN1_item_i2d(cast(libressl_d.openssl.asn1.ASN1_VALUE*)(a), out_, libressl_d.openssl.asn1.ASN1_ITEM_rptr(itname)); }

	//#define IMPLEMENT_ASN1_DUP_FUNCTION(stname) stname* stname##_dup(stname* x) { return libressl_d.openssl.asn1.ASN1_item_dup(libressl_d.openssl.asn1.ASN1_ITEM_rptr(stname), x); }

	//#define IMPLEMENT_ASN1_PRINT_FUNCTION(stname) .IMPLEMENT_ASN1_PRINT_FUNCTION_fname(stname, stname, stname)

	//#define IMPLEMENT_ASN1_PRINT_FUNCTION_fname(stname, itname, fname) int fname##_print_ctx(libressl_d.openssl.bio.BIO* out_, stname* x, int indent, const (libressl_d.openssl.ossl_typ.ASN1_PCTX)* pctx) { return libressl_d.openssl.asn1.ASN1_item_print(out_, cast(libressl_d.openssl.asn1.ASN1_VALUE*)(x), indent, libressl_d.openssl.asn1.ASN1_ITEM_rptr(itname), pctx); }

	//#define IMPLEMENT_ASN1_FUNCTIONS_const(name) .IMPLEMENT_ASN1_FUNCTIONS_const_fname(name, name, name)

	//#define IMPLEMENT_ASN1_FUNCTIONS_const_fname(stname, itname, fname) .IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(stname, itname, fname) .IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname(stname, itname, fname)
}

/* external definitions for primitive types */

extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_BOOLEAN_it;
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_TBOOLEAN_it;
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_FBOOLEAN_it;
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM ASN1_SEQUENCE_it;
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM CBIGNUM_it;
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM BIGNUM_it;
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM LONG_it;
extern __gshared const libressl_d.openssl.ossl_typ.ASN1_ITEM ZLONG_it;

//DECLARE_STACK_OF(ASN1_VALUE)
struct stack_st_ASN1_VALUE
{
	libressl_d.openssl.stack._STACK stack;
}

/* Functions used internally by the ASN1 code */

int ASN1_item_ex_new(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
void ASN1_item_ex_free(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
int ASN1_template_new(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (libressl_d.openssl.asn1.ASN1_TEMPLATE)* tt);
int ASN1_primitive_new(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);

void ASN1_template_free(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (libressl_d.openssl.asn1.ASN1_TEMPLATE)* tt);
int ASN1_template_d2i(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (ubyte)** in_, core.stdc.config.c_long len, const (libressl_d.openssl.asn1.ASN1_TEMPLATE)* tt);
int ASN1_item_ex_d2i(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (ubyte)** in_, core.stdc.config.c_long len, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, int tag, int aclass, char opt, libressl_d.openssl.asn1.ASN1_TLC* ctx);

int ASN1_item_ex_i2d(libressl_d.openssl.asn1.ASN1_VALUE** pval, ubyte** out_, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it, int tag, int aclass);
int ASN1_template_i2d(libressl_d.openssl.asn1.ASN1_VALUE** pval, ubyte** out_, const (libressl_d.openssl.asn1.ASN1_TEMPLATE)* tt);
void ASN1_primitive_free(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);

int asn1_ex_c2i(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (ubyte)* cont, int len, int utype, char* free_cont, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);

int asn1_get_choice_selector(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
int asn1_set_choice_selector(libressl_d.openssl.asn1.ASN1_VALUE** pval, int value, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);

libressl_d.openssl.asn1.ASN1_VALUE** asn1_get_field_ptr(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (libressl_d.openssl.asn1.ASN1_TEMPLATE)* tt);

const (libressl_d.openssl.asn1.ASN1_TEMPLATE)* asn1_do_adb(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (libressl_d.openssl.asn1.ASN1_TEMPLATE)* tt, int nullerr);

int asn1_do_lock(libressl_d.openssl.asn1.ASN1_VALUE** pval, int op, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);

void asn1_enc_init(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
void asn1_enc_free(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
int asn1_enc_restore(int* len, ubyte** out_, libressl_d.openssl.asn1.ASN1_VALUE** pval, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
int asn1_enc_save(libressl_d.openssl.asn1.ASN1_VALUE** pval, const (ubyte)* in_, int inlen, const (libressl_d.openssl.ossl_typ.ASN1_ITEM)* it);
