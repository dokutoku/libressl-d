/* $OpenBSD: ec.h,v 1.27 2021/09/12 16:23:19 tb Exp $ */
/*
 * Originally written by Bodo Moeller for the OpenSSL project.
 */
/**
 * Include file for the OpenSSL EC functions
 *
 * Author: Originally written by Bodo Moeller for the OpenSSL project
 */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */
module libressl_d.openssl.ec;


private static import core.stdc.config;
private static import libressl_d.compat.stdio;
private static import libressl_d.openssl.bio;
private static import libressl_d.openssl.crypto;
private static import libressl_d.openssl.evp;
private static import libressl_d.openssl.ossl_typ;
public import libressl_d.openssl.asn1;
public import libressl_d.openssl.bn;
public import libressl_d.openssl.opensslconf;

version (OPENSSL_NO_EC) {
	static assert(false, "EC is disabled.");
}

version (OPENSSL_NO_DEPRECATED) {
} else {
	public import libressl_d.openssl.bn;
}

extern (C):
nothrow @nogc:

enum OPENSSL_ECC_MAX_FIELD_BITS = 661;

/**
 * Enum for the point conversion form as defined in X9.62 (ECDSA)
 *  for the encoding of a elliptic curve point (x,y)
 */
enum point_conversion_form_t
{
	/**
	 * the point is encoded as z||x, where the octet z specifies
	 *  which solution of the quadratic equation y is
	 */
	POINT_CONVERSION_COMPRESSED = 2,

	/**
	 * the point is encoded as z||x||y, where z is the octet 0x02
	 */
	POINT_CONVERSION_UNCOMPRESSED = 4,

	/**
	 * the point is encoded as z||x||y, where the octet z specifies
	 *  which solution of the quadratic equation y is
	 */
	POINT_CONVERSION_HYBRID = 6,
}

//Declaration name in C language
enum
{
	POINT_CONVERSION_COMPRESSED = .point_conversion_form_t.POINT_CONVERSION_COMPRESSED,
	POINT_CONVERSION_UNCOMPRESSED = .point_conversion_form_t.POINT_CONVERSION_UNCOMPRESSED,
	POINT_CONVERSION_HYBRID = .point_conversion_form_t.POINT_CONVERSION_HYBRID,
}

struct ec_method_st;
alias EC_METHOD = .ec_method_st;

/*
 * EC_METHOD *meth;
 * -- field definition
 * -- curve coefficients
 * -- optional generator with associated information (order, cofactor)
 * -- optional extra data (precomputed table for fast computation of multiples of generator)
 * -- ASN1 stuff
 */
struct ec_group_st;
alias EC_GROUP = .ec_group_st;

struct ec_point_st;
alias EC_POINT = .ec_point_st;

/* *******************************************************************/
/*               EC_METHODs for curves over GF(p)                   */
/* *******************************************************************/

/**
 * Returns the basic GFp ec methods which provides the basis for the optimized methods.
 *
 * Returns: EC_METHOD object
 */
const (.EC_METHOD)* EC_GFp_simple_method();

/**
 * Returns GFp methods using montgomery multiplication.
 *
 * Returns: EC_METHOD object
 */
const (.EC_METHOD)* EC_GFp_mont_method();

/**
 * Returns GFp methods using optimized methods for NIST recommended curves
 *
 * Returns: EC_METHOD object
 */
const (.EC_METHOD)* EC_GFp_nist_method();

version (OPENSSL_NO_EC_NISTP_64_GCC_128) {
} else {
	/**
	 * Returns 64-bit optimized methods for nistp224
	 *
	 * Returns: EC_METHOD object
	 */
	const (.EC_METHOD)* EC_GFp_nistp224_method();

	/**
	 * Returns 64-bit optimized methods for nistp256
	 *
	 * Returns: EC_METHOD object
	 */
	const (.EC_METHOD)* EC_GFp_nistp256_method();

	/**
	 * Returns 64-bit optimized methods for nistp521
	 *
	 * Returns: EC_METHOD object
	 */
	const (.EC_METHOD)* EC_GFp_nistp521_method();
}

version (OPENSSL_NO_EC2M) {
} else {
	/* *******************************************************************/
	/*           EC_METHOD for curves over GF(2^m)                      */
	/* *******************************************************************/

	/**
	 * Returns the basic GF2m ec method
	 *
	 * Returns: EC_METHOD object
	 */
	const (.EC_METHOD)* EC_GF2m_simple_method();
}

/* *******************************************************************/
/*                   EC_GROUP functions                             */
/* *******************************************************************/

/**
 * Creates a new EC_GROUP object
 *
 * Params:
 *      meth = EC_METHOD to use
 *
 * Returns: newly created EC_GROUP object or null in case of an error.
 */
.EC_GROUP* EC_GROUP_new(const (.EC_METHOD)* meth);

/**
 * Frees a EC_GROUP object
 *
 * Params:
 *      group = EC_GROUP object to be freed.
 */
void EC_GROUP_free(.EC_GROUP* group);

/**
 * Clears and frees a EC_GROUP object
 *
 * Params:
 *      group = EC_GROUP object to be cleared and freed.
 */
void EC_GROUP_clear_free(.EC_GROUP* group);

/**
 * Copies EC_GROUP objects. Note: both EC_GROUPs must use the same EC_METHOD.
 *
 * Params:
 *      dst = destination EC_GROUP object
 *      src = source EC_GROUP object
 *
 * Returns: 1 on success and 0 if an error occurred.
 */
int EC_GROUP_copy(.EC_GROUP* dst, const (.EC_GROUP)* src);

/**
 * Creates a new EC_GROUP object and copies the copies the content form src to the newly created EC_KEY object
 *
 * Params:
 *      src = source EC_GROUP object
 *
 * Returns: newly created EC_GROUP object or null in case of an error.
 */
.EC_GROUP* EC_GROUP_dup(const (.EC_GROUP)* src);

/**
 * Returns the EC_METHOD of the EC_GROUP object.
 *
 * Params:
 *      group = EC_GROUP object
 *
 * Returns: EC_METHOD used in this EC_GROUP object.
 */
const (.EC_METHOD)* EC_GROUP_method_of(const (.EC_GROUP)* group);

/**
 * Returns the field type of the EC_METHOD.
 *
 * Params:
 *      meth = EC_METHOD object
 *
 * Returns: NID of the underlying field type OID.
 */
int EC_METHOD_get_field_type(const (.EC_METHOD)* meth);

/**
 * Sets the generator and it's order/cofactor of a EC_GROUP object.
 *
 * Params:
 *      group = EC_GROUP object
 *      generator = EC_POINT object with the generator.
 *      order = the order of the group generated by the generator.
 *      cofactor = the index of the sub-group generated by the generator in the group of all points on the elliptic curve.
 *
 * Returns: 1 on success and 0 if an error occured
 */
int EC_GROUP_set_generator(.EC_GROUP* group, const (.EC_POINT)* generator, const (libressl_d.openssl.ossl_typ.BIGNUM)* order, const (libressl_d.openssl.ossl_typ.BIGNUM)* cofactor);

/**
 * Returns the generator of a EC_GROUP object.
 *
 * Params:
 *      group = EC_GROUP object
 *
 * Returns: the currently used generator (possibly null).
 */
const (.EC_POINT)* EC_GROUP_get0_generator(const (.EC_GROUP)* group);

/**
 * Gets the order of a EC_GROUP
 *
 * Params:
 *      group = EC_GROUP object
 *      order = BIGNUM to which the order is copied
 *      ctx = BN_CTX object (optional)
 *
 * Returns: 1 on success and 0 if an error occured
 */
int EC_GROUP_get_order(const (.EC_GROUP)* group, libressl_d.openssl.ossl_typ.BIGNUM* order, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

int EC_GROUP_order_bits(const (.EC_GROUP)* group);

/**
 * Gets the cofactor of a EC_GROUP
 *
 * Params:
 *      group = EC_GROUP object
 *      cofactor = BIGNUM to which the cofactor is copied
 *      ctx = BN_CTX object (optional)
 *
 * Returns: 1 on success and 0 if an error occured
 */
int EC_GROUP_get_cofactor(const (.EC_GROUP)* group, libressl_d.openssl.ossl_typ.BIGNUM* cofactor, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

/**
 * Sets the name of a EC_GROUP object
 *
 * Params:
 *      group = EC_GROUP object
 *      nid = NID of the curve name OID
 */
void EC_GROUP_set_curve_name(.EC_GROUP* group, int nid);

/**
 * Returns the curve name of a EC_GROUP object
 *
 * Params:
 *      group = EC_GROUP object
 *
 * Returns: NID of the curve name OID or 0 if not set.
 */
int EC_GROUP_get_curve_name(const (.EC_GROUP)* group);

void EC_GROUP_set_asn1_flag(.EC_GROUP* group, int flag);
int EC_GROUP_get_asn1_flag(const (.EC_GROUP)* group);

void EC_GROUP_set_point_conversion_form(.EC_GROUP* group, .point_conversion_form_t form);
.point_conversion_form_t EC_GROUP_get_point_conversion_form(const (.EC_GROUP)*);

ubyte* EC_GROUP_get0_seed(const (.EC_GROUP)* x);
size_t EC_GROUP_get_seed_len(const (.EC_GROUP)*);
size_t EC_GROUP_set_seed(.EC_GROUP*, const (ubyte)*, size_t len);

int EC_GROUP_set_curve(.EC_GROUP* group, const (libressl_d.openssl.ossl_typ.BIGNUM)* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* a, const (libressl_d.openssl.ossl_typ.BIGNUM)* b, libressl_d.openssl.ossl_typ.BN_CTX* ctx);
int EC_GROUP_get_curve(const (.EC_GROUP)* group, libressl_d.openssl.ossl_typ.BIGNUM* p, libressl_d.openssl.ossl_typ.BIGNUM* a, libressl_d.openssl.ossl_typ.BIGNUM* b, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

version (LIBRESSL_INTERNAL) {
} else {
	/**
	 * Sets the parameter of a ec over GFp defined by y^2 = x^3 + a*x + b
	 *
	 * Params:
	 *      group = EC_GROUP object
	 *      p = BIGNUM with the prime number
	 *      a = BIGNUM with parameter a of the equation
	 *      b = BIGNUM with parameter b of the equation
	 *      ctx = BN_CTX object (optional)
	 *
	 * Returns: 1 on success and 0 if an error occured
	 */
	int EC_GROUP_set_curve_GFp(.EC_GROUP* group, const (libressl_d.openssl.ossl_typ.BIGNUM)* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* a, const (libressl_d.openssl.ossl_typ.BIGNUM)* b, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * Gets the parameter of the ec over GFp defined by y^2 = x^3 + a*x + b
	 *
	 * Params:
	 *      group = EC_GROUP object
	 *      p = BIGNUM for the prime number
	 *      a = BIGNUM for parameter a of the equation
	 *      b = BIGNUM for parameter b of the equation
	 *      ctx = BN_CTX object (optional)
	 *
	 * Returns: 1 on success and 0 if an error occured
	 */
	int EC_GROUP_get_curve_GFp(const (.EC_GROUP)* group, libressl_d.openssl.ossl_typ.BIGNUM* p, libressl_d.openssl.ossl_typ.BIGNUM* a, libressl_d.openssl.ossl_typ.BIGNUM* b, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

	version (OPENSSL_NO_EC2M) {
	} else {
		/**
		 * Sets the parameter of a ec over GF2m defined by y^2 + x*y = x^3 + a*x^2 + b
		 *
		 * Params:
		 *      group = EC_GROUP object
		 *      p = BIGNUM with the polynomial defining the underlying field
		 *      a = BIGNUM with parameter a of the equation
		 *      b = BIGNUM with parameter b of the equation
		 *      ctx = BN_CTX object (optional)
		 *
		 * Returns: 1 on success and 0 if an error occured
		 */
		int EC_GROUP_set_curve_GF2m(.EC_GROUP* group, const (libressl_d.openssl.ossl_typ.BIGNUM)* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* a, const (libressl_d.openssl.ossl_typ.BIGNUM)* b, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

		/**
		 * Gets the parameter of the ec over GF2m defined by y^2 + x*y = x^3 + a*x^2 + b
		 *
		 * Params:
		 *      group = EC_GROUP object
		 *      p = BIGNUM for the polynomial defining the underlying field
		 *      a = BIGNUM for parameter a of the equation
		 *      b = BIGNUM for parameter b of the equation
		 *      ctx = BN_CTX object (optional)
		 *
		 * Returns: 1 on success and 0 if an error occured
		 */
		int EC_GROUP_get_curve_GF2m(const (.EC_GROUP)* group, libressl_d.openssl.ossl_typ.BIGNUM* p, libressl_d.openssl.ossl_typ.BIGNUM* a, libressl_d.openssl.ossl_typ.BIGNUM* b, libressl_d.openssl.ossl_typ.BN_CTX* ctx);
	}
}

/**
 * Returns the number of bits needed to represent a field element
 *
 * Params:
 *      group = EC_GROUP object
 *
 * Returns: number of bits needed to represent a field element
 */
int EC_GROUP_get_degree(const (.EC_GROUP)* group);

/**
 * Checks whether the parameter in the EC_GROUP define a valid ec group
 *
 * Params:
 *      group = EC_GROUP object
 *      ctx = BN_CTX object (optional)
 *
 * Returns: 1 if group is a valid ec group and 0 otherwise
 */
int EC_GROUP_check(const (.EC_GROUP)* group, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

/**
 * Checks whether the discriminant of the elliptic curve is zero or not
 *
 * Params:
 *      group = EC_GROUP object
 *      ctx = BN_CTX object (optional)
 *
 * Returns: 1 if the discriminant is not zero and 0 otherwise
 */
int EC_GROUP_check_discriminant(const (.EC_GROUP)* group, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

/**
 * Compares two EC_GROUP objects
 *
 * Params:
 *      a = first EC_GROUP object
 *      b = second EC_GROUP object
 *      ctx = BN_CTX object (optional)
 *
 * Returns: 0 if both groups are equal and 1 otherwise
 */
int EC_GROUP_cmp(const (.EC_GROUP)* a, const (.EC_GROUP)* b, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

/*
 * EC_GROUP_new_GF*() calls EC_GROUP_new() and EC_GROUP_set_GF*()
 * after choosing an appropriate EC_METHOD
 */

/**
 * Creates a new EC_GROUP object with the specified parameters defined over GFp (defined by the equation y^2 = x^3 + a*x + b)
 *
 * Params:
 *      p = BIGNUM with the prime number
 *      a = BIGNUM with the parameter a of the equation
 *      b = BIGNUM with the parameter b of the equation
 *      ctx = BN_CTX object (optional)
 *
 * Returns: newly created EC_GROUP object with the specified parameters
 */
.EC_GROUP* EC_GROUP_new_curve_GFp(const (libressl_d.openssl.ossl_typ.BIGNUM)* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* a, const (libressl_d.openssl.ossl_typ.BIGNUM)* b, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

version (OPENSSL_NO_EC2M) {
} else {
	/**
	 * Creates a new EC_GROUP object with the specified parameters defined over GF2m (defined by the equation y^2 + x*y = x^3 + a*x^2 + b)
	 *
	 * Params:
	 *      p = BIGNUM with the polynomial defining the underlying field
	 *      a = BIGNUM with the parameter a of the equation
	 *      b = BIGNUM with the parameter b of the equation
	 *      ctx = BN_CTX object (optional)
	 *
	 * Returns: newly created EC_GROUP object with the specified parameters
	 */
	.EC_GROUP* EC_GROUP_new_curve_GF2m(const (libressl_d.openssl.ossl_typ.BIGNUM)* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* a, const (libressl_d.openssl.ossl_typ.BIGNUM)* b, libressl_d.openssl.ossl_typ.BN_CTX* ctx);
}

/**
 * Creates a EC_GROUP object with a curve specified by a NID
 *
 * Params:
 *      nid = NID of the OID of the curve name
 *
 * Returns: newly created EC_GROUP object with specified curve or null if an error occurred
 */
.EC_GROUP* EC_GROUP_new_by_curve_name(int nid);

/* *******************************************************************/
/*               handling of internal curves                        */
/* *******************************************************************/

struct EC_builtin_curve
{
	int nid;
	const (char)* comment;
}

/**
 * EC_builtin_curves(EC_builtin_curve* , size_t size) returns number
 * of all available curves or zero if a error occurred.
 * In case r ist not zero nitems EC_builtin_curve structures
 * are filled with the data of the first nitems internal groups
 */
size_t EC_get_builtin_curves(.EC_builtin_curve* r, size_t nitems);

const (char)* EC_curve_nid2nist(int nid);
int EC_curve_nist2nid(const (char)* name);

/* *******************************************************************/
/*                    EC_POINT functions                            */
/* *******************************************************************/

/**
 * Creates a new EC_POINT object for the specified EC_GROUP
 *
 * Params:
 *      group = EC_GROUP the underlying EC_GROUP object
 *
 * Returns: newly created EC_POINT object or null if an error occurred
 */
.EC_POINT* EC_POINT_new(const (.EC_GROUP)* group);

/**
 * Frees a EC_POINT object
 *
 * Params:
 *      point = EC_POINT object to be freed
 */
void EC_POINT_free(.EC_POINT* point);

/**
 * Clears and frees a EC_POINT object
 *
 * Params:
 *      point = EC_POINT object to be cleared and freed
 */
void EC_POINT_clear_free(.EC_POINT* point);

/**
 * Copies EC_POINT object
 *
 * Params:
 *      dst = destination EC_POINT object
 *      src = source EC_POINT object
 *
 * Returns: 1 on success and 0 if an error occured
 */
int EC_POINT_copy(.EC_POINT* dst, const (.EC_POINT)* src);

/**
 * Creates a new EC_POINT object and copies the content of the supplied EC_POINT
 *
 * Params:
 *      src = source EC_POINT object
 *      group = underlying the EC_GROUP object
 *
 * Returns: newly created EC_POINT object or null if an error occurred
 */
.EC_POINT* EC_POINT_dup(const (.EC_POINT)* src, const (.EC_GROUP)* group);

/**
 * Returns the EC_METHOD used in EC_POINT object
 *
 * Params:
 *      point = EC_POINT object
 *
 * Returns: the EC_METHOD used
 */
const (.EC_METHOD)* EC_POINT_method_of(const (.EC_POINT)* point);

/**
 * Sets a point to infinity (neutral element)
 *
 * Params:
 *      group = underlying EC_GROUP object
 *      point = EC_POINT to set to infinity
 *
 * Returns: 1 on success and 0 if an error occured
 */
int EC_POINT_set_to_infinity(const (.EC_GROUP)* group, .EC_POINT* point);

int EC_POINT_set_affine_coordinates(const (.EC_GROUP)* group, .EC_POINT* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* x, const (libressl_d.openssl.ossl_typ.BIGNUM)* y, libressl_d.openssl.ossl_typ.BN_CTX* ctx);
int EC_POINT_get_affine_coordinates(const (.EC_GROUP)* group, const (.EC_POINT)* p, libressl_d.openssl.ossl_typ.BIGNUM* x, libressl_d.openssl.ossl_typ.BIGNUM* y, libressl_d.openssl.ossl_typ.BN_CTX* ctx);
int EC_POINT_set_compressed_coordinates(const (.EC_GROUP)* group, .EC_POINT* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* x, int y_bit, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

version (LIBRESSL_INTERNAL) {
	int EC_POINT_set_Jprojective_coordinates(const (.EC_GROUP)* group, .EC_POINT* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* x, const (libressl_d.openssl.ossl_typ.BIGNUM)* y, const (libressl_d.openssl.ossl_typ.BIGNUM)* z, libressl_d.openssl.ossl_typ.BN_CTX* ctx);
	int EC_POINT_get_Jprojective_coordinates(const (.EC_GROUP)* group, const (.EC_POINT)* p, libressl_d.openssl.ossl_typ.BIGNUM* x, libressl_d.openssl.ossl_typ.BIGNUM* y, libressl_d.openssl.ossl_typ.BIGNUM* z, libressl_d.openssl.ossl_typ.BN_CTX* ctx);
} else {
	/**
	 * Sets the jacobian projective coordinates of a EC_POINT over GFp
	 *
	 * Params:
	 *      group = underlying EC_GROUP object
	 *      p = EC_POINT object
	 *      x = BIGNUM with the x-coordinate
	 *      y = BIGNUM with the y-coordinate
	 *      z = BIGNUM with the z-coordinate
	 *      ctx = BN_CTX object (optional)
	 *
	 * Returns: 1 on success and 0 if an error occured
	 */
	int EC_POINT_set_Jprojective_coordinates_GFp(const (.EC_GROUP)* group, .EC_POINT* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* x, const (libressl_d.openssl.ossl_typ.BIGNUM)* y, const (libressl_d.openssl.ossl_typ.BIGNUM)* z, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * Gets the jacobian projective coordinates of a EC_POINT over GFp
	 *
	 * Params:
	 *      group = underlying EC_GROUP object
	 *      p = EC_POINT object
	 *      x = BIGNUM for the x-coordinate
	 *      y = BIGNUM for the y-coordinate
	 *      z = BIGNUM for the z-coordinate
	 *      ctx = BN_CTX object (optional)
	 *
	 * Returns: 1 on success and 0 if an error occured
	 */
	int EC_POINT_get_Jprojective_coordinates_GFp(const (.EC_GROUP)* group, const (.EC_POINT)* p, libressl_d.openssl.ossl_typ.BIGNUM* x, libressl_d.openssl.ossl_typ.BIGNUM* y, libressl_d.openssl.ossl_typ.BIGNUM* z, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * Sets the affine coordinates of a EC_POINT over GFp
	 *
	 * Params:
	 *      group = underlying EC_GROUP object
	 *      p = EC_POINT object
	 *      x = BIGNUM with the x-coordinate
	 *      y = BIGNUM with the y-coordinate
	 *      ctx = BN_CTX object (optional)
	 *
	 * Returns: 1 on success and 0 if an error occured
	 */
	int EC_POINT_set_affine_coordinates_GFp(const (.EC_GROUP)* group, .EC_POINT* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* x, const (libressl_d.openssl.ossl_typ.BIGNUM)* y, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * Gets the affine coordinates of a EC_POINT over GFp
	 *
	 * Params:
	 *      group = underlying EC_GROUP object
	 *      p = EC_POINT object
	 *      x = BIGNUM for the x-coordinate
	 *      y = BIGNUM for the y-coordinate
	 *      ctx = BN_CTX object (optional)
	 *
	 * Returns: 1 on success and 0 if an error occured
	 */
	int EC_POINT_get_affine_coordinates_GFp(const (.EC_GROUP)* group, const (.EC_POINT)* p, libressl_d.openssl.ossl_typ.BIGNUM* x, libressl_d.openssl.ossl_typ.BIGNUM* y, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

	/**
	 * Sets the x9.62 compressed coordinates of a EC_POINT over GFp
	 *
	 * Params:
	 *      group = underlying EC_GROUP object
	 *      p = EC_POINT object
	 *      x = BIGNUM with x-coordinate
	 *      y_bit = integer with the y-Bit (either 0 or 1)
	 *      ctx = BN_CTX object (optional)
	 *
	 * Returns: 1 on success and 0 if an error occured
	 */
	int EC_POINT_set_compressed_coordinates_GFp(const (.EC_GROUP)* group, .EC_POINT* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* x, int y_bit, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

	version (OPENSSL_NO_EC2M) {
	} else {
		/**
		 * Sets the affine coordinates of a EC_POINT over GF2m
		 *
		 * Params:
		 *      group = underlying EC_GROUP object
		 *      p = EC_POINT object
		 *      x = BIGNUM with the x-coordinate
		 *      y = BIGNUM with the y-coordinate
		 *      ctx = BN_CTX object (optional)
		 *
		 * Returns: 1 on success and 0 if an error occured
		 */
		int EC_POINT_set_affine_coordinates_GF2m(const (.EC_GROUP)* group, .EC_POINT* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* x, const (libressl_d.openssl.ossl_typ.BIGNUM)* y, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

		/**
		 * Gets the affine coordinates of a EC_POINT over GF2m
		 *
		 * Params:
		 *      group = underlying EC_GROUP object
		 *      p = EC_POINT object
		 *      x = BIGNUM for the x-coordinate
		 *      y = BIGNUM for the y-coordinate
		 *      ctx = BN_CTX object (optional)
		 *
		 * Returns: 1 on success and 0 if an error occured
		 */
		int EC_POINT_get_affine_coordinates_GF2m(const (.EC_GROUP)* group, const (.EC_POINT)* p, libressl_d.openssl.ossl_typ.BIGNUM* x, libressl_d.openssl.ossl_typ.BIGNUM* y, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

		/**
		 * Sets the x9.62 compressed coordinates of a EC_POINT over GF2m
		 *
		 * Params:
		 *      group = underlying EC_GROUP object
		 *      p = EC_POINT object
		 *      x = BIGNUM with x-coordinate
		 *      y_bit = integer with the y-Bit (either 0 or 1)
		 *      ctx = BN_CTX object (optional)
		 *
		 * Returns: 1 on success and 0 if an error occured
		 */
		int EC_POINT_set_compressed_coordinates_GF2m(const (.EC_GROUP)* group, .EC_POINT* p, const (libressl_d.openssl.ossl_typ.BIGNUM)* x, int y_bit, libressl_d.openssl.ossl_typ.BN_CTX* ctx);
	}
}

/**
 * Encodes a EC_POINT object to a octet string
 *
 * Params:
 *      group = underlying EC_GROUP object
 *      p = EC_POINT object
 *      form = point conversion form
 *      buf = memory buffer for the result. If null the function returns required buffer size.
 *      len = length of the memory buffer
 *      ctx = BN_CTX object (optional)
 *
 * Returns: the length of the encoded octet string or 0 if an error occurred
 */
size_t EC_POINT_point2oct(const (.EC_GROUP)* group, const (.EC_POINT)* p, .point_conversion_form_t form, ubyte* buf, size_t len, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

/**
 * Decodes a EC_POINT from a octet string
 *
 * Params:
 *      group = underlying EC_GROUP object
 *      p = EC_POINT object
 *      buf = memory buffer with the encoded ec point
 *      len = length of the encoded ec point
 *      ctx = BN_CTX object (optional)
 *
 * Returns: 1 on success and 0 if an error occured
 */
int EC_POINT_oct2point(const (.EC_GROUP)* group, .EC_POINT* p, const (ubyte)* buf, size_t len, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

/* other interfaces to point2oct/oct2point: */
libressl_d.openssl.ossl_typ.BIGNUM* EC_POINT_point2bn(const (.EC_GROUP)*, const (.EC_POINT)*, .point_conversion_form_t form, libressl_d.openssl.ossl_typ.BIGNUM*, libressl_d.openssl.ossl_typ.BN_CTX*);
.EC_POINT* EC_POINT_bn2point(const (.EC_GROUP)*, const (libressl_d.openssl.ossl_typ.BIGNUM)*, .EC_POINT*, libressl_d.openssl.ossl_typ.BN_CTX*);
char* EC_POINT_point2hex(const (.EC_GROUP)*, const (.EC_POINT)*, .point_conversion_form_t form, libressl_d.openssl.ossl_typ.BN_CTX*);
.EC_POINT* EC_POINT_hex2point(const (.EC_GROUP)*, const (char)*, .EC_POINT*, libressl_d.openssl.ossl_typ.BN_CTX*);

/* *******************************************************************/
/*         functions for doing EC_POINT arithmetic                  */
/* *******************************************************************/

/**
 * Computes the sum of two EC_POINT
 *
 * Params:
 *      group = underlying EC_GROUP object
 *      r = EC_POINT object for the result (r = a + b)
 *      a = EC_POINT object with the first summand
 *      b = EC_POINT object with the second summand
 *      ctx = BN_CTX object (optional)
 *
 * Returns: 1 on success and 0 if an error occured
 */
int EC_POINT_add(const (.EC_GROUP)* group, .EC_POINT* r, const (.EC_POINT)* a, const (.EC_POINT)* b, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

/**
 * Computes the double of a EC_POINT
 *
 * Params:
 *      group = underlying EC_GROUP object
 *      r = EC_POINT object for the result (r = 2 * a)
 *      a = EC_POINT object
 *      ctx = BN_CTX object (optional)
 *
 * Returns: 1 on success and 0 if an error occured
 */
int EC_POINT_dbl(const (.EC_GROUP)* group, .EC_POINT* r, const (.EC_POINT)* a, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

/**
 * Computes the inverse of a EC_POINT
 *
 * Params:
 *      group = underlying EC_GROUP object
 *      a = EC_POINT object to be inverted (it's used for the result as well)
 *      ctx = BN_CTX object (optional)
 *
 * Returns: 1 on success and 0 if an error occured
 */
int EC_POINT_invert(const (.EC_GROUP)* group, .EC_POINT* a, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

/**
 * Checks whether the point is the neutral element of the group
 *
 * Params:
 *      group = the underlying EC_GROUP object
 *      p = EC_POINT object
 *
 * Returns: 1 if the point is the neutral element and 0 otherwise
 */
int EC_POINT_is_at_infinity(const (.EC_GROUP)* group, const (.EC_POINT)* p);

/**
 * Checks whether the point is on the curve
 *
 * Params:
 *      group = underlying EC_GROUP object
 *      point = EC_POINT object to check
 *      ctx = BN_CTX object (optional)
 *
 * Returns: 1 if point if on the curve and 0 otherwise
 */
int EC_POINT_is_on_curve(const (.EC_GROUP)* group, const (.EC_POINT)* point, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

/**
 * Compares two EC_POINTs
 *
 * Params:
 *      group = underlying EC_GROUP object
 *      a = first EC_POINT object
 *      b = second EC_POINT object
 *      ctx = BN_CTX object (optional)
 *
 * Returns: 0 if both points are equal and a value != 0 otherwise
 */
int EC_POINT_cmp(const (.EC_GROUP)* group, const (.EC_POINT)* a, const (.EC_POINT)* b, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

int EC_POINT_make_affine(const (.EC_GROUP)* group, .EC_POINT* point, libressl_d.openssl.ossl_typ.BN_CTX* ctx);
int EC_POINTs_make_affine(const (.EC_GROUP)* group, size_t num, .EC_POINT** points, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

/**
 * Computes r = generator * n sum_{i=0}^num p[i] * m[i]
 *
 * Params:
 *      group = underlying EC_GROUP object
 *      r = EC_POINT object for the result
 *      n = BIGNUM with the multiplier for the group generator (optional)
 *      num = number futher summands
 *      p = array of size num of EC_POINT objects
 *      m = array of size num of BIGNUM objects
 *      ctx = BN_CTX object (optional)
 *
 * Returns: 1 on success and 0 if an error occured
 */
int EC_POINTs_mul(const (.EC_GROUP)* group, .EC_POINT* r, const (libressl_d.openssl.ossl_typ.BIGNUM)* n, size_t num, const (.EC_POINT)** p, const (libressl_d.openssl.ossl_typ.BIGNUM)** m, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

/**
 * Computes r = generator * n + q * m
 *
 * Params:
 *      group = underlying EC_GROUP object
 *      r = EC_POINT object for the result
 *      n = BIGNUM with the multiplier for the group generator (optional)
 *      q = EC_POINT object with the first factor of the second summand
 *      m = BIGNUM with the second factor of the second summand
 *      ctx = BN_CTX object (optional)
 *
 * Returns: 1 on success and 0 if an error occured
 */
int EC_POINT_mul(const (.EC_GROUP)* group, .EC_POINT* r, const (libressl_d.openssl.ossl_typ.BIGNUM)* n, const (.EC_POINT)* q, const (libressl_d.openssl.ossl_typ.BIGNUM)* m, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

/**
 * Stores multiples of generator for faster point multiplication
 *
 * Params:
 *      group = EC_GROUP object
 *      ctx = BN_CTX object (optional)
 *
 * Returns: 1 on success and 0 if an error occured
 */
int EC_GROUP_precompute_mult(.EC_GROUP* group, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

/**
 * Reports whether a precomputation has been done
 *
 * Params:
 *      group = EC_GROUP object
 *
 * Returns: 1 if a pre-computation has been done and 0 otherwise
 */
int EC_GROUP_have_precompute_mult(const (.EC_GROUP)* group);

/* *******************************************************************/
/*                       ASN1 stuff                                 */
/* *******************************************************************/

/*
 * EC_GROUP_get_basis_type() returns the NID of the basis type
 * used to represent the field elements
 */
int EC_GROUP_get_basis_type(const (.EC_GROUP)*);

version (OPENSSL_NO_EC2M) {
} else {
	int EC_GROUP_get_trinomial_basis(const (.EC_GROUP)*, uint* k);
	int EC_GROUP_get_pentanomial_basis(const (.EC_GROUP)*, uint* k1, uint* k2, uint* k3);
}

enum OPENSSL_EC_EXPLICIT_CURVE = 0x0000;
enum OPENSSL_EC_NAMED_CURVE = 0x0001;

struct ecpk_parameters_st;
alias ECPKPARAMETERS = .ecpk_parameters_st;

.EC_GROUP* d2i_ECPKParameters(.EC_GROUP**, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_ECPKParameters(const (.EC_GROUP)*, ubyte** out_);

//#define d2i_ECPKParameters_bio(bp, x) libressl_d.openssl.asn1.ASN1_d2i_bio_of(.EC_GROUP, null, .d2i_ECPKParameters, bp, x)
//#define i2d_ECPKParameters_bio(bp, x) libressl_d.openssl.asn1.ASN1_i2d_bio_of_const(.EC_GROUP, .i2d_ECPKParameters, bp, x)
//#define d2i_ECPKParameters_fp(fp, x) cast(.EC_GROUP*)(libressl_d.openssl.asn1.ASN1_d2i_fp(null, (char* (*) ()) .d2i_ECPKParameters, fp, cast(ubyte**)(x)))

pragma(inline, true)
int i2d_ECPKParameters_fp(libressl_d.compat.stdio.FILE* fp, ubyte* x)

	do
	{
		return libressl_d.openssl.asn1.ASN1_i2d_fp(&.i2d_ECPKParameters, fp, x);
	}

version (OPENSSL_NO_BIO) {
} else {
	int ECPKParameters_print(libressl_d.openssl.bio.BIO* bp, const (.EC_GROUP)* x, int off);
}

int ECPKParameters_print_fp(libressl_d.compat.stdio.FILE* fp, const (.EC_GROUP)* x, int off);

/* *******************************************************************/
/*                      EC_KEY functions                            */
/* *******************************************************************/

struct ec_key_st;
alias EC_KEY = .ec_key_st;
struct ec_key_method_st;
alias EC_KEY_METHOD = .ec_key_method_st;

/* some values for the encoding_flag */
enum EC_PKEY_NO_PARAMETERS = 0x0001;
enum EC_PKEY_NO_PUBKEY = 0x0002;

/* some values for the flags field */
enum EC_FLAG_NON_FIPS_ALLOW = 0x01;
enum EC_FLAG_FIPS_CHECKED = 0x02;
enum EC_FLAG_COFACTOR_ECDH = 0x1000;

/**
 * Creates a new EC_KEY object.
 *
 * Returns: EC_KEY object or null if an error occurred.
 */
.EC_KEY* EC_KEY_new();

int EC_KEY_get_flags(const (.EC_KEY)* key);

void EC_KEY_set_flags(.EC_KEY* key, int flags);

void EC_KEY_clear_flags(.EC_KEY* key, int flags);

/**
 * Creates a new EC_KEY object using a named curve as underlying EC_GROUP object.
 *
 * Params:
 *      nid = NID of the named curve.
 *
 * Returns: EC_KEY object or null if an error occurred.
 */
.EC_KEY* EC_KEY_new_by_curve_name(int nid);

/**
 * Frees a EC_KEY object.
 *
 * Params:
 *      key = EC_KEY object to be freed.
 */
void EC_KEY_free(.EC_KEY* key);

/**
 * Copies a EC_KEY object.
 *
 * Params:
 *      dst = destination EC_KEY object
 *      src = src EC_KEY object
 *
 * Returns: dst or null if an error occurred.
 */
.EC_KEY* EC_KEY_copy(.EC_KEY* dst, const (.EC_KEY)* src);

/**
 * Creates a new EC_KEY object and copies the content from src to it.
 *
 * Params:
 *      src = the source EC_KEY object
 *
 * Returns: newly created EC_KEY object or null if an error occurred.
 */
.EC_KEY* EC_KEY_dup(const (.EC_KEY)* src);

/**
 * Increases the internal reference count of a EC_KEY object.
 *
 * Params:
 *      key = EC_KEY object
 *
 * Returns: 1 on success and 0 if an error occurred.
 */
int EC_KEY_up_ref(.EC_KEY* key);

/**
 * Returns the EC_GROUP object of a EC_KEY object
 *
 * Params:
 *      key = EC_KEY object
 *
 * Returns: the EC_GROUP object (possibly null).
 */
const (.EC_GROUP)* EC_KEY_get0_group(const (.EC_KEY)* key);

/**
 * Sets the EC_GROUP of a EC_KEY object.
 *
 * Params:
 *      key = EC_KEY object
 *      group = EC_GROUP to use in the EC_KEY object (note: the EC_KEY object will use an own copy of the EC_GROUP).
 *
 * Returns: 1 on success and 0 if an error occurred.
 */
int EC_KEY_set_group(.EC_KEY* key, const (.EC_GROUP)* group);

/**
 * Returns the private key of a EC_KEY object.
 *
 * Params:
 *      key = EC_KEY object
 *
 * Returns: a BIGNUM with the private key (possibly null).
 */
const (libressl_d.openssl.ossl_typ.BIGNUM)* EC_KEY_get0_private_key(const (.EC_KEY)* key);

/**
 * Sets the private key of a EC_KEY object.
 *
 * Params:
 *      key = EC_KEY object
 *      prv = BIGNUM with the private key (note: the EC_KEY object will use an own copy of the BIGNUM).
 *
 * Returns: 1 on success and 0 if an error occurred.
 */
int EC_KEY_set_private_key(.EC_KEY* key, const (libressl_d.openssl.ossl_typ.BIGNUM)* prv);

/**
 * Returns the public key of a EC_KEY object.
 *
 * Params:
 *      key = the EC_KEY object
 *
 * Returns: a EC_POINT object with the public key (possibly null)
 */
const (.EC_POINT)* EC_KEY_get0_public_key(const (.EC_KEY)* key);

/**
 * Sets the public key of a EC_KEY object.
 *
 * Params:
 *      key = EC_KEY object
 *      pub = EC_POINT object with the public key (note: the EC_KEY object will use an own copy of the EC_POINT object).
 *
 * Returns: 1 on success and 0 if an error occurred.
 */
int EC_KEY_set_public_key(.EC_KEY* key, const (.EC_POINT)* pub);

uint EC_KEY_get_enc_flags(const (.EC_KEY)* key);
void EC_KEY_set_enc_flags(.EC_KEY* eckey, uint flags);
.point_conversion_form_t EC_KEY_get_conv_form(const (.EC_KEY)* key);
void EC_KEY_set_conv_form(.EC_KEY* eckey, .point_conversion_form_t cform);
/* functions to set/get method specific data  */
void* EC_KEY_get_key_method_data(.EC_KEY* key, void* function(void*) dup_func, void function(void*) free_func, void function(void*) clear_free_func);

/**
 * Sets the key method data of an EC_KEY object, if none has yet been set.
 *
 * Params:
 *      key = EC_KEY object
 *      data = opaque data to install.
 *      dup_func = a function that duplicates |data|.
 *      free_func = a function that frees |data|.
 *      clear_free_func = a function that wipes and frees |data|.
 *
 * Returns: the previously set data pointer, or null if |data| was inserted.
 */
void* EC_KEY_insert_key_method_data(.EC_KEY* key, void* data, void* function(void*) dup_func, void function(void*) free_func, void function(void*) clear_free_func);

/* wrapper functions for the underlying EC_GROUP object */
void EC_KEY_set_asn1_flag(.EC_KEY* eckey, int asn1_flag);

/**
 * Creates a table of pre-computed multiples of the generator to accelerate further EC_KEY operations.
 *
 * Params:
 *      key = EC_KEY object
 *      ctx = BN_CTX object (optional)
 *
 * Returns: 1 on success and 0 if an error occurred.
 */
int EC_KEY_precompute_mult(.EC_KEY* key, libressl_d.openssl.ossl_typ.BN_CTX* ctx);

/**
 * Creates a new ec private (and optional a new public) key.
 *
 * Params:
 *      key = EC_KEY object
 *
 * Returns: 1 on success and 0 if an error occurred.
 */
int EC_KEY_generate_key(.EC_KEY* key);

/**
 * Verifies that a private and/or public key is valid.
 *
 * Params:
 *      key = the EC_KEY object
 *
 * Returns: 1 on success and 0 otherwise.
 */
int EC_KEY_check_key(const (.EC_KEY)* key);

/**
 * Sets a public key from affine coordindates performing neccessary NIST PKV tests.
 *
 * Params:
 *      key = the EC_KEY object
 *      x = public key x coordinate
 *      y = public key y coordinate
 *
 * Returns: 1 on success and 0 otherwise.
 */
int EC_KEY_set_public_key_affine_coordinates(.EC_KEY* key, libressl_d.openssl.ossl_typ.BIGNUM* x, libressl_d.openssl.ossl_typ.BIGNUM* y);

/* *******************************************************************/
/*        de- and encoding functions for SEC1 ECPrivateKey          */
/* *******************************************************************/

/**
 * Decodes a private key from a memory buffer.
 *
 * Params:
 *      key = a pointer to a EC_KEY object which should be used (or null)
 *      in_ = pointer to memory with the DER encoded private key
 *      len = length of the DER encoded private key
 *
 * Returns: the decoded private key or null if an error occurred.
 */
.EC_KEY* d2i_ECPrivateKey(.EC_KEY** key, const (ubyte)** in_, core.stdc.config.c_long len);

/**
 * Encodes a private key object and stores the result in a buffer.
 *
 * Params:
 *      key = the EC_KEY object to encode
 *      out_ = the buffer for the result (if null the function returns number of bytes needed).
 *
 * Returns: 1 on success and 0 if an error occurred.
 */
int i2d_ECPrivateKey(.EC_KEY* key, ubyte** out_);

/* *******************************************************************/
/*        de- and encoding functions for EC parameters              */
/* *******************************************************************/

/**
 * Decodes ec parameter from a memory buffer.
 *
 * Params:
 *      key = a pointer to a EC_KEY object which should be used (or null)
 *      in_ = pointer to memory with the DER encoded ec parameters
 *      len = length of the DER encoded ec parameters
 *
 * Returns: a EC_KEY object with the decoded parameters or null if an error occurred.
 */
.EC_KEY* d2i_ECParameters(.EC_KEY** key, const (ubyte)** in_, core.stdc.config.c_long len);

/**
 * Encodes ec parameter and stores the result in a buffer.
 *
 * Params:
 *      key = the EC_KEY object with ec paramters to encode
 *      out_ = the buffer for the result (if null the function returns number of bytes needed).
 *
 * Returns: 1 on success and 0 if an error occurred.
 */
int i2d_ECParameters(.EC_KEY* key, ubyte** out_);

/* *******************************************************************/
/*         de- and encoding functions for EC public key             */
/*         (octet string, not DER -- hence 'o2i' and 'i2o')         */
/* *******************************************************************/

/**
 * Decodes a ec public key from a octet string.
 *
 * Params:
 *      key = a pointer to a EC_KEY object which should be used
 *      in_ = memory buffer with the encoded public key
 *      len = length of the encoded public key
 *
 * Returns: EC_KEY object with decoded public key or null if an error occurred.
 */
.EC_KEY* o2i_ECPublicKey(.EC_KEY** key, const (ubyte)** in_, core.stdc.config.c_long len);

/**
 * Encodes a ec public key in an octet string.
 *
 * Params:
 *      key = the EC_KEY object with the public key
 *      out_ = the buffer for the result (if null the function returns number of bytes needed).
 *
 * Returns: 1 on success and 0 if an error occurred
 */
int i2o_ECPublicKey(const (.EC_KEY)* key, ubyte** out_);

version (OPENSSL_NO_BIO) {
} else {
	/**
	 * Prints out the ec parameters on human readable form.
	 *
	 * Params:
	 *      bp = BIO object to which the information is printed
	 *      key = EC_KEY object
	 *
	 * Returns: 1 on success and 0 if an error occurred
	 */
	int ECParameters_print(libressl_d.openssl.bio.BIO* bp, const (.EC_KEY)* key);

	/**
	 * Prints out the contents of a EC_KEY object
	 *
	 * Params:
	 *      bp = BIO object to which the information is printed
	 *      key = EC_KEY object
	 *      off = line offset
	 *
	 * Returns: 1 on success and 0 if an error occurred
	 */
	int EC_KEY_print(libressl_d.openssl.bio.BIO* bp, const (.EC_KEY)* key, int off);
}

/**
 * Prints out the ec parameters on human readable form.
 *
 * Params:
 *      fp = file descriptor to which the information is printed
 *      key = EC_KEY object
 *
 * Returns: 1 on success and 0 if an error occurred
 */
int ECParameters_print_fp(libressl_d.compat.stdio.FILE* fp, const (.EC_KEY)* key);

/**
 * Prints out the contents of a EC_KEY object
 *
 * Params:
 *      fp = file descriptor to which the information is printed
 *      key = EC_KEY object
 *      off = line offset
 *
 * Returns: 1 on success and 0 if an error occurred
 */
int EC_KEY_print_fp(libressl_d.compat.stdio.FILE* fp, const (.EC_KEY)* key, int off);

pragma(inline, true)
int EC_KEY_get_ex_new_index(core.stdc.config.c_long l, void* p, libressl_d.openssl.ossl_typ.CRYPTO_EX_new newf, libressl_d.openssl.ossl_typ.CRYPTO_EX_dup dupf, libressl_d.openssl.ossl_typ.CRYPTO_EX_free freef)

	do
	{
		return libressl_d.openssl.crypto.CRYPTO_get_ex_new_index(libressl_d.openssl.crypto.CRYPTO_EX_INDEX_EC_KEY, l, p, newf, dupf, freef);
	}

int EC_KEY_set_ex_data(.EC_KEY* key, int idx, void* arg);
void* EC_KEY_get_ex_data(const (.EC_KEY)* key, int idx);

const (.EC_KEY_METHOD)* EC_KEY_OpenSSL();
const (.EC_KEY_METHOD)* EC_KEY_get_default_method();
void EC_KEY_set_default_method(const (.EC_KEY_METHOD)* meth);
const (.EC_KEY_METHOD)* EC_KEY_get_method(const (.EC_KEY)* key);
int EC_KEY_set_method(.EC_KEY* key, const (.EC_KEY_METHOD)* meth);
.EC_KEY* EC_KEY_new_method(libressl_d.openssl.ossl_typ.ENGINE* engine);
.EC_KEY_METHOD* EC_KEY_METHOD_new(const (.EC_KEY_METHOD)* meth);
void EC_KEY_METHOD_free(.EC_KEY_METHOD* meth);
void EC_KEY_METHOD_set_init(.EC_KEY_METHOD* meth, int function(.EC_KEY* key) init, void function(.EC_KEY* key) finish, int function(.EC_KEY* dest, const (.EC_KEY)* src) copy, int function(.EC_KEY* key, const (.EC_GROUP)* grp) set_group, int function(.EC_KEY* key, const (libressl_d.openssl.ossl_typ.BIGNUM)* priv_key) set_private, int function(.EC_KEY* key, const (.EC_POINT)* pub_key) set_public);
void EC_KEY_METHOD_set_keygen(.EC_KEY_METHOD* meth, int function(.EC_KEY* key) keygen);
void EC_KEY_METHOD_set_compute_key(.EC_KEY_METHOD* meth, int function(void* out_, size_t outlen, const (.EC_POINT)* pub_key, .EC_KEY* ecdh, void* function(const (void)* in_, size_t inlen, void* out_, size_t* outlen) KDF) ckey);
void EC_KEY_METHOD_get_init(const (.EC_KEY_METHOD)* meth, int function(.EC_KEY* key)* pinit, void function(.EC_KEY* key)* pfinish, int function(.EC_KEY* dest, const (.EC_KEY)* src)* pcopy, int function(.EC_KEY* key, const (.EC_GROUP)* grp)* pset_group, int function(.EC_KEY* key, const (libressl_d.openssl.ossl_typ.BIGNUM)* priv_key)* pset_private, int function(.EC_KEY* key, const (.EC_POINT)* pub_key)* pset_public);
void EC_KEY_METHOD_get_keygen(const (.EC_KEY_METHOD)* meth, int function(.EC_KEY* key)* pkeygen);
void EC_KEY_METHOD_get_compute_key(const (.EC_KEY_METHOD)* meth, int function(void* out_, size_t outlen, const (.EC_POINT)* pub_key, .EC_KEY* ecdh, void* function(const (void)* in_, size_t inlen, void* out_, size_t* outlen) KDF)* pck);

.EC_KEY* ECParameters_dup(.EC_KEY* key);

//#if !defined(__cplusplus)
	//#if defined(__SUNPRO_C)
		//#if __SUNPRO_C >= 0x0520
			//#pragma error_messages(default, E_ARRAY_OF_INCOMPLETE_NONAME, E_ARRAY_OF_INCOMPLETE)
		//#endif
	//#endif
//#endif

pragma(inline, true)
int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int nid)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_EC, libressl_d.openssl.evp.EVP_PKEY_OP_PARAMGEN | libressl_d.openssl.evp.EVP_PKEY_OP_KEYGEN, .EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, null);
	}

pragma(inline, true)
int EVP_PKEY_CTX_set_ec_param_enc(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int flag)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_EC, libressl_d.openssl.evp.EVP_PKEY_OP_PARAMGEN | libressl_d.openssl.evp.EVP_PKEY_OP_KEYGEN, .EVP_PKEY_CTRL_EC_PARAM_ENC, flag, null);
	}

pragma(inline, true)
int EVP_PKEY_CTX_set_ecdh_cofactor_mode(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int flag)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_EC, libressl_d.openssl.evp.EVP_PKEY_OP_DERIVE, .EVP_PKEY_CTRL_EC_ECDH_COFACTOR, flag, null);
	}

pragma(inline, true)
int EVP_PKEY_CTX_get_ecdh_cofactor_mode(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_EC, libressl_d.openssl.evp.EVP_PKEY_OP_DERIVE, .EVP_PKEY_CTRL_EC_ECDH_COFACTOR, -2, null);
	}

pragma(inline, true)
int EVP_PKEY_CTX_set_ecdh_kdf_type(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int kdf)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_EC, libressl_d.openssl.evp.EVP_PKEY_OP_DERIVE, .EVP_PKEY_CTRL_EC_KDF_TYPE, kdf, null);
	}

pragma(inline, true)
int EVP_PKEY_CTX_get_ecdh_kdf_type(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_EC, libressl_d.openssl.evp.EVP_PKEY_OP_DERIVE, .EVP_PKEY_CTRL_EC_KDF_TYPE, -2, null);
	}

pragma(inline, true)
int EVP_PKEY_CTX_set_ecdh_kdf_md(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* md)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_EC, libressl_d.openssl.evp.EVP_PKEY_OP_DERIVE, .EVP_PKEY_CTRL_EC_KDF_MD, 0, md);
	}

pragma(inline, true)
int EVP_PKEY_CTX_get_ecdh_kdf_md(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* pmd)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_EC, libressl_d.openssl.evp.EVP_PKEY_OP_DERIVE, .EVP_PKEY_CTRL_GET_EC_KDF_MD, 0, pmd);
	}

pragma(inline, true)
int EVP_PKEY_CTX_set_ecdh_kdf_outlen(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, int len)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_EC, libressl_d.openssl.evp.EVP_PKEY_OP_DERIVE, .EVP_PKEY_CTRL_EC_KDF_OUTLEN, len, null);
	}

pragma(inline, true)
int EVP_PKEY_CTX_get_ecdh_kdf_outlen(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* plen)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_EC, libressl_d.openssl.evp.EVP_PKEY_OP_DERIVE, .EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN, 0, plen);
	}

pragma(inline, true)
int EVP_PKEY_CTX_set0_ecdh_kdf_ukm(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* p, int plen)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_EC, libressl_d.openssl.evp.EVP_PKEY_OP_DERIVE, .EVP_PKEY_CTRL_EC_KDF_UKM, plen, p);
	}

pragma(inline, true)
int EVP_PKEY_CTX_get0_ecdh_kdf_ukm(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* p)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, libressl_d.openssl.evp.EVP_PKEY_EC, libressl_d.openssl.evp.EVP_PKEY_OP_DERIVE, .EVP_PKEY_CTRL_GET_EC_KDF_UKM, 0, p);
	}

/* SM2 will skip the operation check so no need to pass operation here */
pragma(inline, true)
int EVP_PKEY_CTX_set1_id(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* id, int id_len)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, -1, -1, .EVP_PKEY_CTRL_SET1_ID, id_len, id);
	}

pragma(inline, true)
int EVP_PKEY_CTX_get1_id(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* id)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, -1, -1, .EVP_PKEY_CTRL_GET1_ID, 0, id);
	}

pragma(inline, true)
int EVP_PKEY_CTX_get1_id_len(libressl_d.openssl.ossl_typ.EVP_PKEY_CTX* ctx, void* id_len)

	do
	{
		return libressl_d.openssl.evp.EVP_PKEY_CTX_ctrl(ctx, -1, -1, .EVP_PKEY_CTRL_GET1_ID_LEN, 0, id_len);
	}

enum EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 1;
enum EVP_PKEY_CTRL_EC_PARAM_ENC = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 2;
enum EVP_PKEY_CTRL_EC_ECDH_COFACTOR = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 3;
enum EVP_PKEY_CTRL_EC_KDF_TYPE = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 4;
enum EVP_PKEY_CTRL_EC_KDF_MD = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 5;
enum EVP_PKEY_CTRL_GET_EC_KDF_MD = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 6;
enum EVP_PKEY_CTRL_EC_KDF_OUTLEN = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 7;
enum EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 8;
enum EVP_PKEY_CTRL_EC_KDF_UKM = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 9;
enum EVP_PKEY_CTRL_GET_EC_KDF_UKM = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 10;
enum EVP_PKEY_CTRL_SET1_ID = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 11;
enum EVP_PKEY_CTRL_GET1_ID = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 12;
enum EVP_PKEY_CTRL_GET1_ID_LEN = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 13;

/* KDF types */
enum EVP_PKEY_ECDH_KDF_NONE = 1;
enum EVP_PKEY_ECDH_KDF_X9_63 = 2;

/* BEGIN ERROR CODES */
/**
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_EC_strings();

/* Error codes for the EC functions. */

/* Function codes. */
enum EC_F_BN_TO_FELEM = 224;
enum EC_F_COMPUTE_WNAF = 143;
enum EC_F_D2I_ECPARAMETERS = 144;
enum EC_F_D2I_ECPKPARAMETERS = 145;
enum EC_F_D2I_ECPRIVATEKEY = 146;
enum EC_F_DO_EC_KEY_PRINT = 221;
enum EC_F_ECKEY_PARAM2TYPE = 223;
enum EC_F_ECKEY_PARAM_DECODE = 212;
enum EC_F_ECKEY_PRIV_DECODE = 213;
enum EC_F_ECKEY_PRIV_ENCODE = 214;
enum EC_F_ECKEY_PUB_DECODE = 215;
enum EC_F_ECKEY_PUB_ENCODE = 216;
enum EC_F_ECKEY_TYPE2PARAM = 220;
enum EC_F_ECPARAMETERS_PRINT = 147;
enum EC_F_ECPARAMETERS_PRINT_FP = 148;
enum EC_F_ECPKPARAMETERS_PRINT = 149;
enum EC_F_ECPKPARAMETERS_PRINT_FP = 150;
enum EC_F_ECP_NIST_MOD_192 = 203;
enum EC_F_ECP_NIST_MOD_224 = 204;
enum EC_F_ECP_NIST_MOD_256 = 205;
enum EC_F_ECP_NIST_MOD_521 = 206;
enum EC_F_ECP_NISTZ256_GET_AFFINE = 240;
enum EC_F_ECP_NISTZ256_MULT_PRECOMPUTE = 243;
enum EC_F_ECP_NISTZ256_POINTS_MUL = 241;
enum EC_F_ECP_NISTZ256_PRE_COMP_NEW = 244;
enum EC_F_ECP_NISTZ256_SET_WORDS = 245;
enum EC_F_ECP_NISTZ256_WINDOWED_MUL = 242;
enum EC_F_EC_ASN1_GROUP2CURVE = 153;
enum EC_F_EC_ASN1_GROUP2FIELDID = 154;
enum EC_F_EC_ASN1_GROUP2PARAMETERS = 155;
enum EC_F_EC_ASN1_GROUP2PKPARAMETERS = 156;
enum EC_F_EC_ASN1_PARAMETERS2GROUP = 157;
enum EC_F_EC_ASN1_PKPARAMETERS2GROUP = 158;
enum EC_F_EC_EX_DATA_SET_DATA = 211;
enum EC_F_EC_GF2M_MONTGOMERY_POINT_MULTIPLY = 208;
enum EC_F_EC_GF2M_SIMPLE_GROUP_CHECK_DISCRIMINANT = 159;
enum EC_F_EC_GF2M_SIMPLE_GROUP_SET_CURVE = 195;
enum EC_F_EC_GF2M_SIMPLE_OCT2POINT = 160;
enum EC_F_EC_GF2M_SIMPLE_POINT2OCT = 161;
enum EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES = 162;
enum EC_F_EC_GF2M_SIMPLE_POINT_SET_AFFINE_COORDINATES = 163;
enum EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES = 164;
enum EC_F_EC_GFP_MONT_FIELD_DECODE = 133;
enum EC_F_EC_GFP_MONT_FIELD_ENCODE = 134;
enum EC_F_EC_GFP_MONT_FIELD_MUL = 131;
enum EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE = 209;
enum EC_F_EC_GFP_MONT_FIELD_SQR = 132;
enum EC_F_EC_GFP_MONT_GROUP_SET_CURVE = 189;
enum EC_F_EC_GFP_MONT_GROUP_SET_CURVE_GFP = 135;
enum EC_F_EC_GFP_NISTP224_GROUP_SET_CURVE = 225;
enum EC_F_EC_GFP_NISTP224_POINTS_MUL = 228;
enum EC_F_EC_GFP_NISTP224_POINT_GET_AFFINE_COORDINATES = 226;
enum EC_F_EC_GFP_NISTP256_GROUP_SET_CURVE = 230;
enum EC_F_EC_GFP_NISTP256_POINTS_MUL = 231;
enum EC_F_EC_GFP_NISTP256_POINT_GET_AFFINE_COORDINATES = 232;
enum EC_F_EC_GFP_NISTP521_GROUP_SET_CURVE = 233;
enum EC_F_EC_GFP_NISTP521_POINTS_MUL = 234;
enum EC_F_EC_GFP_NISTP521_POINT_GET_AFFINE_COORDINATES = 235;
enum EC_F_EC_GFP_NIST_FIELD_MUL = 200;
enum EC_F_EC_GFP_NIST_FIELD_SQR = 201;
enum EC_F_EC_GFP_NIST_GROUP_SET_CURVE = 202;
enum EC_F_EC_GFP_SIMPLE_GROUP_CHECK_DISCRIMINANT = 165;
enum EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE = 166;
enum EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE_GFP = 100;
enum EC_F_EC_GFP_SIMPLE_GROUP_SET_GENERATOR = 101;
enum EC_F_EC_GFP_SIMPLE_MAKE_AFFINE = 102;
enum EC_F_EC_GFP_SIMPLE_OCT2POINT = 103;
enum EC_F_EC_GFP_SIMPLE_POINT2OCT = 104;
enum EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE = 137;
enum EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES = 167;
enum EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES_GFP = 105;
enum EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES = 168;
enum EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES_GFP = 128;
enum EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES = 169;
enum EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES_GFP = 129;
enum EC_F_EC_GROUP_CHECK = 170;
enum EC_F_EC_GROUP_CHECK_DISCRIMINANT = 171;
enum EC_F_EC_GROUP_COPY = 106;
enum EC_F_EC_GROUP_GET0_GENERATOR = 139;
enum EC_F_EC_GROUP_GET_COFACTOR = 140;
enum EC_F_EC_GROUP_GET_CURVE_GF2M = 172;
enum EC_F_EC_GROUP_GET_CURVE_GFP = 130;
enum EC_F_EC_GROUP_GET_DEGREE = 173;
enum EC_F_EC_GROUP_GET_ORDER = 141;
enum EC_F_EC_GROUP_GET_PENTANOMIAL_BASIS = 193;
enum EC_F_EC_GROUP_GET_TRINOMIAL_BASIS = 194;
enum EC_F_EC_GROUP_NEW = 108;
enum EC_F_EC_GROUP_NEW_BY_CURVE_NAME = 174;
enum EC_F_EC_GROUP_NEW_FROM_DATA = 175;
enum EC_F_EC_GROUP_PRECOMPUTE_MULT = 142;
enum EC_F_EC_GROUP_SET_CURVE_GF2M = 176;
enum EC_F_EC_GROUP_SET_CURVE_GFP = 109;
enum EC_F_EC_GROUP_SET_EXTRA_DATA = 110;
enum EC_F_EC_GROUP_SET_GENERATOR = 111;
enum EC_F_EC_KEY_CHECK_KEY = 177;
enum EC_F_EC_KEY_COPY = 178;
enum EC_F_EC_KEY_GENERATE_KEY = 179;
enum EC_F_EC_KEY_NEW = 182;
enum EC_F_EC_KEY_PRINT = 180;
enum EC_F_EC_KEY_PRINT_FP = 181;
enum EC_F_EC_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES = 229;
enum EC_F_EC_POINTS_MAKE_AFFINE = 136;
enum EC_F_EC_POINT_ADD = 112;
enum EC_F_EC_POINT_CMP = 113;
enum EC_F_EC_POINT_COPY = 114;
enum EC_F_EC_POINT_DBL = 115;
enum EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M = 183;
enum EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP = 116;
enum EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP = 117;
enum EC_F_EC_POINT_INVERT = 210;
enum EC_F_EC_POINT_IS_AT_INFINITY = 118;
enum EC_F_EC_POINT_IS_ON_CURVE = 119;
enum EC_F_EC_POINT_MAKE_AFFINE = 120;
enum EC_F_EC_POINT_MUL = 184;
enum EC_F_EC_POINT_NEW = 121;
enum EC_F_EC_POINT_OCT2POINT = 122;
enum EC_F_EC_POINT_POINT2OCT = 123;
enum EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M = 185;
enum EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP = 124;
enum EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M = 186;
enum EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP = 125;
enum EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP = 126;
enum EC_F_EC_POINT_SET_TO_INFINITY = 127;
enum EC_F_EC_PRE_COMP_DUP = 207;
enum EC_F_EC_PRE_COMP_NEW = 196;
enum EC_F_EC_WNAF_MUL = 187;
enum EC_F_EC_WNAF_PRECOMPUTE_MULT = 188;
enum EC_F_I2D_ECPARAMETERS = 190;
enum EC_F_I2D_ECPKPARAMETERS = 191;
enum EC_F_I2D_ECPRIVATEKEY = 192;
enum EC_F_I2O_ECPUBLICKEY = 151;
enum EC_F_NISTP224_PRE_COMP_NEW = 227;
enum EC_F_NISTP256_PRE_COMP_NEW = 236;
enum EC_F_NISTP521_PRE_COMP_NEW = 237;
enum EC_F_O2I_ECPUBLICKEY = 152;
enum EC_F_OLD_EC_PRIV_DECODE = 222;
enum EC_F_PKEY_EC_CTRL = 197;
enum EC_F_PKEY_EC_CTRL_STR = 198;
enum EC_F_PKEY_EC_DERIVE = 217;
enum EC_F_PKEY_EC_KEYGEN = 199;
enum EC_F_PKEY_EC_PARAMGEN = 219;
enum EC_F_PKEY_EC_SIGN = 218;

/* Reason codes. */
enum EC_R_ASN1_ERROR = 115;
enum EC_R_ASN1_UNKNOWN_FIELD = 116;
enum EC_R_BIGNUM_OUT_OF_RANGE = 144;
enum EC_R_BUFFER_TOO_SMALL = 100;
enum EC_R_COORDINATES_OUT_OF_RANGE = 146;
enum EC_R_D2I_ECPKPARAMETERS_FAILURE = 117;
enum EC_R_DECODE_ERROR = 142;
enum EC_R_DISCRIMINANT_IS_ZERO = 118;
enum EC_R_EC_GROUP_NEW_BY_NAME_FAILURE = 119;
enum EC_R_FIELD_TOO_LARGE = 143;
enum EC_R_GF2M_NOT_SUPPORTED = 147;
enum EC_R_GROUP2PKPARAMETERS_FAILURE = 120;
enum EC_R_I2D_ECPKPARAMETERS_FAILURE = 121;
enum EC_R_INCOMPATIBLE_OBJECTS = 101;
enum EC_R_INVALID_ARGUMENT = 112;
enum EC_R_INVALID_COMPRESSED_POINT = 110;
enum EC_R_INVALID_COMPRESSION_BIT = 109;
enum EC_R_INVALID_CURVE = 141;
enum EC_R_INVALID_DIGEST = 151;
enum EC_R_INVALID_DIGEST_TYPE = 138;
enum EC_R_INVALID_ENCODING = 102;
enum EC_R_INVALID_FIELD = 103;
enum EC_R_INVALID_FORM = 104;
enum EC_R_INVALID_GROUP_ORDER = 122;
enum EC_R_INVALID_PENTANOMIAL_BASIS = 132;
enum EC_R_INVALID_PRIVATE_KEY = 123;
enum EC_R_INVALID_TRINOMIAL_BASIS = 137;
enum EC_R_KDF_PARAMETER_ERROR = 148;
enum EC_R_KEYS_NOT_SET = 140;
enum EC_R_MISSING_PARAMETERS = 124;
enum EC_R_MISSING_PRIVATE_KEY = 125;
enum EC_R_NOT_A_NIST_PRIME = 135;
enum EC_R_NOT_A_SUPPORTED_NIST_PRIME = 136;
enum EC_R_NOT_IMPLEMENTED = 126;
enum EC_R_NOT_INITIALIZED = 111;
enum EC_R_NO_FIELD_MOD = 133;
enum EC_R_NO_PARAMETERS_SET = 139;
enum EC_R_PASSED_NULL_PARAMETER = 134;
enum EC_R_PEER_KEY_ERROR = 149;
enum EC_R_PKPARAMETERS2GROUP_FAILURE = 127;
enum EC_R_POINT_AT_INFINITY = 106;
enum EC_R_POINT_IS_NOT_ON_CURVE = 107;
enum EC_R_SHARED_INFO_ERROR = 150;
enum EC_R_SLOT_FULL = 108;
enum EC_R_UNDEFINED_GENERATOR = 113;
enum EC_R_UNDEFINED_ORDER = 128;
enum EC_R_UNKNOWN_COFACTOR = 164;
enum EC_R_UNKNOWN_GROUP = 129;
enum EC_R_UNKNOWN_ORDER = 114;
enum EC_R_UNSUPPORTED_FIELD = 131;
enum EC_R_WRONG_CURVE_PARAMETERS = 145;
enum EC_R_WRONG_ORDER = 130;
