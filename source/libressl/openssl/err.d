/* $OpenBSD: err.h,v 1.28 2022/08/29 06:49:24 jsing Exp $ */
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
module libressl.openssl.err;


private static import core.stdc.config;
private static import core.stdc.stdarg;
private static import libressl.openssl.crypto;
public import core.stdc.errno;
public import libressl.compat.stdio;
public import libressl.compat.stdlib;
public import libressl.openssl.opensslconf;
public import libressl.openssl.ossl_typ;

version (OPENSSL_NO_BIO) {
} else {
	public import libressl.openssl.bio;
}

version (OPENSSL_NO_LHASH) {
} else {
	public import libressl.openssl.lhash;
}

extern (C):
nothrow @nogc:

version (OPENSSL_NO_ERR) {
	pragma(inline, true)
	void ERR_PUT_error(int a, int b, int c, const (char)* d, int e)

		do
		{
			.ERR_put_error(a, b, c, null, 0);
		}
} else {
	pragma(inline, true)
	void ERR_PUT_error(int a, int b, int c, const (char)* d, int e)

		do
		{
			.ERR_put_error(a, b, c, d, e);
		}
}

enum ERR_TXT_MALLOCED = 0x01;
enum ERR_TXT_STRING = 0x02;

enum ERR_FLAG_MARK = 0x01;

enum ERR_NUM_ERRORS = 16;

struct err_state_st
{
	libressl.openssl.crypto.CRYPTO_THREADID tid;
	int[.ERR_NUM_ERRORS] err_flags;
	core.stdc.config.c_ulong[.ERR_NUM_ERRORS] err_buffer;
	char*[.ERR_NUM_ERRORS] err_data;
	int[.ERR_NUM_ERRORS] err_data_flags;
	const (char)*[.ERR_NUM_ERRORS] err_file;
	int[.ERR_NUM_ERRORS] err_line;
	int top;
	int bottom;
}

alias ERR_STATE = .err_state_st;

/* library */
enum ERR_LIB_NONE = 1;
enum ERR_LIB_SYS = 2;
enum ERR_LIB_BN = 3;
enum ERR_LIB_RSA = 4;
enum ERR_LIB_DH = 5;
enum ERR_LIB_EVP = 6;
enum ERR_LIB_BUF = 7;
enum ERR_LIB_OBJ = 8;
enum ERR_LIB_PEM = 9;
enum ERR_LIB_DSA = 10;
enum ERR_LIB_X509 = 11;
/* enum ERR_LIB_METH = 12; */
enum ERR_LIB_ASN1 = 13;
enum ERR_LIB_CONF = 14;
enum ERR_LIB_CRYPTO = 15;
enum ERR_LIB_EC = 16;
enum ERR_LIB_SSL = 20;
/* enum ERR_LIB_SSL23 = 21; */
/* enum ERR_LIB_SSL2 = 22; */
/* enum ERR_LIB_SSL3 = 23; */
/* enum ERR_LIB_RSAREF = 30; */
/* enum ERR_LIB_PROXY = 31; */
enum ERR_LIB_BIO = 32;
enum ERR_LIB_PKCS7 = 33;
enum ERR_LIB_X509V3 = 34;
enum ERR_LIB_PKCS12 = 35;
enum ERR_LIB_RAND = 36;
enum ERR_LIB_DSO = 37;
enum ERR_LIB_ENGINE = 38;
enum ERR_LIB_OCSP = 39;
enum ERR_LIB_UI = 40;
enum ERR_LIB_COMP = 41;
enum ERR_LIB_ECDSA = 42;
enum ERR_LIB_ECDH = 43;
enum ERR_LIB_STORE = 44;
enum ERR_LIB_FIPS = 45;
enum ERR_LIB_CMS = 46;
enum ERR_LIB_TS = 47;
enum ERR_LIB_HMAC = 48;
enum ERR_LIB_JPAKE = 49;
enum ERR_LIB_GOST = 50;
enum ERR_LIB_CT = 51;
enum ERR_LIB_KDF = 52;

enum ERR_LIB_USER = 128;

version (LIBRESSL_INTERNAL) {
} else {
	template SYSerr(string f, string r)
	{
		enum SYSerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_SYS, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template BNerr(string f, string r)
	{
		enum BNerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_BN, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template RSAerr(string f, string r)
	{
		enum RSAerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_RSA, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template DHerr(string f, string r)
	{
		enum DHerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_DH, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template EVPerr(string f, string r)
	{
		enum EVPerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_EVP, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template BUFerr(string f, string r)
	{
		enum BUFerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_BUF, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template OBJerr(string f, string r)
	{
		enum OBJerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_OBJ, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template PEMerr(string f, string r)
	{
		enum PEMerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_PEM, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template DSAerr(string f, string r)
	{
		enum DSAerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_DSA, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template X509err(string f, string r)
	{
		enum X509err = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_X509, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template ASN1err(string f, string r)
	{
		enum ASN1err = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_ASN1, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template CONFerr(string f, string r)
	{
		enum CONFerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_CONF, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template CRYPTOerr(string f, string r)
	{
		enum CRYPTOerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_CRYPTO, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template ECerr(string f, string r)
	{
		enum ECerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_EC, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template BIOerr(string f, string r)
	{
		enum BIOerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_BIO, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template PKCS7err(string f, string r)
	{
		enum PKCS7err = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_PKCS7, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template X509V3err(string f, string r)
	{
		enum X509V3err = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_X509V3, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template PKCS12err(string f, string r)
	{
		enum PKCS12err = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_PKCS12, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template RANDerr(string f, string r)
	{
		enum RANDerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_RAND, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template DSOerr(string f, string r)
	{
		enum DSOerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_DSO, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template ENGINEerr(string f, string r)
	{
		enum ENGINEerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_ENGINE, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template OCSPerr(string f, string r)
	{
		enum OCSPerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_OCSP, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template UIerr(string f, string r)
	{
		enum UIerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_UI, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template COMPerr(string f, string r)
	{
		enum COMPerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_COMP, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template ECDSAerr(string f, string r)
	{
		enum ECDSAerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_ECDSA, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template ECDHerr(string f, string r)
	{
		enum ECDHerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_ECDH, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template STOREerr(string f, string r)
	{
		enum STOREerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_STORE, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template FIPSerr(string f, string r)
	{
		enum FIPSerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_FIPS, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template CMSerr(string f, string r)
	{
		enum CMSerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_CMS, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template TSerr(string f, string r)
	{
		enum TSerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_TS, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template HMACerr(string f, string r)
	{
		enum HMACerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_HMAC, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template JPAKEerr(string f, string r)
	{
		enum JPAKEerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_JPAKE, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template GOSTerr(string f, string r)
	{
		enum GOSTerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_GOST, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template SSLerr(string f, string r)
	{
		enum SSLerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_SSL, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template CTerr(string f, string r)
	{
		enum CTerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_CT, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

	template KDFerr(string f, string r)
	{
		enum KDFerr = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_KDF, " ~ f ~ ", " ~ r ~ ", &(__FILE__[0]), __LINE__);";
	}

}

version (LIBRESSL_INTERNAL) {
	template SYSerror(string r)
	{
		enum SYSerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_SYS, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template BNerror(string r)
	{
		enum BNerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_BN, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template RSAerror(string r)
	{
		enum RSAerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_RSA, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template DHerror(string r)
	{
		enum DHerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_DH, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template EVPerror(string r)
	{
		enum EVPerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_EVP, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template BUFerror(string r)
	{
		enum BUFerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_BUF, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template OBJerror(string r)
	{
		enum OBJerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_OBJ, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template PEMerror(string r)
	{
		enum PEMerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_PEM, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template DSAerror(string r)
	{
		enum DSAerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_DSA, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template X509error(string r)
	{
		enum X509error = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_X509, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template ASN1error(string r)
	{
		enum ASN1error = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_ASN1, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template CONFerror(string r)
	{
		enum CONFerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_CONF, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template CRYPTOerror(string r)
	{
		enum CRYPTOerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_CRYPTO, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template ECerror(string r)
	{
		enum ECerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_EC, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template BIOerror(string r)
	{
		enum BIOerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_BIO, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template PKCS7error(string r)
	{
		enum PKCS7error = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_PKCS7, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template X509V3error(string r)
	{
		enum X509V3error = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_X509V3, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template PKCS12error(string r)
	{
		enum PKCS12error = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_PKCS12, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template RANDerror(string r)
	{
		enum RANDerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_RAND, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template DSOerror(string r)
	{
		enum DSOerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_DSO, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template ENGINEerror(string r)
	{
		enum ENGINEerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_ENGINE, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template OCSPerror(string r)
	{
		enum OCSPerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_OCSP, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template UIerror(string r)
	{
		enum UIerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_UI, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template COMPerror(string r)
	{
		enum COMPerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_COMP, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template ECDSAerror(string r)
	{
		enum ECDSAerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_ECDSA, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template ECDHerror(string r)
	{
		enum ECDHerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_ECDH, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template STOREerror(string r)
	{
		enum STOREerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_STORE, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template FIPSerror(string r)
	{
		enum FIPSerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_FIPS, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template CMSerror(string r)
	{
		enum CMSerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_CMS, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template TSerror(string r)
	{
		enum TSerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_TS, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template HMACerror(string r)
	{
		enum HMACerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_HMAC, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template JPAKEerror(string r)
	{
		enum JPAKEerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_JPAKE, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template GOSTerror(string r)
	{
		enum GOSTerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_GOST, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template CTerror(string r)
	{
		enum CTerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_CT, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}

	template KDFerror(string r)
	{
		enum KDFerror = "libressl.openssl.err.ERR_PUT_error(libressl.openssl.err.ERR_LIB_KDF, 0x0FFF, " ~ r ~", &(__FILE__[0]), __LINE__);";
	}
}

pragma(inline, true)
core.stdc.config.c_ulong ERR_PACK(core.stdc.config.c_ulong l, core.stdc.config.c_ulong f, core.stdc.config.c_ulong r)

	do
	{
		return ((l & 0xFFL) << 24L) | ((f & 0x0FFFL) << 12L) | (r & 0x0FFFL);
	}

pragma(inline, true)
int ERR_GET_LIB(core.stdc.config.c_ulong l)

	do
	{
		return cast(int)((l >> 24L) & 0xFFL);
	}

pragma(inline, true)
int ERR_GET_FUNC(core.stdc.config.c_ulong l)

	do
	{
		return cast(int)((l >> 12L) & 0x0FFFL);
	}

pragma(inline, true)
int ERR_GET_REASON(L)(L l)

	do
	{
		return cast(int)(l & 0x0FFFL);
	}

pragma(inline, true)
int ERR_FATAL_ERROR(L)(L l)

	do
	{
		return cast(int)(l & .ERR_R_FATAL);
	}

/* OS functions */
enum SYS_F_FOPEN = 1;
enum SYS_F_CONNECT = 2;
enum SYS_F_GETSERVBYNAME = 3;
enum SYS_F_SOCKET = 4;
enum SYS_F_IOCTLSOCKET = 5;
enum SYS_F_BIND = 6;
enum SYS_F_LISTEN = 7;
enum SYS_F_ACCEPT = 8;

/**
 * Winsock stuff
 */
enum SYS_F_WSASTARTUP = 9;

enum SYS_F_OPENDIR = 10;
enum SYS_F_FREAD = 11;

/* reasons */

/**
 * 2
 */
enum ERR_R_SYS_LIB = .ERR_LIB_SYS;

/**
 * 3
 */
enum ERR_R_BN_LIB = .ERR_LIB_BN;

/**
 * 4
 */
enum ERR_R_RSA_LIB = .ERR_LIB_RSA;

/**
 * 5
 */
enum ERR_R_DH_LIB = .ERR_LIB_DH;

/**
 * 6
 */
enum ERR_R_EVP_LIB = .ERR_LIB_EVP;

/**
 * 7
 */
enum ERR_R_BUF_LIB = .ERR_LIB_BUF;

/**
 * 8
 */
enum ERR_R_OBJ_LIB = .ERR_LIB_OBJ;

/**
 * 9
 */
enum ERR_R_PEM_LIB = .ERR_LIB_PEM;

/**
 * 10
 */
enum ERR_R_DSA_LIB = .ERR_LIB_DSA;

/**
 * 11
 */
enum ERR_R_X509_LIB = .ERR_LIB_X509;

/**
 * 13
 */
enum ERR_R_ASN1_LIB = .ERR_LIB_ASN1;

/**
 * 14
 */
enum ERR_R_CONF_LIB = .ERR_LIB_CONF;

/**
 * 15
 */
enum ERR_R_CRYPTO_LIB = .ERR_LIB_CRYPTO;

/**
 * 16
 */
enum ERR_R_EC_LIB = .ERR_LIB_EC;

/**
 * 20
 */
enum ERR_R_SSL_LIB = .ERR_LIB_SSL;

/**
 * 32
 */
enum ERR_R_BIO_LIB = .ERR_LIB_BIO;

/**
 * 33
 */
enum ERR_R_PKCS7_LIB = .ERR_LIB_PKCS7;

/**
 * 34
 */
enum ERR_R_X509V3_LIB = .ERR_LIB_X509V3;

/**
 * 35
 */
enum ERR_R_PKCS12_LIB = .ERR_LIB_PKCS12;

/**
 * 36
 */
enum ERR_R_RAND_LIB = .ERR_LIB_RAND;

/**
 * 37
 */
enum ERR_R_DSO_LIB = .ERR_LIB_DSO;

/**
 * 38
 */
enum ERR_R_ENGINE_LIB = .ERR_LIB_ENGINE;

/**
 * 39
 */
enum ERR_R_OCSP_LIB = .ERR_LIB_OCSP;

/**
 * 40
 */
enum ERR_R_UI_LIB = .ERR_LIB_UI;

/**
 * 41
 */
enum ERR_R_COMP_LIB = .ERR_LIB_COMP;

/**
 * 42
 */
enum ERR_R_ECDSA_LIB = .ERR_LIB_ECDSA;

/**
 * 43
 */
enum ERR_R_ECDH_LIB = .ERR_LIB_ECDH;

/**
 * 44
 */
enum ERR_R_STORE_LIB = .ERR_LIB_STORE;

/**
 * 45
 */
enum ERR_R_TS_LIB = .ERR_LIB_TS;

enum ERR_R_NESTED_ASN1_ERROR = 58;
enum ERR_R_BAD_ASN1_OBJECT_HEADER = 59;
enum ERR_R_BAD_GET_ASN1_OBJECT_CALL = 60;
enum ERR_R_EXPECTING_AN_ASN1_SEQUENCE = 61;
enum ERR_R_ASN1_LENGTH_MISMATCH = 62;
enum ERR_R_MISSING_ASN1_EOS = 63;

/* fatal error */
enum ERR_R_FATAL = 64;
enum ERR_R_MALLOC_FAILURE = 1 | .ERR_R_FATAL;
enum ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED = 2 | .ERR_R_FATAL;
enum ERR_R_PASSED_NULL_PARAMETER = 3 | .ERR_R_FATAL;
enum ERR_R_INTERNAL_ERROR = 4 | .ERR_R_FATAL;
enum ERR_R_DISABLED = 5 | .ERR_R_FATAL;
enum ERR_R_INIT_FAIL = 6 | .ERR_R_FATAL;

/*
 * 99 is the maximum possible ERR_R_... code, higher values
 * are reserved for the individual libraries
 */

struct ERR_string_data_st
{
	core.stdc.config.c_ulong error;
	const (char)* string_;
}

alias ERR_STRING_DATA = .ERR_string_data_st;

void ERR_put_error(int lib, int func, int reason, const (char)* file, int line);
void ERR_set_error_data(char* data, int flags);

core.stdc.config.c_ulong ERR_get_error();
core.stdc.config.c_ulong ERR_get_error_line(const (char)** file, int* line);
core.stdc.config.c_ulong ERR_get_error_line_data(const (char)** file, int* line, const (char)** data, int* flags);
core.stdc.config.c_ulong ERR_peek_error();
core.stdc.config.c_ulong ERR_peek_error_line(const (char)** file, int* line);
core.stdc.config.c_ulong ERR_peek_error_line_data(const (char)** file, int* line, const (char)** data, int* flags);
core.stdc.config.c_ulong ERR_peek_last_error();
core.stdc.config.c_ulong ERR_peek_last_error_line(const (char)** file, int* line);
core.stdc.config.c_ulong ERR_peek_last_error_line_data(const (char)** file, int* line, const (char)** data, int* flags);
void ERR_clear_error();
char* ERR_error_string(core.stdc.config.c_ulong e, char* buf);
void ERR_error_string_n(core.stdc.config.c_ulong e, char* buf, size_t len);
const (char)* ERR_lib_error_string(core.stdc.config.c_ulong e);
const (char)* ERR_func_error_string(core.stdc.config.c_ulong e);
const (char)* ERR_reason_error_string(core.stdc.config.c_ulong e);
void ERR_print_errors_cb(int function(const (char)* str, size_t len, void* u) nothrow @nogc cb, void* u);
void ERR_print_errors_fp(libressl.compat.stdio.FILE* fp);

version (OPENSSL_NO_BIO) {
} else {
	void ERR_print_errors(libressl.openssl.ossl_typ.BIO* bp);
}

void ERR_asprintf_error_data(char* format, ...);

version (LIBRESSL_INTERNAL) {
} else {
	void ERR_add_error_data(int num, ...);
	void ERR_add_error_vdata(int num, core.stdc.stdarg.va_list args);
}

void ERR_load_strings(int lib, .ERR_STRING_DATA* str);
void ERR_unload_strings(int lib, .ERR_STRING_DATA* str);
void ERR_load_ERR_strings();
void ERR_load_crypto_strings();
void ERR_free_strings();

void ERR_remove_thread_state(const (libressl.openssl.crypto.CRYPTO_THREADID)* tid);

version (OPENSSL_NO_DEPRECATED) {
} else {
	/**
	 * if zero we look it up
	 */
	void ERR_remove_state(core.stdc.config.c_ulong pid);
}

.ERR_STATE* ERR_get_state();

version (OPENSSL_NO_LHASH) {
} else {
	struct lhash_st_ERR_STRING_DATA;
	struct lhash_st_ERR_STATE;
	.lhash_st_ERR_STRING_DATA* ERR_get_string_table();
	.lhash_st_ERR_STATE* ERR_get_err_state_table();
	void ERR_release_err_state_table(.lhash_st_ERR_STATE** hash);
}

int ERR_get_next_error_library();

int ERR_set_mark();
int ERR_pop_to_mark();

/* Already defined in ossl_typ.h */
/* alias ERR_FNS = .st_ERR_FNS; */

/**
 * An application can use this function and provide the return value to loaded
 * modules that should use the application's ERR state/functionality
 */
const (libressl.openssl.ossl_typ.ERR_FNS)* ERR_get_implementation();

/**
 * A loaded module should call this function prior to any ERR operations using
 * the application's "ERR_FNS".
 */
int ERR_set_implementation(const (libressl.openssl.ossl_typ.ERR_FNS)* fns);
