/* $OpenBSD: gost.h,v 1.3 2016/09/04 17:02:31 jsing Exp $ */
/*
 * Copyright (c) 2014 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Copyright (c) 2005-2006 Cryptocom LTD
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
 */
module libressl_d.openssl.gost;


private static import core.stdc.config;
private static import libressl_d.openssl.asn1;
private static import libressl_d.openssl.evp;
private static import libressl_d.openssl.ossl_typ;
private static import std.bitmanip;
public import libressl_d.openssl.asn1t;
public import libressl_d.openssl.ec;
public import libressl_d.openssl.opensslconf;

version (OPENSSL_NO_GOST) {
	//static assert(false, "GOST is disabled.");
}

extern (C):
nothrow @nogc:

version (none) {
	struct gost2814789_key_st
	{
		uint[8] key;
		uint[256] k87;
		uint[256] k65;
		uint[256] k43;
		uint[256] k21;
		uint count;

		//ToDO:
		mixin(std.bitmanip.bitfields!(uint, "key_meshing", 1));
	}

	alias GOST2814789_KEY = .gost2814789_key_st;
} else {
	package alias GOST2814789_KEY = void;
}

int Gost2814789_set_sbox(.GOST2814789_KEY* key, int nid);
int Gost2814789_set_key(.GOST2814789_KEY* key, const (ubyte)* userKey, const int bits);
void Gost2814789_ecb_encrypt(const (ubyte)* in_, ubyte* out_, .GOST2814789_KEY* key, const int enc);
void Gost2814789_cfb64_encrypt(const (ubyte)* in_, ubyte* out_, size_t length_, .GOST2814789_KEY* key, ubyte* ivec, int* num, const int enc);
void Gost2814789_cnt_encrypt(const (ubyte)* in_, ubyte* out_, size_t length_, .GOST2814789_KEY* key, ubyte* ivec, ubyte* cnt_buf, int* num);

struct GOST_CIPHER_PARAMS
{
	libressl_d.openssl.ossl_typ.ASN1_OCTET_STRING* iv;
	libressl_d.openssl.asn1.ASN1_OBJECT* enc_param_set;
}

.GOST_CIPHER_PARAMS* GOST_CIPHER_PARAMS_new();
void GOST_CIPHER_PARAMS_free(.GOST_CIPHER_PARAMS* a);
.GOST_CIPHER_PARAMS* d2i_GOST_CIPHER_PARAMS(.GOST_CIPHER_PARAMS** a, const (ubyte)** in_, core.stdc.config.c_long len);
int i2d_GOST_CIPHER_PARAMS(.GOST_CIPHER_PARAMS* a, ubyte** out_);
extern const libressl_d.openssl.ossl_typ.ASN1_ITEM GOST_CIPHER_PARAMS_it;

enum GOST2814789IMIT_LENGTH = 4;
enum GOST2814789IMIT_CBLOCK = 8;
alias GOST2814789IMIT_LONG = uint;

version (none) {
	struct GOST2814789IMITstate_st
	{
		.GOST2814789IMIT_LONG Nl;
		.GOST2814789IMIT_LONG Nh;
		ubyte[.GOST2814789IMIT_CBLOCK] data;
		uint num;

		.GOST2814789_KEY cipher;
		ubyte[.GOST2814789IMIT_CBLOCK] mac;
	}

	alias GOST2814789IMIT_CTX = .GOST2814789IMITstate_st;
} else {
	package alias GOST2814789IMIT_CTX = void;
}

/* Note, also removed second parameter and removed dctx.cipher setting */
int GOST2814789IMIT_Init(.GOST2814789IMIT_CTX* c, int nid);
int GOST2814789IMIT_Update(.GOST2814789IMIT_CTX* c, const (void)* data, size_t len);
int GOST2814789IMIT_Final(ubyte* md, .GOST2814789IMIT_CTX* c);
void GOST2814789IMIT_Transform(.GOST2814789IMIT_CTX* c, const (ubyte)* data);
ubyte* GOST2814789IMIT(const (ubyte)* d, size_t n, ubyte* md, int nid, const (ubyte)* key, const (ubyte)* iv);

alias GOSTR341194_LONG = uint;

enum GOSTR341194_LENGTH = 32;
enum GOSTR341194_CBLOCK = 32;
enum GOSTR341194_LBLOCK = .GOSTR341194_CBLOCK / 4;

version (none) {
	struct GOSTR341194state_st
	{
		.GOSTR341194_LONG Nl;
		.GOSTR341194_LONG Nh;
		.GOSTR341194_LONG[.GOSTR341194_LBLOCK] data;
		uint num;

		.GOST2814789_KEY cipher;
		ubyte[.GOSTR341194_CBLOCK] H;
		ubyte[.GOSTR341194_CBLOCK] S;
	}

	alias GOSTR341194_CTX = .GOSTR341194state_st;
} else {
	package alias GOSTR341194_CTX = void;
}

/* Note, also removed second parameter and removed dctx.cipher setting */
int GOSTR341194_Init(.GOSTR341194_CTX* c, int nid);
int GOSTR341194_Update(.GOSTR341194_CTX* c, const (void)* data, size_t len);
int GOSTR341194_Final(ubyte* md, .GOSTR341194_CTX* c);
void GOSTR341194_Transform(.GOSTR341194_CTX* c, const (ubyte)* data);
ubyte* GOSTR341194(const (ubyte)* d, size_t n, ubyte* md, int nid);

//#if defined(_LP64)
version (X86_64) {
	alias STREEBOG_LONG64 = core.stdc.config.c_ulong;
	//#define U64(C) C##UL
} else {
	alias STREEBOG_LONG64 = core.stdc.config.cpp_ulonglong;
	//#define U64(C) C##ULL
}

enum STREEBOG_LBLOCK = 8;
enum STREEBOG_CBLOCK = 64;
enum STREEBOG256_LENGTH = 32;
enum STREEBOG512_LENGTH = 64;

struct STREEBOGstate_st
{
	.STREEBOG_LONG64[.STREEBOG_LBLOCK] data;
	uint num;
	uint md_len;
	.STREEBOG_LONG64[.STREEBOG_LBLOCK] h;
	.STREEBOG_LONG64[.STREEBOG_LBLOCK] N;
	.STREEBOG_LONG64[.STREEBOG_LBLOCK] Sigma;
}

alias STREEBOG_CTX = .STREEBOGstate_st;

int STREEBOG256_Init(.STREEBOG_CTX* c);
int STREEBOG256_Update(.STREEBOG_CTX* c, const (void)* data, size_t len);
int STREEBOG256_Final(ubyte* md, .STREEBOG_CTX* c);
void STREEBOG256_Transform(.STREEBOG_CTX* c, const (ubyte)* data);
ubyte* STREEBOG256(const (ubyte)* d, size_t n, ubyte* md);

int STREEBOG512_Init(.STREEBOG_CTX* c);
int STREEBOG512_Update(.STREEBOG_CTX* c, const (void)* data, size_t len);
int STREEBOG512_Final(ubyte* md, .STREEBOG_CTX* c);
void STREEBOG512_Transform(.STREEBOG_CTX* c, const (ubyte)* data);
ubyte* STREEBOG512(const (ubyte)* d, size_t n, ubyte* md);

//struct gost_key_st;
package alias gost_key_st = void;

alias GOST_KEY = .gost_key_st;
.GOST_KEY* GOST_KEY_new();
void GOST_KEY_free(.GOST_KEY* r);
int GOST_KEY_check_key(const (.GOST_KEY)* eckey);
int GOST_KEY_set_public_key_affine_coordinates(.GOST_KEY* key, libressl_d.openssl.ossl_typ.BIGNUM* x, libressl_d.openssl.ossl_typ.BIGNUM* y);
const (libressl_d.openssl.ec.EC_GROUP)* GOST_KEY_get0_group(const (.GOST_KEY)* key);
int GOST_KEY_set_group(.GOST_KEY* key, const (libressl_d.openssl.ec.EC_GROUP)* group);
int GOST_KEY_get_digest(const (.GOST_KEY)* key);
int GOST_KEY_set_digest(.GOST_KEY* key, int digest_nid);
const (libressl_d.openssl.ossl_typ.BIGNUM)* GOST_KEY_get0_private_key(const (.GOST_KEY)* key);
int GOST_KEY_set_private_key(.GOST_KEY* key, const (libressl_d.openssl.ossl_typ.BIGNUM)* priv_key);
const (libressl_d.openssl.ec.EC_POINT)* GOST_KEY_get0_public_key(const (.GOST_KEY)* key);
int GOST_KEY_set_public_key(.GOST_KEY* key, const (libressl_d.openssl.ec.EC_POINT)* pub_key);
size_t GOST_KEY_get_size(const (.GOST_KEY)* r);

/* Gost-specific pmeth control-function parameters */
/* For GOST R34.10 parameters */
enum EVP_PKEY_CTRL_GOST_PARAMSET = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 1;
enum EVP_PKEY_CTRL_GOST_SIG_FORMAT = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 2;
enum EVP_PKEY_CTRL_GOST_SET_DIGEST = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 3;
enum EVP_PKEY_CTRL_GOST_GET_DIGEST = libressl_d.openssl.evp.EVP_PKEY_ALG_CTRL + 4;

enum GOST_SIG_FORMAT_SR_BE = 0;
enum GOST_SIG_FORMAT_RS_LE = 1;

/* BEGIN ERROR CODES */
/**
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_GOST_strings();

/* Error codes for the GOST functions. */

/* Function codes. */
enum GOST_F_DECODE_GOST01_ALGOR_PARAMS = 104;
enum GOST_F_ENCODE_GOST01_ALGOR_PARAMS = 105;
enum GOST_F_GOST2001_COMPUTE_PUBLIC = 106;
enum GOST_F_GOST2001_DO_SIGN = 107;
enum GOST_F_GOST2001_DO_VERIFY = 108;
enum GOST_F_GOST2001_KEYGEN = 109;
enum GOST_F_GOST89_GET_ASN1_PARAMETERS = 102;
enum GOST_F_GOST89_SET_ASN1_PARAMETERS = 103;
enum GOST_F_GOST_KEY_CHECK_KEY = 124;
enum GOST_F_GOST_KEY_NEW = 125;
enum GOST_F_GOST_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES = 126;
enum GOST_F_PARAM_COPY_GOST01 = 110;
enum GOST_F_PARAM_DECODE_GOST01 = 111;
enum GOST_F_PKEY_GOST01_CTRL = 116;
enum GOST_F_PKEY_GOST01_DECRYPT = 112;
enum GOST_F_PKEY_GOST01_DERIVE = 113;
enum GOST_F_PKEY_GOST01_ENCRYPT = 114;
enum GOST_F_PKEY_GOST01_PARAMGEN = 115;
enum GOST_F_PKEY_GOST01_SIGN = 123;
enum GOST_F_PKEY_GOST_MAC_CTRL = 100;
enum GOST_F_PKEY_GOST_MAC_KEYGEN = 101;
enum GOST_F_PRIV_DECODE_GOST01 = 117;
enum GOST_F_PUB_DECODE_GOST01 = 118;
enum GOST_F_PUB_ENCODE_GOST01 = 119;
enum GOST_F_PUB_PRINT_GOST01 = 120;
enum GOST_F_UNPACK_SIGNATURE_CP = 121;
enum GOST_F_UNPACK_SIGNATURE_LE = 122;

/* Reason codes. */
enum GOST_R_BAD_KEY_PARAMETERS_FORMAT = 104;
enum GOST_R_BAD_PKEY_PARAMETERS_FORMAT = 105;
enum GOST_R_CANNOT_PACK_EPHEMERAL_KEY = 106;
enum GOST_R_CTRL_CALL_FAILED = 107;
enum GOST_R_ERROR_COMPUTING_SHARED_KEY = 108;
enum GOST_R_ERROR_PARSING_KEY_TRANSPORT_INFO = 109;
enum GOST_R_INCOMPATIBLE_ALGORITHMS = 110;
enum GOST_R_INCOMPATIBLE_PEER_KEY = 111;
enum GOST_R_INVALID_DIGEST_TYPE = 100;
enum GOST_R_INVALID_IV_LENGTH = 103;
enum GOST_R_INVALID_MAC_KEY_LENGTH = 101;
enum GOST_R_KEY_IS_NOT_INITIALIZED = 112;
enum GOST_R_KEY_PARAMETERS_MISSING = 113;
enum GOST_R_MAC_KEY_NOT_SET = 102;
enum GOST_R_NO_PARAMETERS_SET = 115;
enum GOST_R_NO_PEER_KEY = 116;
enum GOST_R_NO_PRIVATE_PART_OF_NON_EPHEMERAL_KEYPAIR = 117;
enum GOST_R_PUBLIC_KEY_UNDEFINED = 118;
enum GOST_R_RANDOM_NUMBER_GENERATOR_FAILED = 120;
enum GOST_R_SIGNATURE_MISMATCH = 121;
enum GOST_R_SIGNATURE_PARTS_GREATER_THAN_Q = 122;
enum GOST_R_UKM_NOT_SET = 123;
