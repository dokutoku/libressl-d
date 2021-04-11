/* $OpenBSD: sha.h,v 1.21 2015/09/13 21:09:56 doug Exp $ */
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
module libressl_d.openssl.sha;


private static import core.stdc.config;
public import core.stdc.stddef;
public import libressl_d.openssl.opensslconf;

//#if !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__OpenBSD__)
//	#define __bounded__(x, y, z)
//#endif

extern (C):
nothrow @nogc:

//#if defined(OPENSSL_NO_SHA) || defined(OPENSSL_NO_SHA1)
//	static assert(false, "SHA is disabled.");
//#endif

/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! SHA_LONG has to be at least 32 bits wide.                    !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */

alias SHA_LONG = uint;

enum SHA_LBLOCK = 16;

/**
 * SHA treats input data as a
 * contiguous array of 32 bit
 * wide big-endian values.
 */
enum SHA_CBLOCK = .SHA_LBLOCK * 4;

enum SHA_LAST_BLOCK = .SHA_CBLOCK - 8;
enum SHA_DIGEST_LENGTH = 20;

struct SHAstate_st
{
	.SHA_LONG h0;
	.SHA_LONG h1;
	.SHA_LONG h2;
	.SHA_LONG h3;
	.SHA_LONG h4;
	.SHA_LONG Nl;
	.SHA_LONG Nh;
	.SHA_LONG[.SHA_LBLOCK] data;
	uint num;
}

alias SHA_CTX = SHAstate_st;

//#if !defined(OPENSSL_NO_SHA1)
int SHA1_Init(.SHA_CTX* c);

//__attribute__((__bounded__(__buffer__, 2, 3)));
int SHA1_Update(.SHA_CTX* c, const (void)* data, size_t len);

int SHA1_Final(ubyte* md, .SHA_CTX* c);

//__attribute__((__bounded__(__buffer__, 1, 2)));
ubyte* SHA1(const (ubyte)* d, size_t n, ubyte* md);

void SHA1_Transform(.SHA_CTX* c, const (ubyte)* data);
//#endif

/**
 * SHA-256 treats input data as a
 * contiguous array of 32 bit
 * wide big-endian values.
 */
enum SHA256_CBLOCK = .SHA_LBLOCK * 4;

enum SHA224_DIGEST_LENGTH = 28;
enum SHA256_DIGEST_LENGTH = 32;

struct SHA256state_st
{
	.SHA_LONG[8] h;
	.SHA_LONG Nl;
	.SHA_LONG Nh;
	.SHA_LONG[.SHA_LBLOCK] data;
	uint num;
	uint md_len;
}

alias SHA256_CTX = .SHA256state_st;

//#if !defined(OPENSSL_NO_SHA256)
int SHA224_Init(.SHA256_CTX* c);

//__attribute__((__bounded__(__buffer__, 2, 3)));
int SHA224_Update(.SHA256_CTX* c, const (void)* data, size_t len);

int SHA224_Final(ubyte* md, .SHA256_CTX* c);

//__attribute__((__bounded__(__buffer__, 1, 2)));
ubyte* SHA224(const (ubyte)* d, size_t n, ubyte* md);

int SHA256_Init(.SHA256_CTX* c);

//__attribute__((__bounded__(__buffer__, 2, 3)));
int SHA256_Update(.SHA256_CTX* c, const (void)* data, size_t len);

int SHA256_Final(ubyte* md, .SHA256_CTX* c);

//__attribute__((__bounded__(__buffer__, 1, 2)));
ubyte* SHA256(const (ubyte)* d, size_t n, ubyte* md);

void SHA256_Transform(.SHA256_CTX* c, const (ubyte)* data);
//#endif

enum SHA384_DIGEST_LENGTH = 48;
enum SHA512_DIGEST_LENGTH = 64;

//#if !defined(OPENSSL_NO_SHA512)
/*
 * Unlike 32-bit digest algorithms, SHA-512 *relies* on SHA_LONG64
 * being exactly 64-bit wide. See Implementation Notes in sha512.c
 * for further details.
 */

/**
 * SHA-512 treats input data as a
 * contiguous array of 64 bit
 * wide big-endian values.
 */
enum SHA512_CBLOCK = .SHA_LBLOCK * 8;

alias SHA_LONG64 = ulong;

struct SHA512state_st
{
	.SHA_LONG64[8] h;
	.SHA_LONG64 Nl;
	.SHA_LONG64 Nh;

	union u_
	{
		.SHA_LONG64[.SHA_LBLOCK] d;
		ubyte[.SHA512_CBLOCK] p;
	}

	u_ u;
	uint num;
	uint md_len;
}

alias SHA512_CTX = .SHA512state_st;
//#endif

//#if !defined(OPENSSL_NO_SHA512)
int SHA384_Init(.SHA512_CTX* c);

//__attribute__((__bounded__(__buffer__, 2, 3)));
int SHA384_Update(.SHA512_CTX* c, const (void)* data, size_t len);

int SHA384_Final(ubyte* md, .SHA512_CTX* c);

//__attribute__((__bounded__(__buffer__, 1, 2)));
ubyte* SHA384(const (ubyte)* d, size_t n, ubyte* md);

int SHA512_Init(.SHA512_CTX* c);

//__attribute__((__bounded__(__buffer__, 2, 3)));
int SHA512_Update(.SHA512_CTX* c, const (void)* data, size_t len);

int SHA512_Final(ubyte* md, .SHA512_CTX* c);

//__attribute__((__bounded__(__buffer__, 1, 2)));
ubyte* SHA512(const (ubyte)* d, size_t n, ubyte* md);

void SHA512_Transform(.SHA512_CTX* c, const (ubyte)* data);
//#endif
