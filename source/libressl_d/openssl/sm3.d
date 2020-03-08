/*	$OpenBSD: sm3.h,v 1.1 2018/11/11 06:53:31 tb Exp $	*/
/*
 * Copyright (c) 2018, Ribose Inc
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
module libressl_d.openssl.sm3;


public import core.stdc.stddef;
public import libressl_d.openssl.opensslconf;

extern (C):
nothrow @nogc:

version (OPENSSL_NO_SM3) {
	//static assert(false, "SM3 is disabled.");
}

enum SM3_DIGEST_LENGTH = 32;
alias SM3_WORD = uint;

enum SM3_CBLOCK = 64;
enum SM3_LBLOCK = .SM3_CBLOCK / 4;

struct SM3state_st
{
	.SM3_WORD A;
	.SM3_WORD B;
	.SM3_WORD C;
	.SM3_WORD D;
	.SM3_WORD E;
	.SM3_WORD F;
	.SM3_WORD G;
	.SM3_WORD H;
	.SM3_WORD Nl;
	.SM3_WORD Nh;
	.SM3_WORD[.SM3_LBLOCK] data;
	uint num;
}

alias SM3_CTX = .SM3state_st;

int SM3_Init(.SM3_CTX* c);
int SM3_Update(.SM3_CTX* c, const (void)* data, size_t len);
int SM3_Final(ubyte* md, .SM3_CTX* c);
