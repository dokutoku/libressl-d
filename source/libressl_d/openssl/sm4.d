/*	$OpenBSD: sm4.h,v 1.1 2019/03/17 17:42:37 tb Exp $	*/
/*
 * Copyright (c) 2017, 2019 Ribose Inc
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
module libressl_d.openssl.sm4;


public import core.stdc.stdint;
public import libressl_d.openssl.opensslconf;

extern (C):
nothrow @nogc:

version (OPENSSL_NO_SM4) {
	//static assert(false, "SM4 is disabled.");
}

enum SM4_DECRYPT = 0;
enum SM4_ENCRYPT = 1;

enum SM4_BLOCK_SIZE = 16;
enum SM4_KEY_SCHEDULE = 32;

struct sm4_key_st
{
	ubyte[128] opaque;
}

alias SM4_KEY = .sm4_key_st;

int SM4_set_key(const (core.stdc.stdint.uint8_t)* key, .SM4_KEY* ks);
void SM4_decrypt(const (core.stdc.stdint.uint8_t)* in_, core.stdc.stdint.uint8_t* out_, const (.SM4_KEY)* ks);
void SM4_encrypt(const (core.stdc.stdint.uint8_t)* in_, core.stdc.stdint.uint8_t* out_, const (.SM4_KEY)* ks);
