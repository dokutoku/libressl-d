/* $OpenBSD: chacha.h,v 1.8 2019/01/22 00:59:21 dlg Exp $ */
/*
 * Copyright (c) 2014 Joel Sing <jsing@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
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
module libressl_d.openssl.chacha;


public import core.stdc.stddef;
public import core.stdc.stdint;
public import libressl_d.openssl.opensslconf;

version (OPENSSL_NO_CHACHA) {
	static assert(false, "ChaCha is disabled.");
}

extern (C):
nothrow @nogc:

struct ChaCha_ctx
{
	uint[16] input;
	ubyte[64] ks;
	ubyte unused;
}

void ChaCha_set_key(.ChaCha_ctx* ctx, const (ubyte)* key, uint keybits);
void ChaCha_set_iv(.ChaCha_ctx* ctx, const (ubyte)* iv, const (ubyte)* counter);
void ChaCha(.ChaCha_ctx* ctx, ubyte* out_, const (ubyte)* in_, size_t len);

void CRYPTO_chacha_20(ubyte* out_, const (ubyte)* in_, size_t len, const ubyte[32] key, const ubyte[8] iv, core.stdc.stdint.uint64_t counter);
void CRYPTO_xchacha_20(ubyte* out_, const (ubyte)* in_, size_t len, const ubyte[32] key, const ubyte[24] iv);
void CRYPTO_hchacha_20(ubyte[32] out_, const ubyte[32] key, const ubyte[16] iv);
