/* $OpenBSD: poly1305.h,v 1.3 2014/07/25 14:04:51 jsing Exp $ */
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
module libressl_d.openssl.poly1305;


public import core.stdc.stddef;
public import libressl_d.openssl.opensslconf;

version (OPENSSL_NO_POLY1305) {
	//static assert(false, "Poly1305 is disabled.");
}

extern (C):
nothrow @nogc:

struct poly1305_context
{
	size_t aligner;
	ubyte[136] opaque;
}

alias poly1305_state = .poly1305_context;

void CRYPTO_poly1305_init(.poly1305_context* ctx, const ubyte[32] key);
void CRYPTO_poly1305_update(.poly1305_context* ctx, const (ubyte)* in_, size_t len);
void CRYPTO_poly1305_finish(.poly1305_context* ctx, ubyte[16] mac);
