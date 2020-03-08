/* $OpenBSD: dtls1.h,v 1.22 2018/08/24 19:35:05 jsing Exp $ */
/*
 * DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005.
 */
/* ====================================================================
 * Copyright (c) 1999-2005 The OpenSSL Project.  All rights reserved.
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
 *    openssl-core@OpenSSL.org.
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
module libressl_d.openssl.dtls1;


private static import core.stdc.config;
private static import libressl_d.openssl.ossl_typ;
private static import libressl_d.openssl.ssl3;
private static import libressl_d.openssl.ssl;
public import libressl_d.compat.stdio;
public import libressl_d.compat.stdlib;
public import libressl_d.compat.string;
public import libressl_d.compat.sys.time;
public import libressl_d.openssl.buffer;
public import libressl_d.openssl.opensslconf;

extern (C):
nothrow @nogc:

enum DTLS1_VERSION = 0xFEFF;

/* lengths of messages */
enum DTLS1_COOKIE_LENGTH = 256;

enum DTLS1_RT_HEADER_LENGTH = 13;

enum DTLS1_HM_HEADER_LENGTH = 12;

enum DTLS1_HM_BAD_FRAGMENT = -2;
enum DTLS1_HM_FRAGMENT_RETRY = -3;

enum DTLS1_CCS_HEADER_LENGTH = 1;

enum DTLS1_AL_HEADER_LENGTH = 2;

//#if !defined(OPENSSL_NO_SSL_INTERN)
struct dtls1_bitmap_st
{
	/**
	 * track 32 packets on 32-bit systems
	 * and 64 - on 64-bit systems
	 */
	core.stdc.config.c_ulong map;

	/**
	 * max record number seen so far,
	 * 64-bit value in big-endian
	 * encoding
	 */
	ubyte[8] max_seq_num;
}

alias DTLS1_BITMAP = .dtls1_bitmap_st;

struct dtls1_retransmit_state
{
	/**
	 * cryptographic state
	 */
	libressl_d.openssl.ossl_typ.EVP_CIPHER_CTX* enc_write_ctx;

	/**
	 * used for mac generation
	 */
	libressl_d.openssl.ossl_typ.EVP_MD_CTX* write_hash;

	libressl_d.openssl.ssl.SSL_SESSION* session;
	ushort epoch;
}

struct hm_header_st
{
	ubyte type;
	core.stdc.config.c_ulong msg_len;
	ushort seq;
	core.stdc.config.c_ulong frag_off;
	core.stdc.config.c_ulong frag_len;
	uint is_ccs;
	.dtls1_retransmit_state saved_retransmit_state;
}

struct ccs_header_st
{
	ubyte type;
	ushort seq;
}

struct dtls1_timeout_st
{
	/* Number of read timeouts so far */
	uint read_timeouts;

	/* Number of write timeouts so far */
	uint write_timeouts;

	/* Number of alerts received so far */
	uint num_alerts;
}

//struct _pqueue;
private alias _pqueue = void;

struct record_pqueue_st
{
	ushort epoch;
	._pqueue* q;
}

alias record_pqueue = .record_pqueue_st;

struct hm_fragment_st
{
	.hm_header_st msg_header;
	ubyte* fragment;
	ubyte* reassembly;
}

alias hm_fragment = .hm_fragment_st;

//struct dtls1_state_internal_st;
package alias dtls1_state_internal_st = void;

struct dtls1_state_st
{
	/* Buffered (sent) handshake records */
	._pqueue* sent_messages;

	/* Indicates when the last handshake msg or heartbeat sent will timeout */
	libressl_d.compat.sys.time.timeval next_timeout;

	/* Timeout duration */
	ushort timeout_duration;

	.dtls1_state_internal_st* internal;
}

alias DTLS1_STATE = .dtls1_state_st;

struct dtls1_record_data_st
{
	ubyte* packet;
	uint packet_length;
	libressl_d.openssl.ssl3.SSL3_BUFFER rbuf;
	libressl_d.openssl.ssl3.SSL3_RECORD rrec;
}

alias DTLS1_RECORD_DATA = .dtls1_record_data_st;
//#endif

/* Timeout multipliers (timeout slice is defined in apps/timeouts.h */
enum DTLS1_TMO_READ_COUNT = 2;
enum DTLS1_TMO_WRITE_COUNT = 2;

enum DTLS1_TMO_ALERT_COUNT = 12;
