/* $OpenBSD: bio.h,v 1.45 2018/06/02 04:41:12 tb Exp $ */
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
module libressl_d.openssl.bio;


private static import core.stdc.config;
private static import libressl_d.compat.netdb;
private static import libressl_d.openssl.ossl_typ;
private static import libressl_d.openssl.stack;
public import core.stdc.stdarg;
public import libressl_d.compat.stdio;
public import libressl_d.openssl.crypto;
public import libressl_d.openssl.opensslconf;

//version = HEADER_BIO_H;

//#if !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__OpenBSD__)
//	#define __bounded__(x, y, z)
//#endif

extern (C):
nothrow @nogc:

/* These are the 'types' of BIOs */
enum BIO_TYPE_NONE = 0;
enum BIO_TYPE_MEM = 1 | 0x0400;
enum BIO_TYPE_FILE = 2 | 0x0400;

enum BIO_TYPE_FD = 4 | 0x0400 | 0x0100;
enum BIO_TYPE_SOCKET = 5 | 0x0400 | 0x0100;
enum BIO_TYPE_NULL = 6 | 0x0400;
enum BIO_TYPE_SSL = 7 | 0x0200;

/**
 * passive filter
 */
enum BIO_TYPE_MD = 8 | 0x0200;

/**
 * filter
 */
enum BIO_TYPE_BUFFER = 9 | 0x0200;

/**
 * filter
 */
enum BIO_TYPE_CIPHER = 10 | 0x0200;

/**
 * filter
 */
enum BIO_TYPE_BASE64 = 11 | 0x0200;

/**
 * socket - connect
 */
enum BIO_TYPE_CONNECT = 12 | 0x0400 | 0x0100;

/**
 * socket for accept
 */
enum BIO_TYPE_ACCEPT = 13 | 0x0400 | 0x0100;

/**
 * client proxy BIO
 */
enum BIO_TYPE_PROXY_CLIENT = 14 | 0x0200;

/**
 * server proxy BIO
 */
enum BIO_TYPE_PROXY_SERVER = 15 | 0x0200;

/**
 * server proxy BIO
 */
enum BIO_TYPE_NBIO_TEST = 16 | 0x0200;

enum BIO_TYPE_NULL_FILTER = 17 | 0x0200;

/**
 * BER . bin filter
 */
enum BIO_TYPE_BER = 18 | 0x0200;

/**
 * (half a) BIO pair
 */
enum BIO_TYPE_BIO = 19 | 0x0400;

/**
 * filter
 */
enum BIO_TYPE_LINEBUFFER = 20 | 0x0200;

enum BIO_TYPE_DGRAM = 21 | 0x0400 | 0x0100;

/**
 * filter
 */
enum BIO_TYPE_ASN1 = 22 | 0x0200;

/**
 * filter
 */
enum BIO_TYPE_COMP = 23 | 0x0200;

/**
 *  socket, fd, connect or accept
 */
enum BIO_TYPE_DESCRIPTOR = 0x0100;

enum BIO_TYPE_FILTER = 0x0200;
enum BIO_TYPE_SOURCE_SINK = 0x0400;

/**
 * BIO_TYPE_START is the first user-allocated BIO type. No pre-defined type,
 * flag bits aside, may exceed this value.
 */
enum BIO_TYPE_START = 128;

/*
 * BIO_FILENAME_READ|BIO_CLOSE to open or close on free.
 * BIO_set_fp(in_,stdin,BIO_NOCLOSE);
 */
enum BIO_NOCLOSE = 0x00;
enum BIO_CLOSE = 0x01;

/*
 * These are used in the following macros and are passed to
 * BIO_ctrl()
 */

/**
 * opt - rewind/zero etc
 */
enum BIO_CTRL_RESET = 1;

/**
 *  opt - are we at the eof
 */
enum BIO_CTRL_EOF = 2;

/**
 *  opt - extra tit-bits
 */
enum BIO_CTRL_INFO = 3;

/**
 *  man - set the 'IO' type
 */
enum BIO_CTRL_SET = 4;

/**
 *  man - get the 'IO' type
 */
enum BIO_CTRL_GET = 5;

/**
 *  opt - internal, used to signify change
 */
enum BIO_CTRL_PUSH = 6;

/**
 *  opt - internal, used to signify change
 */
enum BIO_CTRL_POP = 7;

/**
 *  man - set the 'close' on free
 */
enum BIO_CTRL_GET_CLOSE = 8;

/**
 *  man - set the 'close' on free
 */
enum BIO_CTRL_SET_CLOSE = 9;

/**
 *  opt - is their more data buffered
 */
enum BIO_CTRL_PENDING = 10;

/**
 *  opt - 'flush' buffered output
 */
enum BIO_CTRL_FLUSH = 11;

/**
 *  man - extra stuff for 'duped' BIO
 */
enum BIO_CTRL_DUP = 12;

/**
 *  opt - number of bytes still to write
 */
enum BIO_CTRL_WPENDING = 13;

/* callback is int cb(BIO* io,state,ret); */

/**
 *  opt - set callback function
 */
enum BIO_CTRL_SET_CALLBACK = 14;

/**
 *  opt - set callback function
 */
enum BIO_CTRL_GET_CALLBACK = 15;

/**
 *  BIO_s_file special
 */
enum BIO_CTRL_SET_FILENAME = 30;

/* dgram BIO stuff */

/**
 *  BIO dgram special
 */
enum BIO_CTRL_DGRAM_CONNECT = 31;

/**
 * allow for an externally
 * connected socket to be
 * passed in
 */
enum BIO_CTRL_DGRAM_SET_CONNECTED = 32;

/**
 *  setsockopt, essentially
 */
enum BIO_CTRL_DGRAM_SET_RECV_TIMEOUT = 33;

/**
 *  getsockopt, essentially
 */
enum BIO_CTRL_DGRAM_GET_RECV_TIMEOUT = 34;

/**
 *  setsockopt, essentially
 */
enum BIO_CTRL_DGRAM_SET_SEND_TIMEOUT = 35;

/**
 *  getsockopt, essentially
 */
enum BIO_CTRL_DGRAM_GET_SEND_TIMEOUT = 36;

/**
 *  flag whether the last
 */
enum BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP = 37;

/**
 * I/O operation tiemd out
 */
enum BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP = 38;

/* #ifdef IP_MTU_DISCOVER */

/**
 *  set DF bit on egress packets
 */
enum BIO_CTRL_DGRAM_MTU_DISCOVER = 39;

/* #endif */

/**
 *  as kernel for current MTU
 */
enum BIO_CTRL_DGRAM_QUERY_MTU = 40;

enum BIO_CTRL_DGRAM_GET_FALLBACK_MTU = 47;

/**
 *  get cached value for MTU
 */
enum BIO_CTRL_DGRAM_GET_MTU = 41;

/**
 * set cached value for
 * MTU. want to use this
 * if asking the kernel
 * fails
 */
enum BIO_CTRL_DGRAM_SET_MTU = 42;

/**
 * check whether the MTU
 * was exceed in the
 * previous write
 * operation
 */
enum BIO_CTRL_DGRAM_MTU_EXCEEDED = 43;

enum BIO_CTRL_DGRAM_GET_PEER = 46;

/**
 *  Destination for the data
 */
enum BIO_CTRL_DGRAM_SET_PEER = 44;

/**
 * Next DTLS handshake timeout to
 * adjust socket timeouts
 */
enum BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT = 45;

/* modifiers */
enum BIO_FP_READ = 0x02;
enum BIO_FP_WRITE = 0x04;
enum BIO_FP_APPEND = 0x08;
enum BIO_FP_TEXT = 0x10;

enum BIO_FLAGS_READ = 0x01;
enum BIO_FLAGS_WRITE = 0x02;
enum BIO_FLAGS_IO_SPECIAL = 0x04;
enum BIO_FLAGS_RWS = .BIO_FLAGS_READ | .BIO_FLAGS_WRITE | .BIO_FLAGS_IO_SPECIAL;
enum BIO_FLAGS_SHOULD_RETRY = 0x08;

/* Used in BIO_gethostbyname() */
enum BIO_GHBN_CTRL_HITS = 1;
enum BIO_GHBN_CTRL_MISSES = 2;
enum BIO_GHBN_CTRL_CACHE_SIZE = 3;
enum BIO_GHBN_CTRL_GET_ENTRY = 4;
enum BIO_GHBN_CTRL_FLUSH = 5;

/* Mostly used in the SSL BIO */
/*
 * Not used anymore
 */
@disable
{
	enum BIO_FLAGS_PROTOCOL_DELAYED_READ = 0x10;
	enum BIO_FLAGS_PROTOCOL_DELAYED_WRITE = 0x20;
	enum BIO_FLAGS_PROTOCOL_STARTUP = 0x40;
}

enum BIO_FLAGS_BASE64_NO_NL = 0x0100;

/**
 * This is used with memory BIOs: it means we shouldn't free up or change the
 * data in any way.
 */
enum BIO_FLAGS_MEM_RDONLY = 0x0200;

alias BIO = .bio_st;

void BIO_set_flags(.BIO* b, int flags);
int BIO_test_flags(const (.BIO)* b, int flags);
void BIO_clear_flags(.BIO* b, int flags);

//#define BIO_get_flags(b) .BIO_test_flags(b, ~0x00)
//#define BIO_set_retry_special(b) .BIO_set_flags(b, (.BIO_FLAGS_IO_SPECIAL | .BIO_FLAGS_SHOULD_RETRY))
//#define BIO_set_retry_read(b) .BIO_set_flags(b, (.BIO_FLAGS_READ | .BIO_FLAGS_SHOULD_RETRY))
//#define BIO_set_retry_write(b) .BIO_set_flags(b, (.BIO_FLAGS_WRITE | .BIO_FLAGS_SHOULD_RETRY))

/* These are normally used internally in BIOs */
//#define BIO_clear_retry_flags(b) .BIO_clear_flags(b, (.BIO_FLAGS_RWS | .BIO_FLAGS_SHOULD_RETRY))
//#define BIO_get_retry_flags(b) .BIO_test_flags(b, (.BIO_FLAGS_RWS | .BIO_FLAGS_SHOULD_RETRY))

/* These should be used by the application to tell why we should retry */
//#define BIO_should_read(a) .BIO_test_flags(a, .BIO_FLAGS_READ)
//#define BIO_should_write(a) .BIO_test_flags(a, .BIO_FLAGS_WRITE)
//#define BIO_should_io_special(a) .BIO_test_flags(a, .BIO_FLAGS_IO_SPECIAL)
//#define BIO_retry_type(a) .BIO_test_flags(a, .BIO_FLAGS_RWS)
//#define BIO_should_retry(a) .BIO_test_flags(a, .BIO_FLAGS_SHOULD_RETRY)

/*
 * The next three are used in conjunction with the
 * BIO_should_io_special() condition.  After this returns true,
 * .BIO* IO_get_retry_BIO(.BIO* io, int* eason); will walk the BIO
 * stack and return the 'reason' for the special and the offending BIO.
 * Given a BIO, BIO_get_retry_reason(bio) will return the code.
 */
/**
 * Returned from the SSL bio when the certificate retrieval code had an error
 */
enum BIO_RR_SSL_X509_LOOKUP = 0x01;

/**
 * Returned from the connect BIO when a connect would have blocked
 */
enum BIO_RR_CONNECT = 0x02;

/**
 * Returned from the accept BIO when an accept would have blocked
 */
enum BIO_RR_ACCEPT = 0x03;

/* These are passed by the BIO callback */
enum BIO_CB_FREE = 0x01;
enum BIO_CB_READ = 0x02;
enum BIO_CB_WRITE = 0x03;
enum BIO_CB_PUTS = 0x04;
enum BIO_CB_GETS = 0x05;
enum BIO_CB_CTRL = 0x06;

/**
 * The callback is called before and after the underling operation,
 * The BIO_CB_RETURN flag indicates if it is after the call
 */
enum BIO_CB_RETURN = 0x80;

//#define BIO_CB_return(a) (a | .BIO_CB_RETURN)
//#define BIO_cb_pre(a) (!(a & .BIO_CB_RETURN))
//#define BIO_cb_post(a) (a & .BIO_CB_RETURN)

//core.stdc.config.c_long (*BIO_get_callback(const (.BIO)* b))(.bio_st*, int, const (char)*, int, core.stdc.config.c_long, core.stdc.config.c_long);
void BIO_set_callback(.BIO* b, core.stdc.config.c_long function(.bio_st*, int, const (char)*, int, core.stdc.config.c_long, core.stdc.config.c_long) callback);
char* BIO_get_callback_arg(const (.BIO)* b);
void BIO_set_callback_arg(.BIO* b, char* arg);

const (char)* BIO_method_name(const (.BIO)* b);
int BIO_method_type(const (.BIO)* b);

alias bio_info_cb = extern (C) nothrow @nogc void function(.bio_st*, int, const (char)*, int, core.stdc.config.c_long, core.stdc.config.c_long);
alias BIO_info_cb = extern (C) nothrow @nogc int function(.BIO*, int, int);

struct bio_method_st
{
	int type;
	const (char)* name;
	int function(.BIO*, const (char)*, int) bwrite;
	int function(.BIO*, char*, int) bread;
	int function(.BIO*, const (char)*) bputs;
	int function(.BIO*, char*, int) bgets;
	core.stdc.config.c_long function(.BIO*, int, core.stdc.config.c_long, void*) ctrl;
	int function(.BIO*) create;
	int function(.BIO*) destroy;
	core.stdc.config.c_long function(.BIO*, int, .bio_info_cb*) callback_ctrl;
}

alias BIO_METHOD = .bio_method_st;

struct bio_st
{
	const (.BIO_METHOD)* method;

	/**
	 * bio, mode, argp, argi, argl, ret
	 */
	core.stdc.config.c_long function(.bio_st*, int, const (char)*, int, core.stdc.config.c_long, core.stdc.config.c_long) callback;

	/**
	 * first argument for the callback
	 */
	char* cb_arg;

	int init;
	int shutdown;

	/**
	 * extra storage
	 */
	int flags;

	int retry_reason;
	int num;
	void* ptr_;

	/**
	 * used by filter BIOs
	 */
	.bio_st* next_bio;

	/**
	 * used by filter BIOs
	 */
	.bio_st* prev_bio;

	int references;
	core.stdc.config.c_ulong num_read;
	core.stdc.config.c_ulong num_write;

	libressl_d.openssl.ossl_typ.CRYPTO_EX_DATA ex_data;
}

//DECLARE_STACK_OF(BIO)
struct stack_st_BIO
{
	libressl_d.openssl.stack._STACK stack;
}

struct bio_f_buffer_ctx_struct
{
	/*
	 * Buffers are setup like this:
	 *
	 * <---------------------- size ----------------------.
	 * +---------------------------------------------------+
	 * | consumed | remaining          | free space        |
	 * +---------------------------------------------------+
	 * <-- off -.<------- len ------.
	 */

	/* .BIO* io; */ /* this is now in the BIO struct */

	/**
	 * how big is the input buffer
	 */
	int ibuf_size;

	/**
	 * how big is the output buffer
	 */
	int obuf_size;

	/**
	 * the char array
	 */
	char* ibuf;

	/**
	 * how many bytes are in it
	 */
	int ibuf_len;

	/**
	 * write/read offset
	 */
	int ibuf_off;

	/**
	 * the char array
	 */
	char* obuf;

	/**
	 * how many bytes are in it
	 */
	int obuf_len;

	/**
	 * write/read offset
	 */
	int obuf_off;
}

alias BIO_F_BUFFER_CTX = .bio_f_buffer_ctx_struct;

/**
 * Prefix and suffix callback in ASN1 BIO
 */
alias asn1_ps_func = extern (C) nothrow @nogc int function(.BIO* b, ubyte** pbuf, int* plen, void* parg);

/* BIO_METHOD accessors */
.BIO_METHOD* BIO_meth_new(int type, const (char)* name);
void BIO_meth_free(.BIO_METHOD* biom);
//int (*BIO_meth_get_write(const (.BIO_METHOD)* biom))(.BIO*, const (char)*, int);
int BIO_meth_set_write(.BIO_METHOD* biom, int function(.BIO*, const (char)*, int) write);
//int (*BIO_meth_get_read(const (.BIO_METHOD)* biom))(.BIO*, char*, int);
int BIO_meth_set_read(.BIO_METHOD* biom, int function(.BIO*, char*, int) read);
//int (*BIO_meth_get_puts(const (.BIO_METHOD)* biom))(.BIO*, const (char)*);
int BIO_meth_set_puts(.BIO_METHOD* biom, int function(.BIO*, const (char)*) puts);
//int (*BIO_meth_get_gets(const (.BIO_METHOD)* biom))(.BIO*, char*, int);
int BIO_meth_set_gets(.BIO_METHOD* biom, int function(.BIO*, char*, int) gets);
//core.stdc.config.c_long (*BIO_meth_get_ctrl(const (.BIO_METHOD)* biom))(.BIO*, int, core.stdc.config.c_long, void*);
int BIO_meth_set_ctrl(.BIO_METHOD* biom, core.stdc.config.c_long function(.BIO*, int, core.stdc.config.c_long, void*) ctrl);
//int (*BIO_meth_get_create(const (.BIO_METHOD)* biom))(.BIO*);
int BIO_meth_set_create(.BIO_METHOD* biom, int function(.BIO*) create);
//int (*BIO_meth_get_destroy(const (.BIO_METHOD)* biom))(.BIO*);
int BIO_meth_set_destroy(.BIO_METHOD* biom, int function(.BIO*) destroy);
//core.stdc.config.c_long (*BIO_meth_get_callback_ctrl(const (.BIO_METHOD)* biom))(.BIO*, int, .BIO_info_cb*);
int BIO_meth_set_callback_ctrl(.BIO_METHOD* biom, core.stdc.config.c_long function(.BIO*, int, .BIO_info_cb*) callback_ctrl);

/* connect BIO stuff */
enum BIO_CONN_S_BEFORE = 1;
enum BIO_CONN_S_GET_IP = 2;
enum BIO_CONN_S_GET_PORT = 3;
enum BIO_CONN_S_CREATE_SOCKET = 4;
enum BIO_CONN_S_CONNECT = 5;
enum BIO_CONN_S_OK = 6;
enum BIO_CONN_S_BLOCKED_CONNECT = 7;
enum BIO_CONN_S_NBIO = 8;
/*alias BIO_CONN_get_param_hostname = BIO_ctrl; */

enum BIO_C_SET_CONNECT = 100;
enum BIO_C_DO_STATE_MACHINE = 101;
enum BIO_C_SET_NBIO = 102;
enum BIO_C_SET_PROXY_PARAM = 103;
enum BIO_C_SET_FD = 104;
enum BIO_C_GET_FD = 105;
enum BIO_C_SET_FILE_PTR = 106;
enum BIO_C_GET_FILE_PTR = 107;
enum BIO_C_SET_FILENAME = 108;
enum BIO_C_SET_SSL = 109;
enum BIO_C_GET_SSL = 110;
enum BIO_C_SET_MD = 111;
enum BIO_C_GET_MD = 112;
enum BIO_C_GET_CIPHER_STATUS = 113;
enum BIO_C_SET_BUF_MEM = 114;
enum BIO_C_GET_BUF_MEM_PTR = 115;
enum BIO_C_GET_BUFF_NUM_LINES = 116;
enum BIO_C_SET_BUFF_SIZE = 117;
enum BIO_C_SET_ACCEPT = 118;
enum BIO_C_SSL_MODE = 119;
enum BIO_C_GET_MD_CTX = 120;
enum BIO_C_GET_PROXY_PARAM = 121;

/**
 *  data to read first
 */
enum BIO_C_SET_BUFF_READ_DATA = 122;

enum BIO_C_GET_CONNECT = 123;
enum BIO_C_GET_ACCEPT = 124;
enum BIO_C_SET_SSL_RENEGOTIATE_BYTES = 125;
enum BIO_C_GET_SSL_NUM_RENEGOTIATES = 126;
enum BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT = 127;
enum BIO_C_FILE_SEEK = 128;
enum BIO_C_GET_CIPHER_CTX = 129;

/**
 * return end of input value
 */
enum BIO_C_SET_BUF_MEM_EOF_RETURN = 130;

enum BIO_C_SET_BIND_MODE = 131;
enum BIO_C_GET_BIND_MODE = 132;
enum BIO_C_FILE_TELL = 133;
enum BIO_C_GET_SOCKS = 134;
enum BIO_C_SET_SOCKS = 135;

/**
 *  for BIO_s_bio
 */
enum BIO_C_SET_WRITE_BUF_SIZE = 136;

enum BIO_C_GET_WRITE_BUF_SIZE = 137;
enum BIO_C_MAKE_BIO_PAIR = 138;
enum BIO_C_DESTROY_BIO_PAIR = 139;
enum BIO_C_GET_WRITE_GUARANTEE = 140;
enum BIO_C_GET_READ_REQUEST = 141;
enum BIO_C_SHUTDOWN_WR = 142;
enum BIO_C_NREAD0 = 143;
enum BIO_C_NREAD = 144;
enum BIO_C_NWRITE0 = 145;
enum BIO_C_NWRITE = 146;
enum BIO_C_RESET_READ_REQUEST = 147;
enum BIO_C_SET_MD_CTX = 148;

enum BIO_C_SET_PREFIX = 149;
enum BIO_C_GET_PREFIX = 150;
enum BIO_C_SET_SUFFIX = 151;
enum BIO_C_GET_SUFFIX = 152;

enum BIO_C_SET_EX_ARG = 153;
enum BIO_C_GET_EX_ARG = 154;

//#define BIO_set_app_data(s, arg) .BIO_set_ex_data(s, 0, arg)
//#define BIO_get_app_data(s) .BIO_get_ex_data(s, 0)

/* BIO_s_connect() and BIO_s_socks4a_connect() */
//#define BIO_set_conn_hostname(b, name) .BIO_ctrl(b, .BIO_C_SET_CONNECT, 0, cast(char*)(name))
//#define BIO_set_conn_port(b, port) .BIO_ctrl(b, .BIO_C_SET_CONNECT, 1, cast(char*)(port))
//#define BIO_set_conn_ip(b, ip) .BIO_ctrl(b, .BIO_C_SET_CONNECT, 2, cast(char*)(ip))
//#define BIO_set_conn_int_port(b, port) .BIO_ctrl(b, .BIO_C_SET_CONNECT, 3, cast(char*)(port))
//#define BIO_get_conn_hostname(b) .BIO_ptr_ctrl(b, .BIO_C_GET_CONNECT, 0)
//#define BIO_get_conn_port(b) .BIO_ptr_ctrl(b, .BIO_C_GET_CONNECT, 1)
//#define BIO_get_conn_ip(b) .BIO_ptr_ctrl(b, .BIO_C_GET_CONNECT, 2)
//#define BIO_get_conn_int_port(b) .BIO_int_ctrl(b, .BIO_C_GET_CONNECT, 3, 0)

//#define BIO_set_nbio(b, n) .BIO_ctrl(b, .BIO_C_SET_NBIO, n, null)

/* BIO_s_accept_socket() */
//#define BIO_set_accept_port(b, name) .BIO_ctrl(b, .BIO_C_SET_ACCEPT, 0, cast(char*)(name))
//#define BIO_get_accept_port(b) .BIO_ptr_ctrl(b, .BIO_C_GET_ACCEPT, 0)
/* #define BIO_set_nbio(b,n)	.BIO_ctrl(b,.BIO_C_SET_NBIO,n,null) */
//#define BIO_set_nbio_accept(b, n) .BIO_ctrl(b, .BIO_C_SET_ACCEPT, 1, (n) ? ((void*) "a") : (null))
//#define BIO_set_accept_bios(b, bio) .BIO_ctrl(b, .BIO_C_SET_ACCEPT, 2, cast(char*)(bio))

enum BIO_BIND_NORMAL = 0;
enum BIO_BIND_REUSEADDR_IF_UNUSED = 1;
enum BIO_BIND_REUSEADDR = 2;
//#define BIO_set_bind_mode(b, mode) .BIO_ctrl(b, .BIO_C_SET_BIND_MODE, mode, null)
//#define BIO_get_bind_mode(b, mode) .BIO_ctrl(b, .BIO_C_GET_BIND_MODE, 0, null)

//#define BIO_do_connect(b) .BIO_do_handshake(b)
//#define BIO_do_accept(b) .BIO_do_handshake(b)
//#define BIO_do_handshake(b) .BIO_ctrl(b, .BIO_C_DO_STATE_MACHINE, 0, null)

/* BIO_s_proxy_client() */
//#define BIO_set_url(b, url) .BIO_ctrl(b, .BIO_C_SET_PROXY_PARAM, 0, cast(char*)(url))
//#define BIO_set_proxies(b, p) .BIO_ctrl(b, .BIO_C_SET_PROXY_PARAM, 1, cast(char*)(p))
/* BIO_set_nbio(b,n) */
//#define BIO_set_filter_bio(b, s) .BIO_ctrl(b, .BIO_C_SET_PROXY_PARAM, 2, cast(char*)(s))
/* .BIO* IO_get_filter_bio(.BIO* io); */
//#define BIO_set_proxy_cb(b, cb) .BIO_callback_ctrl(b, .BIO_C_SET_PROXY_PARAM, 3, (void* function() cb))
//#define BIO_set_proxy_header(b, sk) .BIO_ctrl(b, .BIO_C_SET_PROXY_PARAM, 4, cast(char*)(sk))
//#define BIO_set_no_connect_return(b, bool) .BIO_int_ctrl(b, .BIO_C_SET_PROXY_PARAM, 5, bool)

//#define BIO_get_proxy_header(b, skp) .BIO_ctrl(b, .BIO_C_GET_PROXY_PARAM, 0, cast(char*)(skp))
//#define BIO_get_proxies(b, pxy_p) .BIO_ctrl(b, .BIO_C_GET_PROXY_PARAM, 1, cast(char*)(pxy_p))
//#define BIO_get_url(b, url) .BIO_ctrl(b, .BIO_C_GET_PROXY_PARAM, 2, cast(char*)(url))
//#define BIO_get_no_connect_return(b) .BIO_ctrl(b, .BIO_C_GET_PROXY_PARAM, 5, null)

//#define BIO_set_fd(b, fd, c) .BIO_int_ctrl(b, .BIO_C_SET_FD, c, fd)
//#define BIO_get_fd(b, c) .BIO_ctrl(b, .BIO_C_GET_FD, 0, cast(char*)(c))

//#define BIO_set_fp(b, fp, c) .BIO_ctrl(b, .BIO_C_SET_FILE_PTR, c, cast(char*)(fp))
//#define BIO_get_fp(b, fpp) .BIO_ctrl(b, .BIO_C_GET_FILE_PTR, 0, cast(char*)(fpp))

//#define BIO_seek(b, ofs) cast(int)(.BIO_ctrl(b, .BIO_C_FILE_SEEK, ofs, null))
//#define BIO_tell(b) cast(int)(.BIO_ctrl(b, .BIO_C_FILE_TELL, 0, null))

/*
 * name is cast to lose const, but might be better to route through a function
 * so we can do it safely
 */
//#define BIO_read_filename(b, name) .BIO_ctrl(b, .BIO_C_SET_FILENAME, .BIO_CLOSE | .BIO_FP_READ, cast(char*)(name))
//#define BIO_write_filename(b, name) .BIO_ctrl(b, .BIO_C_SET_FILENAME, .BIO_CLOSE | .BIO_FP_WRITE, name)
//#define BIO_append_filename(b, name) .BIO_ctrl(b, .BIO_C_SET_FILENAME, .BIO_CLOSE | .BIO_FP_APPEND, name)
//#define BIO_rw_filename(b, name) .BIO_ctrl(b, .BIO_C_SET_FILENAME, .BIO_CLOSE | .BIO_FP_READ | .BIO_FP_WRITE, name)

/*
 * WARNING WARNING, this ups the reference count on the read bio of the
 * SSL structure.  This is because the ssl read BIO is now pointed to by
 * the next_bio field in the bio.  So when you free the BIO, make sure
 * you are doing a BIO_free_all() to catch the underlying BIO.
 */
//#define BIO_set_ssl(b, ssl, c) .BIO_ctrl(b, .BIO_C_SET_SSL, c, cast(char*)(ssl))
//#define BIO_get_ssl(b, sslp) .BIO_ctrl(b, .BIO_C_GET_SSL, 0, cast(char*)(sslp))
//#define BIO_set_ssl_mode(b, client) .BIO_ctrl(b, .BIO_C_SSL_MODE, client, null)
//#define BIO_set_ssl_renegotiate_bytes(b, num) .BIO_ctrl(b, .BIO_C_SET_SSL_RENEGOTIATE_BYTES, num, null)
//#define BIO_get_num_renegotiates(b) .BIO_ctrl(b, .BIO_C_GET_SSL_NUM_RENEGOTIATES, 0, null)
//#define BIO_set_ssl_renegotiate_timeout(b, seconds) .BIO_ctrl(b, .BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT, seconds, null)

/* defined in evp.h */
/* #define BIO_set_md(b,md)	.BIO_ctrl(b,.BIO_C_SET_MD,1,(char *)md) */

//#define BIO_get_mem_data(b, pp) .BIO_ctrl(b, .BIO_CTRL_INFO, 0, cast(char*)(pp))
//#define BIO_set_mem_buf(b, bm, c) .BIO_ctrl(b, .BIO_C_SET_BUF_MEM, c, cast(char*)(bm))
//#define BIO_get_mem_ptr(b, pp) .BIO_ctrl(b, .BIO_C_GET_BUF_MEM_PTR, 0, cast(char*)(pp))
//#define BIO_set_mem_eof_return(b, v) .BIO_ctrl(b, .BIO_C_SET_BUF_MEM_EOF_RETURN, v, null)

/* For the BIO_f_buffer() type */
//#define BIO_get_buffer_num_lines(b) .BIO_ctrl(b, .BIO_C_GET_BUFF_NUM_LINES, 0, null)
//#define BIO_set_buffer_size(b, size) .BIO_ctrl(b, .BIO_C_SET_BUFF_SIZE, size, null)
//#define BIO_set_read_buffer_size(b, size) .BIO_int_ctrl(b, .BIO_C_SET_BUFF_SIZE, size, 0)
//#define BIO_set_write_buffer_size(b, size) .BIO_int_ctrl(b, .BIO_C_SET_BUFF_SIZE, size, 1)
//#define BIO_set_buffer_read_data(b, buf, num) .BIO_ctrl(b, .BIO_C_SET_BUFF_READ_DATA, num, buf)

/* Don't use the next one unless you know what you are doing :-) */
//#define BIO_dup_state(b, ret) .BIO_ctrl(b, .BIO_CTRL_DUP, 0, cast(char*)(ret))

//#define BIO_reset(b) cast(int)(.BIO_ctrl(b, .BIO_CTRL_RESET, 0, null))
//#define BIO_eof(b) cast(int)(.BIO_ctrl(b, .BIO_CTRL_EOF, 0, null))
//#define BIO_set_close(b, c) cast(int)(.BIO_ctrl(b, .BIO_CTRL_SET_CLOSE, c, null))
//#define BIO_get_close(b) cast(int)(.BIO_ctrl(b, .BIO_CTRL_GET_CLOSE, 0, null))
//#define BIO_pending(b) cast(int)(.BIO_ctrl(b, .BIO_CTRL_PENDING, 0, null))
//#define BIO_wpending(b) cast(int)(.BIO_ctrl(b, .BIO_CTRL_WPENDING, 0, null))
/* ...pending macros have inappropriate return type */
size_t BIO_ctrl_pending(.BIO* b);
size_t BIO_ctrl_wpending(.BIO* b);
//#define BIO_flush(b) cast(int)(.BIO_ctrl(b, .BIO_CTRL_FLUSH, 0, null))
//#define BIO_get_info_callback(b, cbp) cast(int)(.BIO_ctrl(b, .BIO_CTRL_GET_CALLBACK, 0, cbp))
//#define BIO_set_info_callback(b, cb) cast(int)(.BIO_callback_ctrl(b, .BIO_CTRL_SET_CALLBACK, cb))

/* For the BIO_f_buffer() type */
//#define BIO_buffer_get_num_lines(b) .BIO_ctrl(b, .BIO_CTRL_GET, 0, null)

/* For BIO_s_bio() */
//#define BIO_set_write_buf_size(b, size) cast(int)(.BIO_ctrl(b, .BIO_C_SET_WRITE_BUF_SIZE, size, null))
//#define BIO_get_write_buf_size(b, size) cast(size_t)(.BIO_ctrl(b, .BIO_C_GET_WRITE_BUF_SIZE, size, null))
//#define BIO_make_bio_pair(b1, b2) cast(int)(.BIO_ctrl(b1, .BIO_C_MAKE_BIO_PAIR, 0, b2))
//#define BIO_destroy_bio_pair(b) cast(int)(.BIO_ctrl(b, .BIO_C_DESTROY_BIO_PAIR, 0, null))
//#define BIO_shutdown_wr(b) cast(int)(.BIO_ctrl(b, .BIO_C_SHUTDOWN_WR, 0, null))
/* macros with inappropriate type -- but ...pending macros use int too: */
//#define BIO_get_write_guarantee(b) cast(int)(.BIO_ctrl(b, .BIO_C_GET_WRITE_GUARANTEE, 0, null))
//#define BIO_get_read_request(b) cast(int)(.BIO_ctrl(b, .BIO_C_GET_READ_REQUEST, 0, null))
size_t BIO_ctrl_get_write_guarantee(.BIO* b);
size_t BIO_ctrl_get_read_request(.BIO* b);
int BIO_ctrl_reset_read_request(.BIO* b);

/* ctrl macros for dgram */
//#define BIO_ctrl_dgram_connect(b, peer) cast(int)(.BIO_ctrl(b, .BIO_CTRL_DGRAM_CONNECT, 0, cast(char*)(peer)))
//#define BIO_ctrl_set_connected(b, state, peer) cast(int)(.BIO_ctrl(b, .BIO_CTRL_DGRAM_SET_CONNECTED, state, cast(char*)(peer)))
//#define BIO_dgram_recv_timedout(b) cast(int)(.BIO_ctrl(b, .BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, null))
//#define BIO_dgram_send_timedout(b) cast(int)(.BIO_ctrl(b, .BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP, 0, null))
//#define BIO_dgram_get_peer(b, peer) cast(int)(.BIO_ctrl(b, .BIO_CTRL_DGRAM_GET_PEER, 0, cast(char*)(peer)))
//#define BIO_dgram_set_peer(b, peer) cast(int)(.BIO_ctrl(b, .BIO_CTRL_DGRAM_SET_PEER, 0, cast(char*)(peer)))

/* These two aren't currently implemented */
/* int BIO_get_ex_num(.BIO* io); */
/* void BIO_set_ex_free_func(.BIO* io,int idx,void function() cb); */
int BIO_set_ex_data(.BIO* bio, int idx, void* data);
void* BIO_get_ex_data(.BIO* bio, int idx);
int BIO_get_ex_new_index(core.stdc.config.c_long argl, void* argp, libressl_d.openssl.ossl_typ.CRYPTO_EX_new* new_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_dup* dup_func, libressl_d.openssl.ossl_typ.CRYPTO_EX_free* free_func);
core.stdc.config.c_ulong BIO_number_read(.BIO* bio);
core.stdc.config.c_ulong BIO_number_written(.BIO* bio);

/* For BIO_f_asn1() */
int BIO_asn1_set_prefix(.BIO* b, .asn1_ps_func* prefix, .asn1_ps_func* prefix_free);
int BIO_asn1_get_prefix(.BIO* b, .asn1_ps_func** pprefix, .asn1_ps_func** pprefix_free);
int BIO_asn1_set_suffix(.BIO* b, .asn1_ps_func* suffix, .asn1_ps_func* suffix_free);
int BIO_asn1_get_suffix(.BIO* b, .asn1_ps_func** psuffix, .asn1_ps_func** psuffix_free);

int BIO_get_new_index();
const (.BIO_METHOD)* BIO_s_file();
.BIO* BIO_new_file(const (char)* filename, const (char)* mode);
.BIO* BIO_new_fp(libressl_d.compat.stdio.FILE* stream, int close_flag);
alias BIO_s_file_internal = .BIO_s_file;
.BIO* BIO_new(const (.BIO_METHOD)* type);
int BIO_set(.BIO* a, const (.BIO_METHOD)* type);
int BIO_free(.BIO* a);
int BIO_up_ref(.BIO* bio);
void* BIO_get_data(.BIO* a);
void BIO_set_data(.BIO* a, void* ptr_);
void BIO_set_init(.BIO* a, int init);
int BIO_get_shutdown(.BIO* a);
void BIO_set_shutdown(.BIO* a, int shut);
void BIO_vfree(.BIO* a);

/+
//__attribute__((__bounded__(__buffer__, 2, 3)));
int BIO_read(.BIO* b, void* data, int len)
+/

/+
//__attribute__((__bounded__(__string__, 2, 3)));
int BIO_gets(.BIO* bp, char* buf, int size)
+/

/+
//__attribute__((__bounded__(__buffer__, 2, 3)));
int BIO_write(.BIO* b, const (void)* data, int len)
+/

int BIO_puts(.BIO* bp, const (char)* buf);
int BIO_indent(.BIO* b, int indent, int max);
core.stdc.config.c_long BIO_ctrl(.BIO* bp, int cmd, core.stdc.config.c_long larg, void* parg);
core.stdc.config.c_long BIO_callback_ctrl(.BIO* b, int cmd, void function(.bio_st*, int, const (char)*, int, core.stdc.config.c_long, core.stdc.config.c_long) fp);
char* BIO_ptr_ctrl(.BIO* bp, int cmd, core.stdc.config.c_long larg);
core.stdc.config.c_long BIO_int_ctrl(.BIO* bp, int cmd, core.stdc.config.c_long larg, int iarg);
.BIO* BIO_push(.BIO* b, .BIO* append);
.BIO* BIO_pop(.BIO* b);
void BIO_free_all(.BIO* a);
.BIO* BIO_find_type(.BIO* b, int bio_type);
.BIO* BIO_next(.BIO* b);
.BIO* BIO_get_retry_BIO(.BIO* bio, int* reason);
int BIO_get_retry_reason(.BIO* bio);
.BIO* BIO_dup_chain(.BIO* in_);

int BIO_nread0(.BIO* bio, char** buf);
int BIO_nread(.BIO* bio, char** buf, int num);
int BIO_nwrite0(.BIO* bio, char** buf);
int BIO_nwrite(.BIO* bio, char** buf, int num);

core.stdc.config.c_long BIO_debug_callback(.BIO* bio, int cmd, const (char)* argp, int argi, core.stdc.config.c_long argl, core.stdc.config.c_long ret);

const (.BIO_METHOD)* BIO_s_mem();
.BIO* BIO_new_mem_buf(const (void)* buf, int len);
const (.BIO_METHOD)* BIO_s_socket();
const (.BIO_METHOD)* BIO_s_connect();
const (.BIO_METHOD)* BIO_s_accept();
const (.BIO_METHOD)* BIO_s_fd();
const (.BIO_METHOD)* BIO_s_log();
const (.BIO_METHOD)* BIO_s_bio();
const (.BIO_METHOD)* BIO_s_null();
const (.BIO_METHOD)* BIO_f_null();
const (.BIO_METHOD)* BIO_f_buffer();
const (.BIO_METHOD)* BIO_f_nbio_test();

//#if !defined(OPENSSL_NO_DGRAM)
const (.BIO_METHOD)* BIO_s_datagram();
//#endif

/* BIO_METHOD* IO_f_ber(); */

int BIO_sock_should_retry(int i);
int BIO_sock_non_fatal_error(int _error);
int BIO_dgram_non_fatal_error(int _error);

int BIO_fd_should_retry(int i);
int BIO_fd_non_fatal_error(int _error);
int BIO_dump_cb(int function(const (void)* data, size_t len, void* u) cb, void* u, const (char)* s, int len);
int BIO_dump_indent_cb(int function(const (void)* data, size_t len, void* u) cb, void* u, const (char)* s, int len, int indent);
int BIO_dump(.BIO* b, const (char)* bytes, int len);
int BIO_dump_indent(.BIO* b, const (char)* bytes, int len, int indent);
int BIO_dump_fp(libressl_d.compat.stdio.FILE* fp, const (char)* s, int len);
int BIO_dump_indent_fp(libressl_d.compat.stdio.FILE* fp, const (char)* s, int len, int indent);
libressl_d.compat.netdb.hostent* BIO_gethostbyname(const (char)* name);
/*
 * We might want a thread-safe interface too:
 * hostent* IO_gethostbyname_r(const (char)* name, hostent* esult, void* uffer, size_t buflen);
 * or something similar (caller allocates a struct hostent,
 * pointed to by "result", and additional buffer space for the various
 * substructures; if the buffer does not suffice, null is returned
 * and an appropriate error code is set).
 */
int BIO_sock_error(int sock);
int BIO_socket_ioctl(int fd, core.stdc.config.c_long type, void* arg);
int BIO_socket_nbio(int fd, int mode);
int BIO_get_port(const (char)* str, ushort* port_ptr);
int BIO_get_host_ip(const (char)* str, ubyte* ip);
int BIO_get_accept_socket(char* host_port, int mode);
int BIO_accept(int sock, char** ip_port);
int BIO_sock_init();
void BIO_sock_cleanup();
int BIO_set_tcp_ndelay(int sock, int turn_on);

.BIO* BIO_new_socket(int sock, int close_flag);
.BIO* BIO_new_dgram(int fd, int close_flag);
.BIO* BIO_new_fd(int fd, int close_flag);
.BIO* BIO_new_connect(const (char)* host_port);
.BIO* BIO_new_accept(const (char)* host_port);

int BIO_new_bio_pair(.BIO** bio1, size_t writebuf1, .BIO** bio2, size_t writebuf2);
/*
 * If successful, returns 1 and in *bio1, *bio2 two BIO pair endpoints.
 * Otherwise returns 0 and sets *bio1 and *bio2 to null.
 * Size 0 uses default value.
 */

void BIO_copy_next_retry(.BIO* b);

/*core.stdc.config.c_long BIO_ghbn_ctrl(int cmd, int iarg, char* arg); */

//#if defined(__MINGW_PRINTF_FORMAT)
	/+
	//__attribute__((__format__(__MINGW_PRINTF_FORMAT, 2, 3), __nonnull__(2)));
	int BIO_printf(.BIO* bio, const (char)* format, ...)
	+/

	/+
	//__attribute__((__format__(__MINGW_PRINTF_FORMAT, 2, 0), __nonnull__(2)));
	int BIO_vprintf(.BIO* bio, const (char)* format, core.stdc.stdarg.va_list args)
	+/

	/+
	//__attribute__((__deprecated__, __format__(__MINGW_PRINTF_FORMAT, 3, 4), __nonnull__(3)));
	int BIO_snprintf(char* buf, size_t n, const (char)* format, ...)
	+/

	/+
	//__attribute__((__deprecated__, __format__(__MINGW_PRINTF_FORMAT, 3, 0), __nonnull__(3)));
	int BIO_vsnprintf(char* buf, size_t n, const (char)* format, core.stdc.stdarg.va_list args)
	+/
//#else
	/+
	//__attribute__((__format__(__printf__, 2, 3), __nonnull__(2)));
	int BIO_printf(.BIO* bio, const (char)* format, ...)
	+/

	/+
	//__attribute__((__format__(__printf__, 2, 0), __nonnull__(2)));
	int BIO_vprintf(.BIO* bio, const (char)* format, core.stdc.stdarg.va_list args)
	+/

	/+
	//__attribute__((__deprecated__, __format__(__printf__, 3, 4), __nonnull__(3)));
	int BIO_snprintf(char* buf, size_t n, const (char)* format, ...)
	+/

	/+
	//__attribute__((__deprecated__, __format__(__printf__, 3, 0), __nonnull__(3)));
	int BIO_vsnprintf(char* buf, size_t n, const (char)* format, core.stdc.stdarg.va_list args)
	+/
//#endif

/* BEGIN ERROR CODES */
/**
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_BIO_strings();

/* Error codes for the BIO functions. */

/* Function codes. */
enum BIO_F_ACPT_STATE = 100;
enum BIO_F_BIO_ACCEPT = 101;
enum BIO_F_BIO_BER_GET_HEADER = 102;
enum BIO_F_BIO_CALLBACK_CTRL = 131;
enum BIO_F_BIO_CTRL = 103;
enum BIO_F_BIO_GETHOSTBYNAME = 120;
enum BIO_F_BIO_GETS = 104;
enum BIO_F_BIO_GET_ACCEPT_SOCKET = 105;
enum BIO_F_BIO_GET_HOST_IP = 106;
enum BIO_F_BIO_GET_PORT = 107;
enum BIO_F_BIO_MAKE_PAIR = 121;
enum BIO_F_BIO_NEW = 108;
enum BIO_F_BIO_NEW_FILE = 109;
enum BIO_F_BIO_NEW_MEM_BUF = 126;
enum BIO_F_BIO_NREAD = 123;
enum BIO_F_BIO_NREAD0 = 124;
enum BIO_F_BIO_NWRITE = 125;
enum BIO_F_BIO_NWRITE0 = 122;
enum BIO_F_BIO_PUTS = 110;
enum BIO_F_BIO_READ = 111;
enum BIO_F_BIO_SOCK_INIT = 112;
enum BIO_F_BIO_WRITE = 113;
enum BIO_F_BUFFER_CTRL = 114;
enum BIO_F_CONN_CTRL = 127;
enum BIO_F_CONN_STATE = 115;
enum BIO_F_DGRAM_SCTP_READ = 132;
enum BIO_F_FILE_CTRL = 116;
enum BIO_F_FILE_READ = 130;
enum BIO_F_LINEBUFFER_CTRL = 129;
enum BIO_F_MEM_READ = 128;
enum BIO_F_MEM_WRITE = 117;
enum BIO_F_SSL_NEW = 118;
enum BIO_F_WSASTARTUP = 119;

/* Reason codes. */
enum BIO_R_ACCEPT_ERROR = 100;
enum BIO_R_BAD_FOPEN_MODE = 101;
enum BIO_R_BAD_HOSTNAME_LOOKUP = 102;
enum BIO_R_BROKEN_PIPE = 124;
enum BIO_R_CONNECT_ERROR = 103;
enum BIO_R_EOF_ON_MEMORY_BIO = 127;
enum BIO_R_ERROR_SETTING_NBIO = 104;
enum BIO_R_ERROR_SETTING_NBIO_ON_ACCEPTED_SOCKET = 105;
enum BIO_R_ERROR_SETTING_NBIO_ON_ACCEPT_SOCKET = 106;
enum BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET = 107;
enum BIO_R_INVALID_ARGUMENT = 125;
enum BIO_R_INVALID_IP_ADDRESS = 108;
enum BIO_R_INVALID_PORT_NUMBER = 129;
enum BIO_R_IN_USE = 123;
enum BIO_R_KEEPALIVE = 109;
enum BIO_R_NBIO_CONNECT_ERROR = 110;
enum BIO_R_NO_ACCEPT_PORT_SPECIFIED = 111;
enum BIO_R_NO_HOSTNAME_SPECIFIED = 112;
enum BIO_R_NO_PORT_DEFINED = 113;
enum BIO_R_NO_PORT_SPECIFIED = 114;
enum BIO_R_NO_SUCH_FILE = 128;
enum BIO_R_NULL_PARAMETER = 115;
enum BIO_R_TAG_MISMATCH = 116;
enum BIO_R_UNABLE_TO_BIND_SOCKET = 117;
enum BIO_R_UNABLE_TO_CREATE_SOCKET = 118;
enum BIO_R_UNABLE_TO_LISTEN_SOCKET = 119;
enum BIO_R_UNINITIALIZED = 120;
enum BIO_R_UNSUPPORTED_METHOD = 121;
enum BIO_R_WRITE_TO_READ_ONLY_BIO = 126;
enum BIO_R_WSASTARTUP = 122;
