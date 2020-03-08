/* $OpenBSD: comp.h,v 1.8 2014/11/03 16:58:28 tedu Exp $ */
module libressl_d.openssl.comp;


private static import core.stdc.config;
private static import libressl_d.openssl.ossl_typ;
private static import libressl_d.openssl.bio;
public import libressl_d.openssl.crypto;

extern (C):
nothrow @nogc:

alias COMP_CTX = .comp_ctx_st;

struct comp_method_st
{
	/**
	 * NID for compression library
	 */
	int type;

	/**
	 * A text string to identify the library
	 */
	const (char)* name;

	int function(.COMP_CTX* ctx) init;
	void function(.COMP_CTX* ctx) finish;
	int function(.COMP_CTX* ctx, ubyte* out_, uint olen, ubyte* in_, uint ilen) compress;
	int function(.COMP_CTX* ctx, ubyte* out_, uint olen, ubyte* in_, uint ilen) expand;
	/* The following two do NOTHING, but are kept for backward compatibility */
	core.stdc.config.c_long function() ctrl;
	core.stdc.config.c_long function() callback_ctrl;
}

alias COMP_METHOD = .comp_method_st;

struct comp_ctx_st
{
	.COMP_METHOD* meth;
	core.stdc.config.c_ulong compress_in;
	core.stdc.config.c_ulong compress_out;
	core.stdc.config.c_ulong expand_in;
	core.stdc.config.c_ulong expand_out;

	libressl_d.openssl.ossl_typ.CRYPTO_EX_DATA ex_data;
}

.COMP_CTX* COMP_CTX_new(.COMP_METHOD* meth);
void COMP_CTX_free(.COMP_CTX* ctx);
int COMP_compress_block(.COMP_CTX* ctx, ubyte* out_, int olen, ubyte* in_, int ilen);
int COMP_expand_block(.COMP_CTX* ctx, ubyte* out_, int olen, ubyte* in_, int ilen);
.COMP_METHOD* COMP_rle();
.COMP_METHOD* COMP_zlib();
void COMP_zlib_cleanup();

//#if defined(HEADER_BIO_H)
//	#if defined(ZLIB)
//		libressl_d.openssl.bio.BIO_METHOD* BIO_f_zlib();
//	#endif
//#endif

void ERR_load_COMP_strings();

/* Error codes for the COMP functions. */

/* Function codes. */
enum COMP_F_BIO_ZLIB_FLUSH = 99;
enum COMP_F_BIO_ZLIB_NEW = 100;
enum COMP_F_BIO_ZLIB_READ = 101;
enum COMP_F_BIO_ZLIB_WRITE = 102;

/* Reason codes. */
enum COMP_R_ZLIB_DEFLATE_ERROR = 99;
enum COMP_R_ZLIB_INFLATE_ERROR = 100;
enum COMP_R_ZLIB_NOT_SUPPORTED = 101;
