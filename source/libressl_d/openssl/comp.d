/* $OpenBSD: comp.h,v 1.9 2022/01/14 08:21:12 tb Exp $ */
module libressl_d.openssl.comp;


private static import libressl_d.openssl.ossl_typ;
private static import libressl_d.openssl.bio;
public import libressl_d.openssl.crypto;

extern (C):
nothrow @nogc:

libressl_d.openssl.ossl_typ.COMP_CTX* COMP_CTX_new(libressl_d.openssl.ossl_typ.COMP_METHOD* meth);
void COMP_CTX_free(libressl_d.openssl.ossl_typ.COMP_CTX* ctx);
int COMP_compress_block(libressl_d.openssl.ossl_typ.COMP_CTX* ctx, ubyte* out_, int olen, ubyte* in_, int ilen);
int COMP_expand_block(libressl_d.openssl.ossl_typ.COMP_CTX* ctx, ubyte* out_, int olen, ubyte* in_, int ilen);
libressl_d.openssl.ossl_typ.COMP_METHOD* COMP_rle();
libressl_d.openssl.ossl_typ.COMP_METHOD* COMP_zlib();
void COMP_zlib_cleanup();

static assert(libressl_d.openssl.bio.HEADER_BIO_H);

version (ZLIB) {
	libressl_d.openssl.bio.BIO_METHOD* BIO_f_zlib();
}

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
