/* $OpenBSD: opensslv.h,v 1.55 2019/10/10 14:29:20 bcook Exp $ */
/**
 * These will change with each release of LibreSSL-portable
 */
module libressl_d.openssl.opensslv;


enum LIBRESSL_VERSION_NUMBER = 0x3000200FL;

/**
 * ^ Patch starts here
 */
enum LIBRESSL_VERSION_TEXT = "LibreSSL 3.0.2";

/* These will never change */
enum OPENSSL_VERSION_NUMBER = 0x20000000L;
enum OPENSSL_VERSION_TEXT = .LIBRESSL_VERSION_TEXT;
enum OPENSSL_VERSION_PTEXT = " part of " ~ .OPENSSL_VERSION_TEXT;

enum SHLIB_VERSION_HISTORY = "";
enum SHLIB_VERSION_NUMBER = "1.0.0";
