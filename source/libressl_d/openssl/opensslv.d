/* $OpenBSD: opensslv.h,v 1.63 2020/12/08 17:39:06 bcook Exp $ */
/**
 * These will change with each release of LibreSSL-portable
 */
module libressl_d.openssl.opensslv;


enum LIBRESSL_VERSION_NUMBER = 0x03030100FL;

/**
 * ^ Patch starts here
 */
enum LIBRESSL_VERSION_TEXT = "LibreSSL 3.3.1";

/* These will never change */
enum OPENSSL_VERSION_NUMBER = 0x20000000L;
enum OPENSSL_VERSION_TEXT = .LIBRESSL_VERSION_TEXT;
enum OPENSSL_VERSION_PTEXT = " part of " ~ .OPENSSL_VERSION_TEXT;

enum SHLIB_VERSION_HISTORY = "";
enum SHLIB_VERSION_NUMBER = "1.0.0";
