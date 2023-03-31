/*
 * Public domain
 * arpa/inet.h compatibility shim
 */
module libressl.compat.arpa.nameser;


//public import core.sys.posix.arpa.nameser;
public import libressl.compat.win32netcompat;

version (Windows) {
	enum INADDRSZ = 4;
	enum IN6ADDRSZ = 16;
	enum INT16SZ = 2;
}
