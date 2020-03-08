/*
 * Public domain
 * arpa/inet.h compatibility shim
 */
module libressl_d.compat.arpa.inet;


public import core.sys.posix.arpa.inet;
public import libressl_d.compat.win32netcompat;

version (Windows) {
	enum AI_ADDRCONFIG = 0x00000400;
}
