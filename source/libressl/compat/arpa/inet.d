/*
 * Public domain
 * arpa/inet.h compatibility shim
 */
module libressl.compat.arpa.inet;


public import core.sys.posix.arpa.inet;
public import libressl.compat.win32netcompat;

version (Windows) {
	enum AI_ADDRCONFIG = 0x00000400;
}
