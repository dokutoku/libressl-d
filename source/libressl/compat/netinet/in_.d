/*
 * Public domain
 * netinet/in.h compatibility shim
 */
module libressl.compat.netinet.in_;


private static import core.stdc.stdint;
public import core.sys.posix.netinet.in_;
public import libressl.compat.win32netcompat;

version (Android) {
	alias in_port_t = core.stdc.stdint.core.stdc.stdint.uint16_t;
}
