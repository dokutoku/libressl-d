/*
 * Public domain
 * netinet/in.h compatibility shim
 */
module libressl.compat.netinet.in_;


private static import core.stdc.stdint;
public import core.sys.darwin.netinet.in_;
public import core.sys.dragonflybsd.netinet.in_;
public import core.sys.freebsd.netinet.in_;
public import core.sys.linux.netinet.in_;
public import core.sys.posix.netinet.in_;
public import libressl.compat.win32netcompat;

version (Android) {
	alias in_port_t = core.stdc.stdint.uint16_t;
}
