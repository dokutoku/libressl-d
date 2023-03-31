/*
 * Public domain
 * sys/ioctl.h compatibility shim
 */
module libressl.compat.sys.ioctl;


public import core.sys.posix.sys.ioctl;
public import libressl.compat.win32netcompat;

version (Windows) {
	alias ioctl = libressl.compat.win32netcompat.ioctlsocket;
}
