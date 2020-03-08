/*
 * Public domain
 * sys/ioctl.h compatibility shim
 */
module libressl_d.compat.sys.ioctl;


public import core.sys.posix.sys.ioctl;
public import libressl_d.compat.win32netcompat;

version (Windows) {
	alias ioctl = core.sys.windows.winsock2.ioctlsocket;
}
