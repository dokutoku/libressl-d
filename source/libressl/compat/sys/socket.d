/*
 * Public domain
 * sys/socket.h compatibility shim
 */
module libressl.compat.sys.socket;


public import core.sys.dragonflybsd.sys.socket;
public import core.sys.linux.sys.socket;
public import core.sys.posix.sys.socket;
public import libressl.compat.win32netcompat;

extern (C):
nothrow @nogc:

version (Posix) {
} else {
	//#define NEED_SOCKET_FLAGS

	/**
	 * set FD_CLOEXEC
	 */
	enum SOCK_CLOEXEC = 0x8000;

	/**
	 * set O_NONBLOCK
	 */
	enum SOCK_NONBLOCK = 0x4000;
}

version (none) {
	int bsd_socketpair(int domain, int type, int protocol, int* socket_vector);

	pragma(inline, true)
	nothrow @nogc
	int socketpair(int d, int t, int p, int sv)

		do
		{
			return .bsd_socketpair(d, t, p, sv);
		}
}
