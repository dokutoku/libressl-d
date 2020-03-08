/*
 * Public domain
 * sys/socket.h compatibility shim
 */
module libressl_d.compat.sys.socket;


public import core.sys.posix.sys.socket;
public import libressl_d.compat.win32netcompat;

version (Posix) {
} else {
	/**
	 *  set FD_CLOEXEC
	 */
	enum SOCK_CLOEXEC = 0x8000;

	/**
	 *  set O_NONBLOCK
	 */
	enum SOCK_NONBLOCK = 0x4000;
}

version (none) {
	int bsd_socketpair(int domain, int type, int protocol, int[2] socket_vector);

	pragma(inline, true)
	nothrow @nogc
	int socketpair(int d, int t, int p, int sv)

		do
		{
			return .bsd_socketpair(d, t, p, sv);
		}
}
