/*
 * Public domain
 *
 * BSD socket emulation code for Winsock2
 * Brent Cook <bcook@openbsd.org>
 */
module libressl.compat.win32netcompat;


//#include <ws2tcpip.h>
private static import libressl.compat.sys.types;
public import core.stdc.errno;
public import core.sys.windows.winsock2;
public import libressl.compat.unistd;

version (Windows):

extern (C):
nothrow @nogc:

enum SHUT_RDWR = core.sys.windows.winsock2.SD_BOTH;
enum SHUT_RD = core.sys.windows.winsock2.SD_RECEIVE;
enum SHUT_WR = core.sys.windows.winsock2.SD_SEND;

int posix_connect(int sockfd, const (sockaddr)* addr, socklen_t addrlen);

int posix_open(const (char)* path, ...);

int posix_close(int fd);

libressl.compat.sys.types.ssize_t posix_read(int fd, void* buf, size_t count);

libressl.compat.sys.types.ssize_t posix_write(int fd, const (void)* buf, size_t count);

int posix_getsockopt(int sockfd, int level, int optname, void* optval, socklen_t* optlen);

int posix_setsockopt(int sockfd, int level, int optname, const (void)* optval, socklen_t optlen);

version (NO_REDEF_POSIX_FUNCTIONS) {
} else {
	alias connect = .posix_connect;
	alias open = .posix_open;
	alias close = .posix_close;
	alias read = .posix_read;
	alias write = .posix_write;
	alias getsockopt = .posix_getsockopt;
	alias setsockopt = .posix_setsockopt;
}
