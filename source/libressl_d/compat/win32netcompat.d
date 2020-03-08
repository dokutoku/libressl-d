/*
 * Public domain
 *
 * BSD socket emulation code for Winsock2
 * Brent Cook <bcook@openbsd.org>
 */
module libressl_d.compat.win32netcompat;


//#include <ws2tcpip.h>
private static import libressl_d.compat.sys.types;
public import core.stdc.errno;
public import core.sys.windows.winsock2;
public import libressl_d.compat.unistd;

version (Windows):

/+
#if !defined(SHUT_RDWR)
	alias SHUT_RDWR = SD_BOTH;
#endif

#if !defined(SHUT_RD)
	alias SHUT_RD = SD_RECEIVE;
#endif

#if !defined(SHUT_WR)
	alias SHUT_WR = SD_SEND;
#endif

int posix_connect(int sockfd, const (sockaddr)* addr, socklen_t addrlen);

int posix_open(const (char)* path, ...);

int posix_close(int fd);

libressl_d.compat.sys.types.ssize_t posix_read(int fd, void* buf, size_t count);

libressl_d.compat.sys.types.ssize_t posix_write(int fd, const (void)* buf, size_t count);

int posix_getsockopt(int sockfd, int level, int optname, void* optval, socklen_t* optlen);

int posix_setsockopt(int sockfd, int level, int optname, const (void)* optval, socklen_t optlen);

#if !defined(NO_REDEF_POSIX_FUNCTIONS)
	#define connect(sockfd, addr, addrlen) .posix_connect(sockfd, addr, addrlen)
	#define open(path, ...) .posix_open(path, __VA_ARGS__)
	#define close(fd) .posix_close(fd)
	#define read(fd, buf, count) .posix_read(fd, buf, count)
	#define write(fd, buf, count) .posix_write(fd, buf, count)
	#define getsockopt(sockfd, level, optname, optval, optlen) .posix_getsockopt(sockfd, level, optname, optval, optlen)
	#define setsockopt(sockfd, level, optname, optval, optlen) .posix_setsockopt(sockfd, level, optname, optval, optlen)
#endif
+/
