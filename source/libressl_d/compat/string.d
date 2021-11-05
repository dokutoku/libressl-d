/*
 * Public domain
 * string.h compatibility shim
 */
module libressl_d.compat.string;


private static import core.sys.windows.winsock2;
public import core.stdc.string;
public import core.sys.posix.string;
public import core.sys.posix.strings;
public import libressl_d.compat.sys.types;

version (Windows) {
	public import core.stdc.errno;
}

extern (C):
nothrow @nogc:

//#if defined(__sun) || defined(_AIX) || defined(__hpux)
	/*
	 * Some functions historically defined in string.h were placed in strings.h by
	 * SUS. Use the same hack as OS X and FreeBSD use to work around on AIX,
	 * Solaris, and HPUX.
	 */
	//#include <strings.h>
//#endif

static if (!__traits(compiles, strcasecmp)) {
	int strcasecmp(const (char)* s1, const (char)* s2);
}

static if (!__traits(compiles, strncasecmp)) {
	int strncasecmp(const (char)* s1, const (char)* s2, size_t len);
}

static if (!__traits(compiles, strlcpy)) {
	size_t strlcpy(char* dst, const (char)* src, size_t siz);
}

static if (!__traits(compiles, strlcat)) {
	size_t strlcat(char* dst, const (char)* src, size_t siz);
}

static if (!__traits(compiles, strndup)) {
	char* strndup(const (char)* str, size_t maxlen);

	/* the only user of strnlen is strndup, so only build it if needed */
	static if (!__traits(compiles, strnlen)) {
		size_t strnlen(const (char)* str, size_t maxlen);
	}
}

static if (!__traits(compiles, strsep)) {
	char* strsep(char** stringp, const (char)* delim);
}

static if (!__traits(compiles, explicit_bzero)) {
	void explicit_bzero(void*, size_t);
}

static if (!__traits(compiles, timingsafe_bcmp)) {
	int timingsafe_bcmp(const (void)* b1, const (void)* b2, size_t n);
}

static if (!__traits(compiles, timingsafe_memcmp)) {
	int timingsafe_memcmp(const (void)* b1, const (void)* b2, size_t len);
}

static if (!__traits(compiles, memmem)) {
	void* memmem(const (void)* big, size_t big_len, const (void)* little, size_t little_len);
}

version (Windows) {
	pragma(inline, true)
	nothrow @nogc
	private char* posix_strerror(int errnum)

		do
		{
			if (errnum == core.sys.windows.winsock2.ECONNREFUSED) {
				return cast(char*)("Connection refused");
			}

			return core.stdc.string.strerror(errnum);
		}

	alias strerror = .posix_strerror;
}
