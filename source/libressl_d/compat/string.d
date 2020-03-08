/*
 * Public domain
 * string.h compatibility shim
 */
module libressl_d.compat.string;


private static import core.sys.windows.winsock2;
public import core.stdc.string;
public import core.sys.posix.string;
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

//#if !defined(HAVE_STRCASECMP)
	//int strcasecmp(const (char)* s1, const (char)* s2);
	//int strncasecmp(const (char)* s1, const (char)* s2, size_t len);
//#endif

//#if !defined(HAVE_STRLCPY)
	//size_t strlcpy(char* dst, const (char)* src, size_t siz);
//#endif

//#if !defined(HAVE_STRLCAT)
	//size_t strlcat(char* dst, const (char)* src, size_t siz);
//#endif

//#if !defined(HAVE_STRNDUP)
	//char* strndup(const (char)* str, size_t maxlen);

	/* the only user of strnlen is strndup, so only build it if needed */
	//#if !defined(HAVE_STRNLEN)
		//size_t strnlen(const (char)* str, size_t maxlen);
	//#endif
//#endif

//#if !defined(HAVE_STRSEP)
	//char* strsep(char** stringp, const (char)* delim);
//#endif

//#if !defined(HAVE_EXPLICIT_BZERO)
	//void explicit_bzero(void*, size_t);
//#endif

//#if !defined(HAVE_TIMINGSAFE_BCMP)
	//int timingsafe_bcmp(const (void)* b1, const (void)* b2, size_t n);
//#endif

//#if !defined(HAVE_TIMINGSAFE_MEMCMP)
	//int timingsafe_memcmp(const (void)* b1, const (void)* b2, size_t len);
//#endif

//#if !defined(HAVE_MEMMEM)
	//void* memmem(const (void)* big, size_t big_len, const (void)* little, size_t little_len);
//#endif

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
