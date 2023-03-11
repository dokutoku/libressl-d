/*
 * Public domain
 * unistd.h compatibility shim
 */
module libressl_d.compat.unistd;


private static import core.sys.windows.winbase;
private static import libressl_d.compat.stdio;
private static import libressl_d.compat.sys.types;
public import core.sys.posix.unistd;

extern (C):
nothrow @nogc:

version (Posix) {
	//#if defined(__MINGW32__)
		//int ftruncate(int fd, libressl_d.compat.stdio.off_t length_);
		//libressl_d.compat.sys.types.uid_t getuid();
		//libressl_d.compat.sys.types.ssize_t pread(int d, void* buf, size_t nbytes, libressl_d.compat.stdio.off_t offset);
		//libressl_d.compat.sys.types.ssize_t pwrite(int d, const (void)* buf, size_t nbytes, libressl_d.compat.stdio.off_t offset);
	//#endif
} else {
	public import libressl_d.compat.stdlib;
	//#include <io.h>
	//#include <process.h>

	enum STDOUT_FILENO = 1;
	enum STDERR_FILENO = 2;

	enum R_OK = 4;
	enum W_OK = 2;
	enum X_OK = 0;
	enum F_OK = 0;

	enum SEEK_SET = 0;
	enum SEEK_CUR = 1;
	enum SEEK_END = 2;

	version (Windows) {
		public import core.sys.windows.windows;

		int _access(const (char)* path, const int access_mode);

		alias access = ._access;

		pragma(inline, true)
		nothrow @nogc
		uint sleep(uint seconds)

			do
			{
				core.sys.windows.winbase.Sleep(seconds * 1000);

				return seconds;
			}
	} else {
		//alias access = ._access;
	}

	int ftruncate(int fd, libressl_d.compat.stdio.off_t length_);
	libressl_d.compat.sys.types.uid_t getuid();
	libressl_d.compat.sys.types.ssize_t pread(int d, void* buf, size_t nbytes, libressl_d.compat.stdio.off_t offset);
	libressl_d.compat.sys.types.ssize_t pwrite(int d, const (void)* buf, size_t nbytes, libressl_d.compat.stdio.off_t offset);
}

static if (!__traits(compiles, getentropy)) {
	int getentropy(void* buf, size_t buflen);
} else {
	/*
	 * Solaris 11.3 adds getentropy(2), but defines the function in sys/random.h
	 */
	//#if defined(__sun)
		//public import core.sys.posix.sys.random;
	//#endif
}

static if (!__traits(compiles, getpagesize)) {
	int getpagesize();
}

pragma(inline, true)
pure nothrow @safe @nogc @live
int pledge(REQUEST, PATHS)(REQUEST request, PATHS paths)

	do
	{
		return 0;
	}

pragma(inline, true)
pure nothrow @safe @nogc @live
int unveil(PATH, PERMISSIONS)(PATH path, PERMISSIONS permissions)

	do
	{
		return 0;
	}

//#if !defined(HAVE_PIPE2)
	//int pipe2(int[2] fildes, int flags);
//#endif
