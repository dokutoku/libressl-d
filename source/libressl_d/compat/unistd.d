/*
 * Public domain
 * unistd.h compatibility shim
 */
module libressl_d.compat.unistd;


private static import core.sys.windows.winbase;
private static import libressl_d.compat.sys.types;
public import core.sys.posix.unistd;

version (Posix) {
	//#if defined(__MINGW32__)
		//int ftruncate(int fd, off_t length_);
		//libressl_d.compat.sys.types.uid_t getuid();
		//libressl_d.compat.sys.types.ssize_t pread(int d, void* buf, size_t nbytes, off_t offset);
		//libressl_d.compat.sys.types.ssize_t pwrite(int d, const (void)* buf, size_t nbytes, off_t offset);
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

	//alias access = _access;

	version (Windows) {
		public import core.sys.windows.windows;

		pragma(inline, true)
		nothrow @nogc
		package(libressl_d)
		uint sleep(uint seconds)

			do
			{
				core.sys.windows.winbase.Sleep(seconds * 1000);

				return seconds;
			}
	}

	//uint sleep(uint seconds);

	//int ftruncate(int fd, off_t length_);
	//libressl_d.compat.sys.types.uid_t getuid();
	//libressl_d.compat.sys.types.ssize_t pread(int d, void* buf, size_t nbytes, off_t offset);
	//libressl_d.compat.sys.types.ssize_t pwrite(int d, const (void)* buf, size_t nbytes, off_t offset);
}

//#if !defined(HAVE_GETENTROPY)
	//int getentropy(void* buf, size_t buflen);
//#else
	/*
	 * Solaris 11.3 adds getentropy(2), but defines the function in sys/random.h
	 */
	//#if defined(__sun)
		//public import core.sys.posix.sys.random;
	//#endif
//#endif

//#if !defined(HAVE_GETPAGESIZE)
	//int getpagesize();
//#endif

//#define pledge(request, paths) 0
//#define unveil(path, permissions) 0

//#if !defined(HAVE_PIPE2)
	//int pipe2(int[2] fildes, int flags);
//#endif
