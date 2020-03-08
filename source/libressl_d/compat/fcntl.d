/*
 * Public domain
 * fcntl.h compatibility shim
 */
module libressl_d.compat.fcntl;


public import core.sys.posix.fcntl;

version (Posix) {
	//alias O_NONBLOCK = O_NONBLOCK;
	//alias O_CLOEXEC = O_CLOEXEC;
	//alias FD_CLOEXEC = FD_CLOEXEC;
} else {
	//#if defined(_MSC_VER)
		//#if _MSC_VER >= 1900
			//#include <../ucrt/fcntl.h>
		//#else
			//#include <../include/fcntl.h>
		//#endif
	//#else
		//#include_next <fcntl.h>
	//#endif

	enum O_NONBLOCK = 0x100000;
	enum O_CLOEXEC = 0x200000;
	enum FD_CLOEXEC = 1;
}
