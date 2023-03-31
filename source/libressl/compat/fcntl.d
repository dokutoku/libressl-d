/*
 * Public domain
 * fcntl.h compatibility shim
 */
module libressl.compat.fcntl;


private static import core.stdcpp.xutility;
public import core.sys.darwin.fcntl;
public import core.sys.bionic.fcntl;
public import core.sys.linux.fcntl;
public import core.sys.posix.fcntl;

version (Posix) {
	//alias O_NONBLOCK = O_NONBLOCK;
	//alias O_CLOEXEC = O_CLOEXEC;
	//alias FD_CLOEXEC = FD_CLOEXEC;
} else {
	static if (__traits(compiles, core.stdcpp.xutility._MSC_VER)) {
		static if (core.stdcpp.xutility._MSC_VER >= 1900) {
			//#include <../ucrt/fcntl.h>
		} else {
			//#include <../include/fcntl.h>
		}
	} else {
		//#include_next <fcntl.h>
	}

	enum O_NONBLOCK = 0x100000;
	enum O_CLOEXEC = 0x200000;
	enum FD_CLOEXEC = 1;
}
