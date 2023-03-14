/*
 * Public domain
 * resolv.h compatibility shim
 */
module libressl_d.compat.resolv;


private static import core.stdcpp.xutility;

version (Windows) {
	static if (core.stdcpp.xutility._MSC_VER >= 1900) {
		//#include <../ucrt/resolv.h>
	} else {
		//#include <../include/resolv.h>
	}
}
//#elif defined(HAVE_RESOLV_H)
	//#include_next <resolv.h>

extern (C):
nothrow @nogc:

//#if !defined(HAVE_B64_NTOP)
	//int b64_ntop(ubyte const*, size_t, char*, size_t);
	//int b64_pton(char const*, ubyte*, size_t);
//#endif
