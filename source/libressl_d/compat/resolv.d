/*
 * Public domain
 * resolv.h compatibility shim
 */
module libressl_d.compat.resolv;


version (Windows) {
	//#if _MSC_VER >= 1900
		//#include <../ucrt/resolv.h>
	//#else
		//#include <../include/resolv.h>
	//#endif
} else {
	//#include_next <resolv.h>
}

//#if !defined(HAVE_B64_NTOP)
	//int b64_ntop(ubyte const*, size_t, char*, size_t);
	//int b64_pton(char const*, ubyte*, size_t);
//#endif
