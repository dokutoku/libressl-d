/*
 * Public domain
 * machine/endian.h compatibility shim
 */
module libressl_d.compat.machine.endian;


version (Windows) {
	enum LITTLE_ENDIAN = 1234;
	enum BIG_ENDIAN = 4321;
	enum PDP_ENDIAN = 3412;

	/*
	 * Use GCC and Visual Studio compiler defines to determine endian.
	 */
	version (LittleEndian) {
		enum BYTE_ORDER = .LITTLE_ENDIAN;
	} else {
		enum BYTE_ORDER = .BIG_ENDIAN;
	}
//#elif defined(__linux__) || defined(__midipix__)
} else version (linux) {
//	#include <endian.h>
//#elif defined(__sun) || defined(_AIX) || defined(__hpux)
//	public import core.sys.posix.arpa.nameser_compat;
//	public import libressl_d.compat.sys.types;
//#elif defined(__sgi)
//	#include <standards.h>
//	public import core.sys.posix.sys.endian;
} else {
//	public import core.sys.posix.machine.endian;
}

//#ifndef __STRICT_ALIGNMENT
//	#define __STRICT_ALIGNMENT
//
//	#if defined(__i386) || defined(__i386__) || defined(__x86_64) || defined(__x86_64__) || defined(__s390__) || defined(__s390x__) || defined(__aarch64__) || ((defined(__arm__) || defined(__arm)) && __ARM_ARCH >= 6)
//		#undef __STRICT_ALIGNMENT
//	#endif
//#endif
