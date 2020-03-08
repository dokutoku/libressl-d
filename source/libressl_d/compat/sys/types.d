/*
 * Public domain
 * sys/types.h compatibility shim
 */
module libressl_d.compat.sys.types;


private static import libressl_d.compat.limits;
public import core.stdc.stdint;
public import core.sys.posix.sys.types;
public import core.sys.windows.basetsd;

version (Windows) {
	//#if _MSC_VER >= 1900
		//#include <../ucrt/sys/types.h>
	//#else
		//#include <../include/sys/types.h>
	//#endif
}

version (MinGW) {
	//#include <_bsd_types.h>
	alias in_addr_t = core.stdc.stdint.uint32_t;
	alias uid_t = core.stdc.stdint.uint32_t;
}

version (Windows) {
	alias u_char = ubyte;
	alias u_short = ushort;
	alias u_int = uint;
	alias in_addr_t = core.stdc.stdint.uint32_t;
	alias mode_t = core.stdc.stdint.uint32_t;
	alias uid_t = core.stdc.stdint.uint32_t;
	alias ssize_t = core.sys.windows.basetsd.SSIZE_T;
	enum SSIZE_MAX = size_t.max;
}

/+
#if !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__bounded__)
	#define __bounded__(x, y, z)
#endif

#if !defined(HAVE_ATTRIBUTE__DEAD) && !defined(__dead)
	#if defined(_MSC_VER)
		#define __dead __declspec(noreturn)
	#else
		#define __dead __attribute__((__noreturn__))
	#endif
#endif

version (Windows) {
	#define __warn_references(sym, msg)
} else {
	#if !defined(__warn_references)
		#if !defined(__STRING)
			#define __STRING(x) #x
		#endif

		#if defined(__GNUC__) && defined(HAS_GNU_WARNING_LONG)
			#define __warn_references(sym, msg) __asm__(".section .gnu.warning." __STRING(sym) "\n\t.ascii \"" msg "\"\n\t.text");
		#else
			#define __warn_references(sym, msg)
		#endif
	#endif /* __warn_references */
}
+/
