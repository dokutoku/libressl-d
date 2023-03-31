/*
 * Public domain
 * stdio.h compatibility shim
 */
module libressl.compat.stdio;


private static import core.stdc.config;
private static import core.stdcpp.xutility;
public import core.stdc.stdarg;
public import core.stdc.stdio;
public import core.sys.posix.stdio;

version (Windows) {
	static if (core.stdcpp.xutility._MSC_VER >= 1900) {
		//#include <../ucrt/corecrt_io.h>
		public import libressl.compat.stdlib;
	}
}

extern (C):
nothrow @nogc:

static if (!__traits(compiles, vasprintf)) {
	int vasprintf(char** str, const (char)* fmt, core.stdc.stdarg.va_list ap);
}

static if (!__traits(compiles, asprintf)) {
	int asprintf(char** str, const (char)* fmt, ...);
}

version (Windows) {
	alias off_t = core.stdc.config.c_long;

	static if (__traits(compiles, core.stdcpp.xutility._MSC_VER)) {
		//#define __func__ __FUNCTION__
	}

	void posix_perror(const (char)* s);
	core.stdc.stdio.FILE* posix_fopen(const (char)* path, const (char)* mode);
	char* posix_fgets(char* s, int size, core.stdc.stdio.FILE* stream);
	int posix_rename(const (char)* oldpath, const (char)* newpath);

	version (NO_REDEF_POSIX_FUNCTIONS) {
	} else {
		alias perror = .posix_perror;
		alias fopen = .posix_fopen;
		alias fgets = .posix_fgets;
		alias rename = .posix_rename;
	}

	version (Windows) {
		alias snprintf = core.stdc.stdio._snprintf;
	}
}
