/*
 * Public domain
 * stdio.h compatibility shim
 */
module libressl_d.compat.stdio;


public import core.stdc.stdarg;
public import core.stdc.stdio;
public import core.sys.posix.stdio;

version (Windows) {
	//#if _MSC_VER >= 1900
		//#include <../ucrt/corecrt_io.h>
		public import libressl_d.compat.stdlib;
	//#endif
}

//#if !defined(HAVE_ASPRINTF)
	//int vasprintf(char** str, const (char)* fmt, core.stdc.stdarg.va_list ap);
	//int asprintf(char** str, const (char)* fmt, ...);
//#endif

version (Windows) {
	//#if defined(_MSC_VER)
		//#define __func__ __FUNCTION__
	//#endif

	//void posix_perror(const (char)* s);
	//core.stdc.stdio.FILE* posix_fopen(const (char)* path, const (char)* mode);
	//char* posix_fgets(char* s, int size, core.stdc.stdio.FILE* stream);
	//int posix_rename(const (char)* oldpath, const (char)* newpath);

	//#if !defined(NO_REDEF_POSIX_FUNCTIONS)
		//alias perror = posix_perror;
		//alias fopen = posix_fopen;
		//alias fgets = posix_fgets;
		//alias rename = posix_rename;
	//#endif

	version (Windows) {
		alias snprintf = core.stdc.stdio._snprintf;
	}
}
