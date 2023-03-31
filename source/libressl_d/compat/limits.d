/*
 * Public domain
 * limits.h compatibility shim
 */
module libressl.compat.limits;


public import core.stdc.limits;

version (Windows) {
	public import libressl.compat.stdlib;

	private enum _MAX_PATH = 260;

	static if (!__traits(compiles, core.stdc.limits.PATH_MAX)) {
		enum PATH_MAX = ._MAX_PATH;
	} else {
		enum PATH_MAX = core.stdc.limits.PATH_MAX;
	}
}

/+
#if defined(__hpux)
	//public import core.sys.posix.sys.param;

	static if (!__traits(compiles, core.stdc.limits.PATH_MAX)) {
		enum PATH_MAX = MAXPATHLEN;
	} else {
		enum PATH_MAX = core.stdc.limits.PATH_MAX;
	}
#endif
+/
