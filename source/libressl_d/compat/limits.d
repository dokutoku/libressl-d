/*
 * Public domain
 * limits.h compatibility shim
 */
module libressl_d.compat.limits;


public import core.stdc.limits;

/+
version (Windows) {
	public import libressl_d.compat.stdlib;

	enum PATH_MAX = (!__traits(compiles, core.stdc.limits.PATH_MAX)) ? (_MAX_PATH) : (core.stdc.limits.PATH_MAX);
}

#if defined(__hpux)
	//public import core.sys.posix.sys.param;

	enum PATH_MAX = (!__traits(compiles, core.stdc.limits.PATH_MAX)) ? (MAXPATHLEN) : (core.stdc.limits.PATH_MAX);
#endif
+/
