/*
 * Public domain
 * sys/mman.h compatibility shim
 */
module libressl.compat.sys.mman;


public import core.sys.posix.sys.mman;

//#if !defined(MAP_ANON)
	//#if defined(MAP_ANONYMOUS)
		//alias MAP_ANON = MAP_ANONYMOUS;
	//#else
		//static assert(false, "System does not support mapping anonymous pages?");
	//#endif
//#endif
