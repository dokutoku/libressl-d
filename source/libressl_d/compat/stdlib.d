/*
 * stdlib.h compatibility shim
 * Public domain
 */
module libressl_d.compat.stdlib;


private static import core.stdc.config;
public import core.stdc.stdint;
public import core.stdc.stdlib;
public import core.sys.posix.stdlib;
public import libressl_d.compat.sys.types;

extern (C):
nothrow @nogc:

//#if !defined(HAVE_ARC4RANDOM_BUF)
	//core.stdc.stdint.uint32_t arc4random();
	//void arc4random_buf(void* _buf, size_t n);
	//core.stdc.stdint.uint32_t arc4random_uniform(core.stdc.stdint.uint32_t upper_bound);
//#endif

//#if !defined(HAVE_FREEZERO)
	//void freezero(void* ptr_, size_t sz);
//#endif

//#if !defined(HAVE_GETPROGNAME)
	//const (char)* getprogname();
//#endif

//void* reallocarray(void*, size_t, size_t);

//#if !defined(HAVE_RECALLOCARRAY)
	//void* recallocarray(void*, size_t, size_t, size_t);
//#endif

//#if !defined(HAVE_STRTONUM)
	//core.stdc.config.cpp_longlong strtonum(const (char)* nptr, core.stdc.config.cpp_longlong minval, core.stdc.config.cpp_longlong maxval, const (char)** errstr);
//#endif
