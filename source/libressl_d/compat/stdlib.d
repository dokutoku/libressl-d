/*
 * stdlib.h compatibility shim
 * Public domain
 */
module libressl.compat.stdlib;


private static import core.stdc.config;
public import core.stdc.stdint;
public import core.stdc.stdlib;
public import core.sys.bionic.stdlib;
public import core.sys.darwin.stdlib;
public import core.sys.dragonflybsd.stdlib;
public import core.sys.freebsd.stdlib;
public import core.sys.netbsd.stdlib;
public import core.sys.openbsd.stdlib;
public import core.sys.posix.stdlib;
public import core.sys.solaris.stdlib;
public import libressl.compat.sys.types;

extern (C):
nothrow @nogc:

static if (!__traits(compiles, arc4random)) {
	core.stdc.stdint.uint32_t arc4random();
}

static if (!__traits(compiles, arc4random_buf)) {
	void arc4random_buf(void* _buf, size_t n);
}

static if (!__traits(compiles, arc4random_uniform)) {
	core.stdc.stdint.uint32_t arc4random_uniform(core.stdc.stdint.uint32_t upper_bound);
}

static if (!__traits(compiles, freezero)) {
	void freezero(void* ptr_, size_t sz);
}

static if (!__traits(compiles, getprogname)) {
	const (char)* getprogname();
}

void* reallocarray(void*, size_t, size_t);

static if (!__traits(compiles, recallocarray)) {
	void* recallocarray(void*, size_t, size_t, size_t);
}

static if (!__traits(compiles, strtonum)) {
	//core.stdc.config.cpp_longlong strtonum(const (char)* nptr, core.stdc.config.cpp_longlong minval, core.stdc.config.cpp_longlong maxval, const (char)** errstr);
}
