/*
 * Public domain
 * sys/time.h compatibility shim
 */
module libressl.compat.time;


public import core.stdc.time;
public import core.sys.freebsd.time;
public import core.sys.posix.time;
public import core.sys.solaris.time;
public import libressl.compat.sys.time;

version (none) {
	public import core.sys.dragonflybsd.time;
	public import core.sys.netbsd.time;
	public import core.sys.openbsd.time;
}

extern (C):
nothrow @nogc:

version (Windows) {
	core.stdc.time.tm* __gmtime_r(const (core.stdc.time.time_t)* t, core.stdc.time.tm* tm);
	alias gmtime_r = .__gmtime_r;
}

static if (!__traits(compiles, timegm)) {
	core.stdc.time.time_t timegm(core.stdc.time.tm* tm);
}

static if (!__traits(compiles, CLOCK_REALTIME)) {
	enum CLOCK_REALTIME = 0;
}

static if (!__traits(compiles, CLOCK_MONOTONIC)) {
	alias CLOCK_MONOTONIC = .CLOCK_REALTIME;
}

version (Posix) {
	static if (!__traits(compiles, clock_gettime)) {
		alias clockid_t = int;
		int clock_gettime(.clockid_t clock_id, libressl.compat.sys.time.timespec* tp);
	}

	//#if defined(timespecsub)
		//version = HAVE_TIMESPECSUB;
	//#endif

	//#if !defined(HAVE_TIMESPECSUB)
	static if (!__traits(compiles, timespecsub)) {
		pragma(inline, true)
		pure nothrow @trusted @nogc @live
		void timespecsub(scope const libressl.compat.sys.time.timespec* tsp, scope const libressl.compat.sys.time.timespec* usp, scope libressl.compat.sys.time.timespec* vsp)

			in
			{
				assert(tsp != null);
				assert(usp != null);
				assert(vsp != null);
			}

			do
			{
				vsp.tv_sec = tsp.tv_sec - usp.tv_sec;
				vsp.tv_nsec = tsp.tv_nsec - usp.tv_nsec;

				if (vsp.tv_nsec < 0) {
					vsp.tv_sec--;
					vsp.tv_nsec += 1000000000L;
				}
			}
	}
}
