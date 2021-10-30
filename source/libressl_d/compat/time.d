/*
 * Public domain
 * sys/time.h compatibility shim
 */
module libressl_d.compat.time;


public import core.stdc.time;
public import libressl_d.compat.sys.time;

extern (C):
nothrow @nogc:

//#if defined(_WIN32)
	//core.stdc.time.tm* __gmtime_r(const (core.stdc.time.time_t)* t, core.stdc.time.tm* core.stdc.time.tm);
	//alias gmtime_r = .__gmtime_r;
//#endif

//#if !defined(HAVE_TIMEGM)
	//core.stdc.time.time_t timegm(core.stdc.time.tm* core.stdc.time.tm);
//#endif

//#if !defined(CLOCK_MONOTONIC)
	//alias CLOCK_MONOTONIC = libressl_d.compat.sys.time.CLOCK_REALTIME;
//#endif

//#if !defined(CLOCK_REALTIME)
	//enum CLOCK_REALTIME = 0;
//#endif

version (Posix) {
	//#if !defined(HAVE_CLOCK_GETTIME)
		alias clockid_t = int;
		//int clock_gettime(.clockid_t clock_id, timespec* tp);
	//#endif

	//#if defined(timespecsub)
		//version = HAVE_TIMESPECSUB;
	//#endif

	//#if !defined(HAVE_TIMESPECSUB)
		pragma(inline, true)
		pure nothrow @trusted @nogc @live
		void timespecsub(scope const libressl_d.compat.sys.time.timespec* tsp, scope const libressl_d.compat.sys.time.timespec* usp, scope libressl_d.compat.sys.time.timespec* vsp)

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
	//#endif
}
