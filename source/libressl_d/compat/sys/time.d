/*
 * Public domain
 * sys/time.h compatibility shim
 */
module libressl_d.compat.sys.time;


public import core.sys.posix.sys.time;
public import core.sys.windows.winsock2;

version (Windows) {
	//extern (C)
	//nothrow @nogc
	//int gettimeofday(.timeval* tp, void* tzp);
}

version (Posix) {
	pragma(inline, true)
	pure nothrow @trusted @nogc
	void timersub(core.sys.posix.sys.time.timeval* tvp, core.sys.posix.sys.time.timeval* uvp, core.sys.posix.sys.time.timeval* vvp)

		in
		{
			assert(tvp != null);
			assert(uvp != null);
			assert(vvp != null);
		}

		do
		{
			vvp.tv_sec = tvp.tv_sec - uvp.tv_sec;
			vvp.tv_usec = tvp.tv_usec - uvp.tv_usec;

			if (vvp.tv_usec < 0) {
				vvp.tv_sec--;
				vvp.tv_usec += 1000000;
			}
		}
}
