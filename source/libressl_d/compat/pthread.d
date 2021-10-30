/*
 * Public domain
 * pthread.h compatibility shim
 */
module libressl_d.compat.pthread;


private static import core.sys.windows.winbase;
private static import core.sys.windows.windef;
private static import core.sys.windows.winnt;
public import core.sys.posix.pthread;
public import core.sys.windows.windows;

package(libressl_d):

extern (C):
nothrow @nogc:

version (Windows) {
	private static import core.stdc.errno;
	public import core.stdc.stdlib;
	//#include <malloc.h>

	/*
	 * Static once initialization values.
	 */
	//#define PTHREAD_ONCE_INIT { INIT_ONCE_STATIC_INIT }

	/+
	/*
	 * Static mutex initialization values.
	 */
	#define PTHREAD_MUTEX_INITIALIZER { .lock = null }

	/*
	 * Once definitions.
	 */
	struct pthread_once
	{
		INIT_ONCE once;
	}

	alias pthread_once_t = .pthread_once;

	//pragma(inline, true)
	extern (Windows)
	package(libressl_d)
	core.sys.windows.windef.BOOL _pthread_once_win32_cb(PINIT_ONCE once, core.sys.windows.winnt.PVOID param, core.sys.windows.winnt.PVOID* context)

		do
		{
			void function() cb = param;
			cb();

			return core.sys.windows.windef.TRUE;
		}

	pragma(inline, true)
	package(libressl_d)
	int pthread_once(.pthread_once_t* once, void function() cb)

		do
		{
			core.sys.windows.windef.BOOL rc = InitOnceExecuteOnce(&once.once, ._pthread_once_win32_cb, cb, null);

			if (rc == 0) {
				return -1;
			} else {
				return 0;
			}
		}

	alias pthread_t = core.sys.windows.windef.DWORD;

	pragma(inline, true)
	package(libressl_d)
	.pthread_t pthread_self()

		do
		{
			return core.sys.windows.winbase.GetCurrentThreadId();
		}

	pragma(inline, true)
	int pthread_equal(.pthread_t t1, .pthread_t t2)

		do
		{
			return t1 == t2;
		}

	struct pthread_mutex
	{
		volatile core.sys.windows.winbase.LPCRITICAL_SECTION lock;
	}

	alias pthread_mutex_t = .pthread_mutex;
	alias pthread_mutexattr_t = void;

	pragma(inline, true)
	package(libressl_d)
	int pthread_mutex_init(.pthread_mutex_t* mutex, const (.pthread_mutexattr_t)* attr)

		do
		{
			mutex.lock = core.stdc.stdlib.malloc(core.sys.windows.winbase.CRITICAL_SECTION.sizeof);

			if (mutex.lock == null) {
				core.stdc.stdlib.exit(core.stdc.errno.ENOMEM);
			}

			core.sys.windows.winbase.InitializeCriticalSection(mutex.lock);

			return 0;
		}

	pragma(inline, true)
	package(libressl_d)
	int pthread_mutex_lock(.pthread_mutex_t* mutex)

		do
		{
			if (mutex.lock == null) {
				core.sys.windows.winbase.LPCRITICAL_SECTION lcs = core.stdc.stdlib.malloc(core.sys.windows.winbase.CRITICAL_SECTION.sizeof);

				if (lcs == null) {
					core.stdc.stdlib.exit(core.stdc.errno.ENOMEM);
				}

				core.sys.windows.winbase.InitializeCriticalSection(lcs);

				if (core.sys.windows.winbase.InterlockedCompareExchangePointer(cast(core.sys.windows.winnt.PVOID*)(&mutex.lock), cast(core.sys.windows.winnt.PVOID)(lcs), null) != null) {
					core.sys.windows.winbase.DeleteCriticalSection(lcs);
					core.stdc.stdlib.free(lcs);
				}
			}

			core.sys.windows.winbase.EnterCriticalSection(mutex.lock);

			return 0;
		}

	pragma(inline, true)
	package(libressl_d)
	int pthread_mutex_unlock(.pthread_mutex_t* mutex)

		do
		{
			core.sys.windows.winbase.LeaveCriticalSection(mutex.lock);

			return 0;
		}

	pragma(inline, true)
	package(libressl_d)
	int pthread_mutex_destroy(.pthread_mutex_t* mutex)

		do
		{
			core.sys.windows.winbase.DeleteCriticalSection(mutex.lock);
			core.stdc.stdlib.free(mutex.lock);

			return 0;
		}
	+/
}
