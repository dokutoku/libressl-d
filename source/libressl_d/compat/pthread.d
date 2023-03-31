/*
 * Public domain
 * pthread.h compatibility shim
 */
module libressl.compat.pthread;


private static import core.sys.windows.winbase;
private static import core.sys.windows.windef;
private static import core.sys.windows.winnt;
public import core.sys.darwin.pthread;
public import core.sys.posix.pthread;
public import core.sys.windows.windows;

version (Windows):

private static import core.stdc.errno;
public import libressl.compat.stdlib;
//#include <malloc.h>

extern (C):
nothrow @nogc:

union _RTL_RUN_ONCE
{
	core.sys.windows.winnt.PVOID Ptr;
}

alias RTL_RUN_ONCE = ._RTL_RUN_ONCE;
alias PRTL_RUN_ONCE = ._RTL_RUN_ONCE*;
alias INIT_ONCE = .RTL_RUN_ONCE;
alias PINIT_ONCE = .PRTL_RUN_ONCE;

alias PINIT_ONCE_FN = extern (Windows) nothrow @nogc core.sys.windows.windef.BOOL function(.PINIT_ONCE, core.sys.windows.winnt.PVOID, core.sys.windows.winnt.PVOID*);

extern (Windows)
nothrow @nogc
core.sys.windows.windef.BOOL InitOnceExecuteOnce(.PINIT_ONCE, .PINIT_ONCE_FN, core.sys.windows.winnt.PVOID, core.sys.windows.winnt.LPVOID*);

/*
 * Static once initialization values.
 */
//#define PTHREAD_ONCE_INIT { INIT_ONCE_STATIC_INIT }

/**
 * Static mutex initialization values.
 */
pragma(inline, true)
pure nothrow @safe @nogc @live
.pthread_mutex PTHREAD_MUTEX_INITIALIZER()

	do
	{
		.pthread_mutex output =
		{
			lock: null,
		};

		return output;
	}

/*
 * Once definitions.
 */
struct pthread_once_
{
	.INIT_ONCE once;
}

alias pthread_once_t = .pthread_once_;

private alias void_func = extern (C) nothrow @nogc void function();

pragma(inline, true)
extern (Windows)
core.sys.windows.windef.BOOL _pthread_once_win32_cb(.PINIT_ONCE once, core.sys.windows.winnt.PVOID param, core.sys.windows.winnt.PVOID* context)

	in
	{
		assert(param != null);
	}

	do
	{
		.void_func cb = cast(.void_func)(param);
		cb();

		return core.sys.windows.windef.TRUE;
	}

pragma(inline, true)
int pthread_once(.pthread_once_t* once, .void_func cb)

	in
	{
		assert(once != null);
		assert(cb != null);
	}

	do
	{
		core.sys.windows.windef.BOOL rc = .InitOnceExecuteOnce(&once.once, &._pthread_once_win32_cb, cb, null);

		if (rc == 0) {
			return -1;
		} else {
			return 0;
		}
	}

alias pthread_t = core.sys.windows.windef.DWORD;

pragma(inline, true)
.pthread_t pthread_self()

	do
	{
		return core.sys.windows.winbase.GetCurrentThreadId();
	}

pragma(inline, true)
pure nothrow @safe @nogc @live
int pthread_equal(.pthread_t t1, .pthread_t t2)

	do
	{
		return t1 == t2;
	}

struct pthread_mutex
{
	/* volatile */ core.sys.windows.winbase.LPCRITICAL_SECTION lock;
}

alias pthread_mutex_t = .pthread_mutex;
alias pthread_mutexattr_t = void;

pragma(inline, true)
int pthread_mutex_init(.pthread_mutex_t* mutex, scope const .pthread_mutexattr_t* attr)

	in
	{
		assert(mutex != null);
	}

	do
	{
		mutex.lock = cast(core.sys.windows.winbase.LPCRITICAL_SECTION)(libressl.compat.stdlib.malloc(core.sys.windows.winbase.CRITICAL_SECTION.sizeof));

		if (mutex.lock == null) {
			libressl.compat.stdlib.exit(core.stdc.errno.ENOMEM);
		}

		core.sys.windows.winbase.InitializeCriticalSection(mutex.lock);

		return 0;
	}

//ToDo: InterlockedCompareExchangePointer
version (none)
pragma(inline, true)
int pthread_mutex_lock(.pthread_mutex_t* mutex)

	in
	{
		assert(mutex != null);
	}

	do
	{
		if (mutex.lock == null) {
			core.sys.windows.winbase.LPCRITICAL_SECTION lcs = cast(core.sys.windows.winbase.LPCRITICAL_SECTION)(libressl.compat.stdlib.malloc(core.sys.windows.winbase.CRITICAL_SECTION.sizeof));

			if (lcs == null) {
				libressl.compat.stdlib.exit(core.stdc.errno.ENOMEM);
			}

			core.sys.windows.winbase.InitializeCriticalSection(lcs);

			if (core.sys.windows.winbase.InterlockedCompareExchangePointer(cast(core.sys.windows.winnt.PVOID*)(&mutex.lock), cast(core.sys.windows.winnt.PVOID)(lcs), null) != null) {
				core.sys.windows.winbase.DeleteCriticalSection(lcs);
				libressl.compat.stdlib.free(lcs);
			}
		}

		core.sys.windows.winbase.EnterCriticalSection(mutex.lock);

		return 0;
	}

pragma(inline, true)
int pthread_mutex_unlock(.pthread_mutex_t* mutex)

	in
	{
		assert(mutex != null);
	}

	do
	{
		core.sys.windows.winbase.LeaveCriticalSection(mutex.lock);

		return 0;
	}

pragma(inline, true)
int pthread_mutex_destroy(.pthread_mutex_t* mutex)

	in
	{
		assert(mutex != null);
	}

	do
	{
		core.sys.windows.winbase.DeleteCriticalSection(mutex.lock);
		libressl.compat.stdlib.free(mutex.lock);
		mutex.lock = null;

		return 0;
	}
