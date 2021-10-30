/*
 * Public domain
 * syslog.h compatibility shim
 */
module libressl_d.compat.syslog;


private static import core.stdc.stdarg;
public import core.sys.posix.syslog;

extern (C):
nothrow @nogc:

//#if !defined(HAVE_SYSLOG_R)
	version (Windows) {
		/**
		 *  informational
		 */
		enum LOG_INFO = 6;

		/**
		 * random user-level messages
		 */
		enum LOG_USER = 1 << 3;

		/**
		 * reserved for local use
		 */
		enum LOG_LOCAL2 = 18 << 3;
	}

	struct syslog_data
	{
		int log_stat;
		const (char)* log_tag;
		int log_fac;
		int log_mask;
	}

	pragma(inline, true)
	pure nothrow @trusted @nogc @live
	.syslog_data SYSLOG_DATA_INIT()

		do
		{
			.syslog_data output =
			{
				0,
				cast(const (char)*)(0),
				.LOG_USER,
				0xFF,
			};

			return output;
		}

	//void syslog_r(int, .syslog_data*, const (char)*, ...);
	//void vsyslog_r(int, .syslog_data*, const (char)*, core.stdc.stdarg.va_list);
//#endif
