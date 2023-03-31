/*
 * Public domain
 * err.h compatibility shim
 */
module libressl.compat.err;



public import core.stdc.errno;
public import core.stdc.stdarg;
public import core.sys.bionic.err;
public import core.sys.darwin.err;
public import core.sys.dragonflybsd.err;
public import core.sys.freebsd.err;
public import core.sys.linux.err;
public import core.sys.netbsd.err;
public import core.sys.openbsd.err;
public import core.sys.solaris.err;
public import libressl.compat.stdio;
public import libressl.compat.stdlib;
public import libressl.compat.string;

extern (C):

version (Posix) {
} else {
	version (D_BetterC) {
	} else {
		pragma(inline, true)
		nothrow
		noreturn err(int eval, const (char)* fmt, ...)

			do
			{
				int sverrno = core.stdc.errno.errno;
				core.stdc.stdarg.va_list ap;

				core.stdc.stdarg.va_start(ap, fmt);

				if (fmt != null) {
					libressl.compat.stdio.vfprintf(libressl.compat.stdio.stderr, fmt, ap);
					libressl.compat.stdio.fprintf(libressl.compat.stdio.stderr, ": ");
				}

				core.stdc.stdarg.va_end(ap);
				libressl.compat.stdio.fprintf(libressl.compat.stdio.stderr, "%s\n", libressl.compat.string.strerror(sverrno));
				libressl.compat.stdlib.exit(eval);
			}

		pragma(inline, true)
		nothrow
		noreturn errx(int eval, const (char)* fmt, ...)

			do
			{
				core.stdc.stdarg.va_list ap;

				core.stdc.stdarg.va_start(ap, fmt);

				if (fmt != null) {
					libressl.compat.stdio.vfprintf(libressl.compat.stdio.stderr, fmt, ap);
				}

				core.stdc.stdarg.va_end(ap);
				libressl.compat.stdio.fprintf(libressl.compat.stdio.stderr, "\n");
				libressl.compat.stdlib.exit(eval);
			}

		pragma(inline, true)
		nothrow
		void warn(const (char)* fmt, ...)

			do
			{
				int sverrno = core.stdc.errno.errno;
				core.stdc.stdarg.va_list ap;

				core.stdc.stdarg.va_start(ap, fmt);

				if (fmt != null) {
					libressl.compat.stdio.vfprintf(libressl.compat.stdio.stderr, fmt, ap);
					libressl.compat.stdio.fprintf(libressl.compat.stdio.stderr, ": ");
				}

				core.stdc.stdarg.va_end(ap);
				libressl.compat.stdio.fprintf(libressl.compat.stdio.stderr, "%s\n", libressl.compat.string.strerror(sverrno));
			}

		pragma(inline, true)
		nothrow
		void vwarnx(const (char)* fmt, core.stdc.stdarg.va_list args)

			do
			{
				if (fmt != null) {
					libressl.compat.stdio.vfprintf(libressl.compat.stdio.stderr, fmt, args);
				}

				libressl.compat.stdio.fprintf(libressl.compat.stdio.stderr, "\n");
			}

		pragma(inline, true)
		nothrow
		void warnx(const (char)* fmt, ...)

			do
			{
				core.stdc.stdarg.va_list ap;

				core.stdc.stdarg.va_start(ap, fmt);
				.vwarnx(fmt, ap);
				core.stdc.stdarg.va_end(ap);
			}
	}
}
