/*
 * Public domain
 * err.h compatibility shim
 */
module libressl_d.compat.err;



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
public import libressl_d.compat.stdio;
public import libressl_d.compat.stdlib;
public import libressl_d.compat.string;

extern (C):

version (Posix) {
} else {
	version (D_BetterC) {
	} else {
		//noreturn
		pragma(inline, true)
		nothrow
		void err(int eval, const (char)* fmt, ...)

			do
			{
				int sverrno = core.stdc.errno.errno;
				core.stdc.stdarg.va_list ap;

				core.stdc.stdarg.va_start(ap, fmt);

				if (fmt != null) {
					libressl_d.compat.stdio.vfprintf(libressl_d.compat.stdio.stderr, fmt, ap);
					libressl_d.compat.stdio.fprintf(libressl_d.compat.stdio.stderr, ": ");
				}

				core.stdc.stdarg.va_end(ap);
				libressl_d.compat.stdio.fprintf(libressl_d.compat.stdio.stderr, "%s\n", libressl_d.compat.string.strerror(sverrno));
				libressl_d.compat.stdlib.exit(eval);
			}

		//noreturn
		pragma(inline, true)
		nothrow
		void errx(int eval, const (char)* fmt, ...)

			do
			{
				core.stdc.stdarg.va_list ap;

				core.stdc.stdarg.va_start(ap, fmt);

				if (fmt != null) {
					libressl_d.compat.stdio.vfprintf(libressl_d.compat.stdio.stderr, fmt, ap);
				}

				core.stdc.stdarg.va_end(ap);
				libressl_d.compat.stdio.fprintf(libressl_d.compat.stdio.stderr, "\n");
				libressl_d.compat.stdlib.exit(eval);
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
					libressl_d.compat.stdio.vfprintf(libressl_d.compat.stdio.stderr, fmt, ap);
					libressl_d.compat.stdio.fprintf(libressl_d.compat.stdio.stderr, ": ");
				}

				core.stdc.stdarg.va_end(ap);
				libressl_d.compat.stdio.fprintf(libressl_d.compat.stdio.stderr, "%s\n", libressl_d.compat.string.strerror(sverrno));
			}

		pragma(inline, true)
		nothrow
		void warnx(const (char)* fmt, ...)

			do
			{
				core.stdc.stdarg.va_list ap;

				core.stdc.stdarg.va_start(ap, fmt);

				if (fmt != null) {
					libressl_d.compat.stdio.vfprintf(libressl_d.compat.stdio.stderr, fmt, ap);
				}

				core.stdc.stdarg.va_end(ap);
				libressl_d.compat.stdio.fprintf(libressl_d.compat.stdio.stderr, "\n");
			}
	}
}
