/*
 * Public domain
 * err.h compatibility shim
 */
module libressl_d.compat.err;



public import core.stdc.errno;
public import core.stdc.stdarg;
public import libressl_d.compat.stdio;
public import libressl_d.compat.stdlib;
public import libressl_d.compat.string;

extern (C):
package(libressl_d):

//#if defined(HAVE_ERR_H)
	//#include_next <err.h>
//#else
	version (D_BetterC) {
	} else {
		//#if defined(_MSC_VER)
			//__declspec(noreturn)
		//#else
			//__attribute__((noreturn))
		//#endif
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

		//#if defined(_MSC_VER)
			//__declspec(noreturn)
		//#else
			//__attribute__((noreturn))
		//#endif
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
//#endif
