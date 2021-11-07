/*
 * dirent.h - dirent API for Microsoft Visual Studio
 *
 * Copyright (C) 2006-2012 Toni Ronkko
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * ``Software''), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED ``AS IS'', WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL TONI RONKKO BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * $Id: dirent.h,v 1.20 2014/03/19 17:52:23 tronkko Exp $
 */
module libressl_d.compat.dirent_msvc;


private static import core.stdc.config;
private static import core.stdc.stddef;
private static import core.sys.windows.basetsd;
private static import core.sys.windows.winbase;
private static import core.sys.windows.windef;
private static import core.sys.windows.winnt;
private static import libressl_d.compat.limits;
public import core.stdc.errno;
public import core.stdc.stdarg;
public import core.stdc.wchar_;
public import core.sys.windows.windows;
public import libressl_d.compat.stdio;
public import libressl_d.compat.stdlib;
public import libressl_d.compat.string;
public import libressl_d.compat.sys.stat;
public import libressl_d.compat.sys.types;

version (Windows):
extern (C):
nothrow @nogc:

alias errno_t = int;

.errno_t _set_errno(int);
.errno_t mbstowcs_s(size_t*, wchar_t*, size_t, const (char)*, size_t);
.errno_t wcstombs_s(size_t*, char*, size_t, const (wchar_t)*, size_t);

/**
 * Indicates that d_type field is available in dirent structure
 */
enum _DIRENT_HAVE_D_TYPE = true;

/**
 * Indicates that d_namlen field is available in dirent structure
 */
enum _DIRENT_HAVE_D_NAMLEN = true;

/* Maximum length of file name */
enum PATH_MAX = libressl_d.compat.limits.PATH_MAX;

static if (!__traits(compiles, libressl_d.compat.stdio.FILENAME_MAX)) {
	enum FILENAME_MAX = core.sys.windows.windef.MAX_PATH;
} else {
	enum FILENAME_MAX = libressl_d.compat.stdio.FILENAME_MAX;
}

enum NAME_MAX = libressl_d.compat.limits.NAME_MAX;

/**
 * Return the exact length of d_namlen without zero terminator
 */
pragma(inline, true)
pure nothrow @trusted @nogc @live
void _D_EXACT_NAMLEN(P)(P p)

	do
	{
		return p.d_namlen;
	}

/**
 * Return number of bytes needed to store d_namlen
 */
pragma(inline, true)
pure nothrow @safe @nogc @live
void _D_ALLOC_NAMLEN(P)(P p)

	do
	{
		return libressl_d.compat.limits.PATH_MAX;
	}

/**
 * Wide-character version
 */
struct _wdirent
{
	/**
	 * Always zero
	 */
	core.stdc.config.c_long d_ino;

	/**
	 * Structure size
	 */
	ushort d_reclen;

	/**
	 * Length of name without \0
	 */
	size_t d_namlen;

	/**
	 * File type
	 */
	int d_type;

	/**
	 * File name
	 */
	core.stdc.stddef.wchar_t[libressl_d.compat.limits.PATH_MAX] d_name = '\0';
}

struct _WDIR
{
	/**
	 * Current directory entry
	 */
	._wdirent ent;

	/**
	 * Private file data
	 */
	core.sys.windows.winbase.WIN32_FIND_DATAW data;

	/**
	 * True if data is valid
	 */
	int cached;

	/**
	 * Win32 search handle
	 */
	core.sys.windows.basetsd.HANDLE handle;

	/**
	 * Initial directory name
	 */
	core.stdc.stddef.wchar_t* patt;
}

/**
 * Multi-byte character versions
 */
struct dirent
{
	/**
	 * Always zero
	 */
	core.stdc.config.c_long d_ino;

	/**
	 * Structure size
	 */
	ushort d_reclen;

	/**
	 * Length of name without \0
	 */
	size_t d_namlen;

	/**
	 * File type
	 */
	int d_type;

	/**
	 * File name
	 */
	char[libressl_d.compat.limits.PATH_MAX] d_name = '\0';
}

struct DIR
{
	.dirent ent;
	._WDIR* wdirp;
}

/*
 * Open directory stream DIRNAME for read and return a pointer to the
 * internal working area that is used to retrieve individual directory
 * entries.
 */
package(libressl_d)
._WDIR* _wopendir(const (core.stdc.stddef.wchar_t)* dirname)

	do
	{
		/* Must have directory name */
		if ((dirname == null) || (dirname[0] == '\0')) {
			._set_errno(core.stdc.errno.ENOENT);

			return null;
		}

		/* Allocate new _WDIR structure */
		._WDIR* dirp = cast(._WDIR*)(libressl_d.compat.stdlib.malloc(._WDIR.sizeof));

		int error = void;

		if (dirp != null) {
			/* Reset _WDIR structure */
			dirp.handle = core.sys.windows.winbase.INVALID_HANDLE_VALUE;
			dirp.patt = null;
			dirp.cached = 0;

			/* Compute the length of full path plus zero terminator */
			core.sys.windows.windef.DWORD n = core.sys.windows.winbase.GetFullPathNameW(dirname, 0, null, null);

			/* Allocate room for absolute directory name and search pattern */
			dirp.patt = cast(core.stdc.stddef.wchar_t*)(libressl_d.compat.stdlib.malloc((core.stdc.stddef.wchar_t.sizeof * n) + 16));

			if (dirp.patt != null) {
				/*
				 * Convert relative directory name to an absolute one.  This
				 * allows rewinddir() to function correctly even when current
				 * working directory is changed between opendir() and rewinddir().
				 */
				n = core.sys.windows.winbase.GetFullPathNameW(dirname, n, dirp.patt, null);

				if (n > 0) {
					/* Append search pattern \* to the directory name */
					core.stdc.stddef.wchar_t* p = dirp.patt + n;

					if (dirp.patt < p) {
						switch (p[-1]) {
							case '\\':
							case '/':
							case ':':
								/* Directory ends in path separator, e.g. c:\temp\ */
								/*NOP*/
								//;

								break;

							default:
								/* Directory name doesn't end in path separator */
								*p++ = '\\';
						}
					}

					*p++ = '*';
					*p = '\0';

					/* Open directory stream and retrieve the first entry */
					if (.dirent_first(dirp)) {
						/* Directory stream opened successfully */
						error = 0;
					} else {
						/* Cannot retrieve first entry */
						error = 1;
						._set_errno(core.stdc.errno.ENOENT);
					}
				} else {
					/* Cannot retrieve full path name */
					._set_errno(core.stdc.errno.ENOENT);
					error = 1;
				}
			} else {
				/* Cannot allocate memory for search pattern */
				error = 1;
			}
		} else {
			/* Cannot allocate _WDIR structure */
			error = 1;
		}

		/* Clean up in case of error */
		if ((error) && (dirp != null)) {
			._wclosedir(dirp);
			dirp = null;
		}

		return dirp;
	}

/*
 * Read next directory entry.  The directory entry is returned in dirent
 * structure in the d_name field.  Individual directory entries returned by
 * this function include regular files, sub-directories, pseudo-directories
 * "." and ".." as well as volume labels, hidden files and system files.
 */
package(libressl_d)
._wdirent* _wreaddir(._WDIR* dirp)

	in
	{
		assert(dirp != null);
	}

	do
	{
		/* Read next directory entry */
		core.sys.windows.winbase.WIN32_FIND_DATAW* datap = .dirent_next(dirp);

		._wdirent* entp = void;

		if (datap != null) {
			/* Pointer to directory entry to return */
			entp = &dirp.ent;

			/*
			 * Copy file name as wide-character string.  If the file name is too
			 * core.stdc.config.c_long to fit in to the destination buffer, then truncate file name
			 * to PATH_MAX characters and zero-terminate the buffer.
			 */
			size_t n = 0;

			while (((n + 1) < libressl_d.compat.limits.PATH_MAX) && (datap.cFileName[n] != 0)) {
				entp.d_name[n] = datap.cFileName[n];
				n++;
			}

			dirp.ent.d_name[n] = 0;

			/* Length of file name excluding zero terminator */
			entp.d_namlen = n;

			/* File type */
			core.sys.windows.windef.DWORD attr = datap.dwFileAttributes;

			if ((attr & core.sys.windows.winnt.FILE_ATTRIBUTE_DEVICE) != 0) {
				entp.d_type = libressl_d.compat.sys.stat.DT_CHR;
			} else if ((attr & core.sys.windows.winnt.FILE_ATTRIBUTE_DIRECTORY) != 0) {
				entp.d_type = libressl_d.compat.sys.stat.DT_DIR;
			} else {
				entp.d_type = libressl_d.compat.sys.stat.DT_REG;
			}

			/* Reset dummy fields */
			entp.d_ino = 0;
			entp.d_reclen = ._wdirent.sizeof;
		} else {
			/* Last directory entry read */
			entp = null;
		}

		return entp;
	}

/*
 * Close directory stream opened by opendir() function.  This invalidates the
 * DIR structure as well as any directory entry read previously by
 * _wreaddir().
 */
package(libressl_d)
int _wclosedir(._WDIR* dirp)

	do
	{
		int ok = void;

		if (dirp != null) {
			/* Release search handle */
			if (dirp.handle != core.sys.windows.winbase.INVALID_HANDLE_VALUE) {
				core.sys.windows.winbase.FindClose(dirp.handle);
				dirp.handle = core.sys.windows.winbase.INVALID_HANDLE_VALUE;
			}

			/* Release search pattern */
			if (dirp.patt != null) {
				libressl_d.compat.stdlib.free(dirp.patt);
				dirp.patt = null;
			}

			/* Release directory structure */
			libressl_d.compat.stdlib.free(dirp);

			/*success*/
			ok = 0;
		} else {
			/* Invalid directory stream */
			._set_errno(core.stdc.errno.EBADF);

			/*failure*/
			ok = -1;
		}

		return ok;
	}

/*
 * Rewind directory stream such that _wreaddir() returns the very first
 * file name again.
 */
package(libressl_d)
void _wrewinddir(._WDIR* dirp)

	do
	{
		if (dirp != null) {
			/* Release existing search handle */
			if (dirp.handle != core.sys.windows.winbase.INVALID_HANDLE_VALUE) {
				core.sys.windows.winbase.FindClose(dirp.handle);
				dirp.handle = core.sys.windows.windef.NULL;
			}

			/* Open new search handle */
			.dirent_first(dirp);
		}
	}

/* Get first directory entry(internal) */
package(libressl_d)
core.sys.windows.winbase.WIN32_FIND_DATAW* dirent_first(._WDIR* dirp)

	in
	{
		assert(dirp != null);
	}

	do
	{
		core.sys.windows.winbase.WIN32_FIND_DATAW* datap = void;

		/* Open directory and retrieve the first entry */
		dirp.handle = core.sys.windows.winbase.FindFirstFileW(dirp.patt, &dirp.data);

		if (dirp.handle != core.sys.windows.winbase.INVALID_HANDLE_VALUE) {
			/* a directory entry is now waiting in memory */
			datap = &dirp.data;
			dirp.cached = 1;
		} else {
			/* Failed to re-open directory: no directory entry in memory */
			dirp.cached = 0;
			datap = null;
		}

		return datap;
	}

/* Get next directory entry(internal) */
package(libressl_d)
core.sys.windows.winbase.WIN32_FIND_DATAW* dirent_next(._WDIR* dirp)

	in
	{
		assert(dirp != null);
	}

	do
	{
		core.sys.windows.winbase.WIN32_FIND_DATAW* p = void;

		/* Get next directory entry */
		if (dirp.cached != 0) {
			/* A valid directory entry already in memory */
			p = &dirp.data;
			dirp.cached = 0;
		} else if (dirp.handle != core.sys.windows.winbase.INVALID_HANDLE_VALUE) {
			/* Get the next directory entry from stream */
			if (core.sys.windows.winbase.FindNextFileW(dirp.handle, &dirp.data) != core.sys.windows.windef.FALSE) {
				/* Got a file */
				p = &dirp.data;
			} else {
				/* The very last entry has been processed or an error occured */
				core.sys.windows.winbase.FindClose(dirp.handle);
				dirp.handle = core.sys.windows.winbase.INVALID_HANDLE_VALUE;
				p = null;
			}
		} else {
			/* End of directory stream reached */
			p = null;
		}

		return p;
	}

/**
 * Open directory stream using plain old C-string.
 */
package(libressl_d)
.DIR* opendir(const (char)* dirname)

	do
	{
		/* Must have directory name */
		if ((dirname == null) || (dirname[0] == '\0')) {
			._set_errno(core.stdc.errno.ENOENT);

			return null;
		}

		/* Allocate memory for DIR structure */
		.DIR* dirp = cast(.DIR*)(libressl_d.compat.stdlib.malloc(.DIR.sizeof));

		int error = void;

		if (dirp != null) {
			core.stdc.stddef.wchar_t[libressl_d.compat.limits.PATH_MAX] wname = void;
			size_t n = void;

			/* Convert directory name to wide-character string */
			error = .dirent_mbstowcs_s(&n, &(wname[0]), libressl_d.compat.limits.PATH_MAX, dirname, libressl_d.compat.limits.PATH_MAX);

			if (!error) {
				/* Open directory stream using wide-character name */
				dirp.wdirp = ._wopendir(&(wname[0]));

				if (dirp.wdirp) {
					/* Directory stream opened */
					error = 0;
				} else {
					/* Failed to open directory stream */
					error = 1;
				}
			} else {
				/*
				 * Cannot convert file name to wide-character string.  This
				 * occurs if the string contains invalid multi-byte sequences or
				 * the output buffer is too small to contain the resulting
				 * string.
				 */
				error = 1;
			}
		} else {
			/* Cannot allocate DIR structure */
			error = 1;
		}

		/* Clean up in case of error */
		if ((error) && (dirp != null)) {
			libressl_d.compat.stdlib.free(dirp);
			dirp = null;
		}

		return dirp;
	}

/**
 * Read next directory entry.
 *
 * When working with text consoles, please note that file names returned by
 * readdir() are represented in the default ANSI code page while any output to
 * console is typically formatted on another code page.  Thus, non-ASCII
 * characters in file names will not usually display correctly on console.  The
 * problem can be fixed in two ways:(1) change the character set of console
 * to 1252 using chcp utility and use Lucida Console font, or(2) use
 * _cprintf function when writing to console.  The _cprinf() will re-encode
 * ANSI strings to the console code page so many non-ASCII characters will
 * display correcly.
 */
package(libressl_d)
.dirent* readdir(.DIR* dirp)

	in
	{
		assert(dirp != null);
	}

	do
	{
		/* Read next directory entry */
		core.sys.windows.winbase.WIN32_FIND_DATAW* datap = .dirent_next(dirp.wdirp);

		.dirent* entp = void;

		if (datap != null) {
			size_t n = void;

			/* Attempt to convert file name to multi-byte string */
			int error = .dirent_wcstombs_s(&n, &(dirp.ent.d_name[0]), libressl_d.compat.limits.PATH_MAX, &(datap.cFileName[0]), libressl_d.compat.limits.PATH_MAX);

			/*
			 * If the file name cannot be represented by a multi-byte string,
			 * then attempt to use old 8+3 file name.  This allows traditional
			 * Unix-code to access some file names despite of unicode
			 * characters, although file names may seem unfamiliar to the user.
			 *
			 * Be ware that the code below cannot come up with a short file
			 * name unless the file system provides one.  At least
			 * VirtualBox shared folders fail to do this.
			 */
			if ((error) && (datap.cAlternateFileName[0] != '\0')) {
				error = .dirent_wcstombs_s(&n, &(dirp.ent.d_name[0]), libressl_d.compat.limits.PATH_MAX, &(datap.cAlternateFileName[0]), libressl_d.compat.limits.PATH_MAX);
			}

			if (!error) {
				/* Initialize directory entry for return */
				entp = &dirp.ent;

				/* Length of file name excluding zero terminator */
				entp.d_namlen = n - 1;

				/* File attributes */
				core.sys.windows.windef.DWORD attr = datap.dwFileAttributes;

				if ((attr & core.sys.windows.winnt.FILE_ATTRIBUTE_DEVICE) != 0) {
					entp.d_type = libressl_d.compat.sys.stat.DT_CHR;
				} else if ((attr & core.sys.windows.winnt.FILE_ATTRIBUTE_DIRECTORY) != 0) {
					entp.d_type = libressl_d.compat.sys.stat.DT_DIR;
				} else {
					entp.d_type = libressl_d.compat.sys.stat.DT_REG;
				}

				/* Reset dummy fields */
				entp.d_ino = 0;
				entp.d_reclen = .dirent.sizeof;
			} else {
				/*
				 * Cannot convert file name to multi-byte string so construct
				 * an errornous directory entry and return that.  Note that
				 * we cannot return null as that would stop the processing
				 * of directory entries completely.
				 */
				entp = &dirp.ent;
				entp.d_name[0] = '?';
				entp.d_name[1] = '\0';
				entp.d_namlen = 1;
				entp.d_type = libressl_d.compat.sys.stat.DT_UNKNOWN;
				entp.d_ino = 0;
				entp.d_reclen = 0;
			}
		} else {
			/* No more directory entries */
			entp = null;
		}

		return entp;
	}

/**
 * Close directory stream.
 */
package(libressl_d)
int closedir(.DIR* dirp)

	do
	{
		int ok = void;

		if (dirp != null) {
			/* Close wide-character directory stream */
			ok = ._wclosedir(dirp.wdirp);
			dirp.wdirp = null;

			/* Release multi-byte character version */
			libressl_d.compat.stdlib.free(dirp);
		} else {
			/* Invalid directory stream */
			._set_errno(core.stdc.errno.EBADF);

			/*failure*/
			ok = -1;
		}

		return ok;
	}

/**
 * Rewind directory stream to beginning.
 */
package(libressl_d)
void rewinddir(.DIR* dirp)

	in
	{
		assert(dirp != null);
	}

	do
	{
		/* Rewind wide-character string directory stream */
		._wrewinddir(dirp.wdirp);
	}

/* Convert multi-byte string to wide character string */
package(libressl_d)
int dirent_mbstowcs_s(size_t* pReturnValue, core.stdc.stddef.wchar_t* wcstr, size_t sizeInWords, const (char)* mbstr, size_t count)

	do
	{
		return .mbstowcs_s(pReturnValue, wcstr, sizeInWords, mbstr, count);
	}

/* Convert wide-character string to multi-byte string */
package(libressl_d)
int dirent_wcstombs_s(size_t* pReturnValue, char* mbstr, size_t sizeInBytes, /* max size of mbstr */ const (core.stdc.stddef.wchar_t)* wcstr, size_t count)

	do
	{
		return .wcstombs_s(pReturnValue, mbstr, sizeInBytes, wcstr, count);
	}
