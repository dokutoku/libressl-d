/*
 * Public domain
 * sys/stat.h compatibility shim
 */
module libressl_d.compat.sys.stat;


private static import libressl_d.compat.stdio;
public import core.sys.posix.sys.stat;
public import core.sys.windows.stat;
public import core.sys.windows.windows;

version (Posix) {
	/* for old MinGW */
	//enum S_IRWXU = 0;
	//enum S_IRWXG = 0;
	//enum S_IRGRP = 0;
	//enum S_IRWXO = 0;
	//enum S_IROTH = 0;
} else {
	/* File type and permission flags for stat() */
	/**
	 * File type mask
	 */
	alias S_IFMT = core.sys.windows.stat.S_IFMT;

	/**
	 * Directory
	 */
	alias S_IFDIR = core.sys.windows.stat.S_IFDIR;

	/**
	 * Character device
	 */
	alias S_IFCHR = core.sys.windows.stat.S_IFCHR;

	//#if !defined(S_IFFIFO)
		/*
		 * Pipe
		 */
		//alias S_IFFIFO = _S_IFFIFO;
	//#endif

	/**
	 * Regular file
	 */
	alias S_IFREG = core.sys.windows.stat.S_IFREG;

	/**
	 * Read permission
	 */
	alias S_IREAD = core.sys.windows.stat.S_IREAD;

	/**
	 * Write permission
	 */
	alias S_IWRITE = core.sys.windows.stat.S_IWRITE;

	/**
	 * Execute permission
	 */
	alias S_IEXEC = core.sys.windows.stat.S_IEXEC;

	/**
	 * Pipe
	 */
	alias S_IFIFO = core.sys.windows.stat.S_IFIFO;

	/**
	 *  Block device
	 */
	alias S_IFBLK = core.sys.windows.stat.S_IFBLK;

	/**
	 *  Link
	 */
	enum S_IFLNK = 0;

	/**
	 *  Socket
	 */
	enum S_IFSOCK = 0;

	version (Windows) {
		/**
		 *  RWX user
		 */
		enum S_IRWXU = 0;

		/**
		 * Read user
		 */
		alias S_IRUSR = libressl_d.compat.stdio.S_IREAD;

		/**
		 * Write user
		 */
		alias S_IWUSR = libressl_d.compat.stdio.S_IWRITE;

		/**
		 *  Execute user
		 */
		enum S_IXUSR = 0;

		/**
		 *  RWX group
		 */
		enum S_IRWXG = 0;

		/**
		 *  Read group
		 */
		enum S_IRGRP = 0;

		/**
		 *  Write group
		 */
		enum S_IWGRP = 0;

		/**
		 *  Execute group
		 */
		enum S_IXGRP = 0;

		/**
		 *  RWX others
		 */
		enum S_IRWXO = 0;

		/**
		 *  Read others
		 */
		enum S_IROTH = 0;

		/**
		 *  Write others
		 */
		enum S_IWOTH = 0;

		/**
		 *  Execute others
		 */
		enum S_IXOTH = 0;
	}

	/* File type flags for d_type */
	enum DT_UNKNOWN = 0;
	alias DT_REG = .S_IFREG;
	alias DT_DIR = .S_IFDIR;
	alias DT_FIFO = .S_IFIFO;
	alias DT_SOCK = .S_IFSOCK;
	alias DT_CHR = .S_IFCHR;
	alias DT_BLK = .S_IFBLK;
	alias DT_LNK = .S_IFLNK;

	/* Macros for converting between st_mode and d_type */
	pragma(inline, true)
	pure nothrow @safe @nogc @live
	int IFTODT(int mode)

		do
		{
			return mode & .S_IFMT;
		}

	//#define DTTOIF(type) (type)

	/*
	 * File type macros.  Note that block devices, sockets and links cannot be
	 * distinguished on Windows and the macros S_ISBLK, S_ISSOCK and S_ISLNK are
	 * only defined for compatibility.  These macros should always return false
	 * on Windows.
	 */
	pragma(inline, true)
	pure nothrow @safe @nogc @live
	bool S_ISFIFO(int mode)

		out(result)
		{
			assert(!result);
		}

		do
		{
			return (mode & .S_IFMT) == .S_IFIFO;
		}

	pragma(inline, true)
	pure nothrow @safe @nogc @live
	bool S_ISDIR(int mode)

		out(result)
		{
			assert(!result);
		}

		do
		{
			return (mode & .S_IFMT) == .S_IFDIR;
		}

	pragma(inline, true)
	pure nothrow @safe @nogc @live
	bool S_ISREG(int mode)

		out(result)
		{
			assert(!result);
		}

		do
		{
			return (mode & .S_IFMT) == .S_IFREG;
		}

	pragma(inline, true)
	pure nothrow @safe @nogc @live
	bool S_ISLNK(int mode)

		out(result)
		{
			assert(!result);
		}

		do
		{
			return (mode & .S_IFMT) == .S_IFLNK;
		}

	pragma(inline, true)
	pure nothrow @safe @nogc @live
	bool S_ISSOCK(int mode)

		out(result)
		{
			assert(!result);
		}

		do
		{
			return (mode & .S_IFMT) == .S_IFSOCK;
		}

	pragma(inline, true)
	pure nothrow @safe @nogc @live
	bool S_ISCHR(int mode)

		out(result)
		{
			assert(!result);
		}

		do
		{
			return (mode & .S_IFMT) == .S_IFCHR;
		}

	pragma(inline, true)
	pure nothrow @safe @nogc @live
	bool S_ISBLK(int mode)

		out(result)
		{
			assert(!result);
		}

		do
		{
			return (mode & .S_IFMT) == .S_IFBLK;
		}
}
