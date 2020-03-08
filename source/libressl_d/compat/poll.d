/*
 * Public domain
 *
 * poll(2) emulation for Windows
 *
 * This emulates just-enough poll functionality on Windows to work in the
 * context of the openssl(1) program. This is not a replacement for
 * POSIX.1-2001 poll(2).
 *
 * Dongsheng Song <dongsheng.song@gmail.com>
 * Brent Cook <bcook@openbsd.org>
 */
module libressl_d.compat.poll;


private static import core.stdc.config;
public import core.sys.posix.poll;
public import core.sys.windows.winsock2;

version (Windows) {
	/**
	 * Type used for the number of file descriptors.
	 */
	//typedef core.stdc.config.c_ulong int nfds_t;

	//#if !defined(_WIN32_WINNT) || (_WIN32_WINNT < 0x0600)
		/**
		 * Data structure describing a polling request.
		 */
		struct pollfd
		{
			/**
			 * file descriptor
			 */
			int fd;

			/**
			 * requested events
			 */
			short events;

			/**
			 * returned events
			 */
			short revents;
		}

		/* Event types that can be polled */

		/**
		 *  There is data to read.
		 */
		enum POLLIN = 0x0001;

		/**
		 *  There is urgent data to read.
		 */
		enum POLLPRI = 0x0002;

		/**
		 *  Writing now will not block.
		 */
		enum POLLOUT = 0x0004;

		/**
		 *  Normal data may be read.
		 */
		enum POLLRDNORM = 0x0040;

		/**
		 *  Priority data may be read.
		 */
		enum POLLRDBAND = 0x0080;

		/**
		 *  Writing now will not block.
		 */
		enum POLLWRNORM = 0x0100;

		/**
		 *  Priority data may be written.
		 */
		enum POLLWRBAND = 0x0200;

		/* Event types always implicitly polled. */

		/**
		 *  Error condition.
		 */
		enum POLLERR = 0x0008;

		/**
		 *  Hung up.
		 */
		enum POLLHUP = 0x0010;

		/**
		 *  Invalid polling request.
		 */
		enum POLLNVAL = 0x0020;
	//#endif

	/+
	extern (C)
	nothrow @nogc:
	int poll(.pollfd* pfds, .nfds_t nfds, int timeout);
	+/
}
