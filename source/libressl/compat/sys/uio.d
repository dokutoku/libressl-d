/*
 * Public domain
 * sys/select.h compatibility shim
 */
module libressl.compat.sys.uio;


public import core.sys.posix.sys.uio;

version (Windows) {
	public import libressl.compat.sys.types;

	struct iovec
	{
		void* iov_base;
		size_t iov_len;
	}
}
