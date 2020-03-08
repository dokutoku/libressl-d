/*
 * Public domain
 * sys/select.h compatibility shim
 */
module libressl_d.compat.sys.uio;


public import core.sys.posix.sys.uio;

version (Windows) {
	public import libressl_d.compat.sys.types;

	struct iovec
	{
		void* iov_base;
		size_t iov_len;
	}
}
