/*	$OpenBSD: _null.h,v 1.2 2016/09/09 22:07:58 millert Exp $	*/

/*
 * Written by Todd C. Miller, September 9, 2016
 * Public domain.
 */
module libressl_d.compat.sys._null;


//#ifndef NULL
	//#if !defined(__cplusplus)
		//enum NULL = cast(void*)(0);
	//#elif __cplusplus >= 201103L
		//enum NULL nullptr;
	//#elif defined(__GNUG__)
		//enum NULL = __null;
	//#else
		//enum NULL = 0L;
	//#endif
//#endif
