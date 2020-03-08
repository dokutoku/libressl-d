module libressl_d.openssl.opensslconf;


private static import core.stdc.config;
public import libressl_d.openssl.opensslfeatures;
/* crypto/opensslconf.h.in */

//#if defined(_MSC_VER) && !defined(__attribute__)
//	#define __attribute__(a)
//#endif

//#if defined(HEADER_CRYPTLIB_H) && !defined(OPENSSLDIR)
	enum OPENSSLDIR = "/etc/ssl";
//#endif

//#undef OPENSSL_UNISTD
//#define OPENSSL_UNISTD <unistd.h>

//#undef OPENSSL_EXPORT_VAR_AS_FUNCTION

//#if defined(HEADER_IDEA_H) && !defined(IDEA_INT)
	alias IDEA_INT = uint;
//#endif

//#if defined(HEADER_MD2_H) && !defined(MD2_INT)
	alias MD2_INT = uint;
//#endif

//#if defined(HEADER_RC2_H) && !defined(RC2_INT)
	/* I need to put in a mod for the alpha - eay */
	alias RC2_INT = uint;
//#endif

//#if defined(HEADER_RC4_H)
	//#if !defined(RC4_INT)
		/*
		 * using int types make the structure larger but make the code faster
		 * on most boxes I have tested - up to %20 faster.
		 */
		/*
		 * I don't know what does "most" mean, but declaring "int" is a must on:
		 * - Intel P6 because partial register stalls are very expensive;
		 * - elder Alpha because it lacks byte load/store instructions;
		 */
		alias RC4_INT = uint;
	//#endif

	//#if !defined(RC4_CHUNK)
		/*
		 * This enables code handling data aligned at natural CPU word
		 * boundary. See crypto/rc4/rc4_enc.c for further details.
		 */
		alias RC4_CHUNK = core.stdc.config.c_ulong;
	//#endif
//#endif

//#if (defined(HEADER_NEW_DES_H) || defined(HEADER_DES_H)) && !defined(DES_LONG)
	/*
	 * If this is set to 'uint' on a DEC Alpha, this gives about a
	 * %20 speed up (longs are 8 bytes, int's are 4).
	 */
	//#if !defined(DES_LONG)
		alias DES_LONG = uint;
	//#endif
//#endif

/+
#if defined(HEADER_BN_H) && !defined(CONFIG_HEADER_BN_H)
	version = CONFIG_HEADER_BN_H;
	#undef BN_LLONG

	/* Should we define BN_DIV2W here? */

	/* Only one for the following should be defined */
	version = SIXTY_FOUR_BIT_LONG;
	#undef SIXTY_FOUR_BIT
	#undef THIRTY_TWO_BIT
#endif

#if defined(HEADER_RC4_LOCL_H) && !defined(CONFIG_HEADER_RC4_LOCL_H)
	version = CONFIG_HEADER_RC4_LOCL_H;
	/*
	 * if this is defined data[i] is used instead of *data, this is a %20
	 * speedup on x86
	 */
	#undef RC4_INDEX
#endif

#if defined(HEADER_BF_LOCL_H) && !defined(CONFIG_HEADER_BF_LOCL_H)
	version = CONFIG_HEADER_BF_LOCL_H;
	#undef BF_PTR
#endif /* HEADER_BF_LOCL_H */

#if defined(HEADER_DES_LOCL_H) && !defined(CONFIG_HEADER_DES_LOCL_H)
	version = CONFIG_HEADER_DES_LOCL_H;

	#if !defined(DES_DEFAULT_OPTIONS)
		/*
		 * the following is tweaked from a config script, that is why it is a
		 * protected undef/define
		 */
		#if !defined(DES_PTR)
			#undef DES_PTR
		#endif

		/*
		 * This helps C compiler generate the correct code for multiple functional
		 * units.  It reduces register dependancies at the expense of 2 more
		 * registers
		 */
		#if !defined(DES_RISC1)
			#undef DES_RISC1
		#endif

		#if !defined(DES_RISC2)
			#undef DES_RISC2
		#endif

		#if defined(DES_RISC1) && defined(DES_RISC2)
			YOU SHOULD NOT HAVE BOTH DES_RISC1 AND DES_RISC2 DEFINED !!!!!
		#endif

		/*
		 * Unroll the inner loop, this sometimes helps, sometimes hinders.
		 * Very mucy CPU dependant
		 */
		#if !defined(DES_UNROLL)
			version = DES_UNROLL;
		#endif

		/*
		 * These default values were supplied by
		 * Peter Gutman <pgut001@cs.auckland.ac.nz>
		 * They are only used if nothing else has been defined
		 */
		#if !defined(DES_PTR) && !defined(DES_RISC1) && !defined(DES_RISC2) && !defined(DES_UNROLL)
			/*
			 * Special defines which change the way the code is built depending on the
			 * CPU and OS.  For SGI machines you can use _MIPS_SZLONG (32 or 64) to find
			 * even newer MIPS CPU's, but at the moment one size fits all for
			 * optimization options.  Older Sparc's work better with only UNROLL, but
			 * there's no way to tell at compile time what it is you're running on
			 */
			#if defined(sun) /* Newer Sparc's */
				version = DES_PTR;
				version = DES_RISC1;
				version = DES_UNROLL;
			#elif defined(__ultrix) /* Older MIPS */
				version = DES_PTR;
				version = DES_RISC2;
				version = DES_UNROLL;
			#elif defined(__osf1__) /* Alpha */
				version = DES_PTR;
				version = DES_RISC2;
			#elif defined(_AIX) /* RS6000 */
				/* Unknown */
			#elif defined(__hpux) /* HP-PA */
				/* Unknown */
			#elif defined(__aux) /* 68K */
				/* Unknown */
			#elif defined(__dgux) /* 88K (but P6 in latest boxes) */
				version = DES_UNROLL;
			#elif defined(__sgi) /* Newer MIPS */
				version = DES_PTR;
				version = DES_RISC2;
				version = DES_UNROLL;
			#elif defined(i386) || defined(__i386__) /* x86 boxes, should be gcc */
				version = DES_PTR;
				version = DES_RISC1;
				version = DES_UNROLL;
			#endif /* Systems-specific speed defines */
		#endif
	#endif /* DES_DEFAULT_OPTIONS */
#endif /* HEADER_DES_LOCL_H */
+/
