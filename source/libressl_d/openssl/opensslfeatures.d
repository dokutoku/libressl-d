/*
 * Feature flags for LibreSSL... so you can actually tell when things
 * are enabled, rather than not being able to tell when things are
 * enabled (or possibly not yet not implemented, or removed!).
 */
module libressl_d.openssl.opensslfeatures;


version (none):

/* version = LIBRESSL_HAS_TLS1_3; */

version = OPENSSL_THREADS;

version = OPENSSL_NO_BUF_FREELISTS;
version = OPENSSL_NO_GMP;
version = OPENSSL_NO_JPAKE;
version = OPENSSL_NO_KRB5;
version = OPENSSL_NO_RSAX;
version = OPENSSL_NO_SHA0;
version = OPENSSL_NO_SSL2;
version = OPENSSL_NO_STORE;

/*
 * OPENSSL_NO_* flags that currently appear in OpenSSL.
 */

/* version = OPENSSL_NO_AFALGENG; */
/* version = OPENSSL_NO_ALGORITHMS; */
/* version = OPENSSL_NO_ARIA; */
/* version = OPENSSL_NO_ASM; */
version = OPENSSL_NO_ASYNC;
/* version = OPENSSL_NO_AUTOALGINIT; */
/* version = OPENSSL_NO_AUTOERRINIT; */
/* version = OPENSSL_NO_AUTOLOAD_CONFIG; */
/* version = OPENSSL_NO_BF; */
/* version = OPENSSL_NO_BLAKE2; */
/* version = OPENSSL_NO_CAMELLIA; */
/* version = OPENSSL_NO_CAST; */
/* version = OPENSSL_NO_CHACHA; */
/* version = OPENSSL_NO_CMAC; */
/* version = OPENSSL_NO_CMS; */
version = OPENSSL_NO_COMP; /* XXX */
/* version = OPENSSL_NO_CRYPTO_MDEBUG; */
/* version = OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE; */
/* version = OPENSSL_NO_CT; */
/* version = OPENSSL_NO_DECC_INIT; */
/* version = OPENSSL_NO_DES; */
/* version = OPENSSL_NO_DGRAM; */
/* version = OPENSSL_NO_DH; */
/* version = OPENSSL_NO_DSA; */
/* version = OPENSSL_NO_DSO; */
/* version = OPENSSL_NO_DTLS; */
/* version = OPENSSL_NO_DTLS1; */
/* version = OPENSSL_NO_DTLS1_2; */
/* version = OPENSSL_NO_DTLS1_2_METHOD; */
/* version = OPENSSL_NO_DTLS1_METHOD; */
version = OPENSSL_NO_DYNAMIC_ENGINE;
/* version = OPENSSL_NO_EC; */
/* version = OPENSSL_NO_EC2M; */
version = OPENSSL_NO_EC_NISTP_64_GCC_128;
version = OPENSSL_NO_EGD;
/* version = OPENSSL_NO_ENGINE; */
/* version = OPENSSL_NO_ERR; */
/* version = OPENSSL_NO_FUZZ_LIBFUZZER; */
/* version = OPENSSL_NO_GOST; */
version = OPENSSL_NO_HEARTBEATS;
/* version = OPENSSL_NO_HW; */
/* version = OPENSSL_NO_HW_PADLOCK; */
/* version = OPENSSL_NO_IDEA; */
version = OPENSSL_NO_MD2;
/* version = OPENSSL_NO_MD4; */
/* version = OPENSSL_NO_MD5; */
version = OPENSSL_NO_MDC2;
/* version = OPENSSL_NO_MULTIBLOCK; */
/* version = OPENSSL_NO_NEXTPROTONEG; */
/* version = OPENSSL_NO_OCB; */
/* version = OPENSSL_NO_OCSP; */
/* version = OPENSSL_NO_POLY1305; */
/* version = OPENSSL_NO_POSIX_IO; */
version = OPENSSL_NO_PSK;
/* version = OPENSSL_NO_RC2; */
/* version = OPENSSL_NO_RC4; */
version = OPENSSL_NO_RC5;
version = OPENSSL_NO_RFC3779;
/* version = OPENSSL_NO_RMD160; */
/* version = OPENSSL_NO_RSA; */
/* version = OPENSSL_NO_SCRYPT; */
version = OPENSSL_NO_SCTP;
version = OPENSSL_NO_SEED;
/* version = OPENSSL_NO_SIPHASH; */
/* version = OPENSSL_NO_SM2; */
/* version = OPENSSL_NO_SM3; */
/* version = OPENSSL_NO_SM4; */
/* version = OPENSSL_NO_SOCK; */
version = OPENSSL_NO_SRP;
/* version = OPENSSL_NO_SRTP; */
version = OPENSSL_NO_SSL3;
version = OPENSSL_NO_SSL3_METHOD;
/* version = OPENSSL_NO_SSL_TRACE; */
/* version = OPENSSL_NO_STDIO; */
/* version = OPENSSL_NO_TLS; */
/* version = OPENSSL_NO_TLS1; */
/* version = OPENSSL_NO_TLS1_1; */
/* version = OPENSSL_NO_TLS1_1_METHOD; */
/* version = OPENSSL_NO_TLS1_2; */
/* version = OPENSSL_NO_TLS1_2_METHOD; */

//#if !defined(LIBRESSL_HAS_TLS1_3)
version = OPENSSL_NO_TLS1_3;
//#endif

/* version = OPENSSL_NO_TLS1_METHOD; */
/* version = OPENSSL_NO_TS; */
/* version = OPENSSL_NO_UI_CONSOLE; */
/* version = OPENSSL_NO_UNIT_TEST; */
/* version = OPENSSL_NO_WEAK_SSL_CIPHERS; */
/* version = OPENSSL_NO_WHIRLPOOL; */
