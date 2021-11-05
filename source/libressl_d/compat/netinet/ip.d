/*
 * Public domain
 * netinet/ip.h compatibility shim
 */
module libressl_d.compat.netinet.ip;


//#if defined(__hpux)
	//public import core.sys.posix.netinet.in_systm;
//#endif

//public import core.sys.posix.netinet.ip;
public import libressl_d.compat.win32netcompat;

/*
 * Definitions for DiffServ Codepoints as per RFC2474
 */
enum IPTOS_DSCP_CS0 = 0x00;
enum IPTOS_DSCP_CS1 = 0x20;
enum IPTOS_DSCP_CS2 = 0x40;
enum IPTOS_DSCP_CS3 = 0x60;
enum IPTOS_DSCP_CS4 = 0x80;
enum IPTOS_DSCP_CS5 = 0xA0;
enum IPTOS_DSCP_CS6 = 0xC0;
enum IPTOS_DSCP_CS7 = 0xE0;

enum IPTOS_DSCP_AF11 = 0x28;
enum IPTOS_DSCP_AF12 = 0x30;
enum IPTOS_DSCP_AF13 = 0x38;
enum IPTOS_DSCP_AF21 = 0x48;
enum IPTOS_DSCP_AF22 = 0x50;
enum IPTOS_DSCP_AF23 = 0x58;
enum IPTOS_DSCP_AF31 = 0x68;
enum IPTOS_DSCP_AF32 = 0x70;
enum IPTOS_DSCP_AF33 = 0x78;
enum IPTOS_DSCP_AF41 = 0x88;
enum IPTOS_DSCP_AF42 = 0x90;
enum IPTOS_DSCP_AF43 = 0x98;

enum IPTOS_DSCP_EF = 0xB8;
