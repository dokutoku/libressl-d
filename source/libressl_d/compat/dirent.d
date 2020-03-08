/*
 * Public domain
 * dirent.h compatibility shim
 */
module libressl_d.compat.dirent;


public import core.sys.posix.dirent;
public import core.sys.windows.windows;
public import libressl_d.compat.dirent_msvc;
