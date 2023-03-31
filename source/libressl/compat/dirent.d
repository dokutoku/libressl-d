/*
 * Public domain
 * dirent.h compatibility shim
 */
module libressl.compat.dirent;


public import core.sys.posix.dirent;
public import core.sys.windows.windows;
public import libressl.compat.dirent_msvc;
