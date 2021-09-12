bin_PROGRAMS = xlogin
xlogin_SOURCES = main.c getpass.c vfuncs.c
#xlogin_CFLAGS=-O3 -pipe -fomit-frame-pointer -pie -fpic -fstack-protector-strong
xlogin_LDADD=-lutil @LIBPAM@
#activate immediate binding
xlogin_LDFLAGS=-Wl,-z,relro,-z,now
