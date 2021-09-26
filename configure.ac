#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

#AC_PREREQ([2.69])
AC_INIT([xlogin], [0.43.1], [crakem8@gmail.com],[xlogin],[github.com/Crakem])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_CONFIG_HEADERS([config.h])

# Change default CFLAGS
: ${CFLAGS="-O3 -pipe -fomit-frame-pointer -pie -fpic -fstack-protector-strong"}

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
#AC_CHECK_HEADERS( security/pam_appl.h security/pam_misc.h time.h )

#USE_PAM src/main.c
AC_ARG_WITH([pam],
            [AS_HELP_STRING([--without-pam],
              [disable support for pam])],
            [],
            [with_pam=yes])

          LIBPAM=
          AS_IF([test "x$with_pam" != xno],
            [AC_CHECK_LIB([pam], [main],
              [AC_SUBST([LIBPAM], ["-lpam -lpam_misc"]) #crea una makefile output variable
#               AC_DEFINE([HAVE_LIBPAM], [1],
               AC_DEFINE([USE_PAM], [1],
                         [Define if you have libpam])
              ],
              [AC_MSG_FAILURE(
                 [pam test failed (--without-pam to disable)])],
              [])],
	      [AC_SUBST([LIBPAM], ["-lcrypt"])])

#UTMP_GROUP_NAME src/main.c
AC_ARG_VAR([utmp_group_name],[Define utmp group name (found in /etc/passwd file). Defaults to 'utmp'])
AS_IF([test "x$utmp_group_name" != x],
[AC_DEFINE_UNQUOTED([UTMP_GROUP_NAME], ["$utmp_group_name"],[Custom utmp group name])],
[AC_DEFINE_UNQUOTED([UTMP_GROUP_NAME], ["utmp"],[Define default utmp group name as 'utmp'])]
)

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h paths.h shadow.h stddef.h stdlib.h string.h sys/vfs.h syslog.h termios.h unistd.h utmp.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([alarm dup2 getspnam gettimeofday memset putenv setenv socket strdup strerror strrchr strstr])

#AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

AC_OUTPUT
