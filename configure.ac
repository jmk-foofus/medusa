AC_INIT([medusa], [2.2])
AC_CONFIG_SRCDIR([src/medusa.c])
AM_CONFIG_HEADER(config.h)

dnl Detect the canonical host and target build environment
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([subdir-objects])

AC_LANG([C])
AC_PROG_CC

AC_HEADER_STDC

AC_CHECK_SIZEOF(int,cross)
AC_CHECK_SIZEOF(long,cross)
AC_CHECK_SIZEOF(long long,cross)
AC_CHECK_SIZEOF(short,cross)

CFLAGS="${CFLAGS=}"
AC_MSG_CHECKING(whether to enable debugging)
debug_default="yes"
AC_ARG_ENABLE(debug, [  --enable-debug=[no/yes] turn on debugging (default=yes)],, enable_debug=$debug_default)
if test "x$enable_debug" = "xyes"; then
  CPPFLAGS="$CPPFLAGS -g -DDEBUG"
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

AC_ARG_WITH(postgresql, AS_HELP_STRING([--with-postgresql=prefix],[Prefix for postgresql include directory (default = /usr)]), [postgresql_prefix="$withval"], [postgresql_prefix="/usr"])
AC_ARG_WITH(afpfsng, AS_HELP_STRING([--with-afpfsng=prefix],[Prefix for afpfs-ng include directory (default = /usr)]), [afpfsng_prefix="$withval"], [afpfsng_prefix="/usr"])

dnl FreeBSD was not looking in /usr/local...
dnl AC_SEARCH_LIBS ?
if test -d "/usr/local/lib"
  then LDFLAGS="$LDFLAGS -L/usr/local/lib"
fi

CPPFLAGS="$CPPFLAGS -fPIC"
CPPFLAGS="$CPPFLAGS -I/usr/include -I/usr/local/include -I${postgresql_prefix}/include/postgresql -I${postgresql_prefix}/include/pgsql -I${afpfsng_prefix}/include/afpfs-ng"

AS_MESSAGE([checking for pthread support...])
AC_CHECK_LIB(pthread, main, [], [AC_MSG_ERROR([ *** Application requires pthread support *** ])])

AS_MESSAGE([checking for dlopen/dlclose...])
AC_CHECK_LIB(dl, dlclose,
  [], 
  [AC_CHECK_LIB(c, dlclose, 
    [],
    [AC_MSG_ERROR([ *** Application requires dlopen/dlclose (e.g. libdl) *** ])])
  ]
)

dnl MacPorts
if test -d "/opt/local"; then
  CPPFLAGS="$CPPFLAGS -I/opt/local/include"
  LDFLAGS="$LDFLAGS -L/opt/local/lib"
fi

dnl Mac OS X doesn't have clock_gettime()
AC_SEARCH_LIBS(clock_gettime, [rt])
AC_CHECK_FUNCS(clock_gettime, [], [AC_MSG_WARN([ No clock_gettime(), using gettimeofday() instead ])])

dnl ********** OpenSSL Checks ********** 
check_libssl="false"

AS_MESSAGE([checking for OpenSSL Library and Header files...])

check_ssl_dir() { :
  AC_MSG_CHECKING([$1/include/openssl/ssh.h])
  if test -f "$1/include/openssl/ssl.h"
  then
    AC_MSG_RESULT([found])
    CPPFLAGS="$CPPFLAGS -I$1/include"
    LDFLAGS="$LDFLAGS -L$1/lib"
    return 0
  else
    AC_MSG_RESULT([not found])
    return 1
  fi
}

AC_ARG_WITH(ssl, AS_HELP_STRING([--with-ssl=prefix],[Prefix for OpenSSL libraries]), 
  [check_ssl_dir "$withval"], 
  [
    for main_dir in /usr /usr/local /usr/lib /usr/pkg /opt/local /usr/local/opt /opt; do
      for sub_dir in / /ssl /openssl; do
        check_ssl_dir "$main_dir$sub_dir" && break 2
      done
    done
  ]
)

AC_CHECK_LIB(crypto, CRYPTO_lock, [], [AC_MSG_WARN([ *** LibCrypto may be required for *BSD ***])])
AC_CHECK_HEADER([openssl/ssl.h], 
  [AC_CHECK_LIB(ssl, main,
    [AC_DEFINE(HAVE_LIBSSL, 1, [Found OpenSSL Library]) LIBS="$LIBS -lssl -lcrypto" check_libssl="true"],
    [AC_MSG_WARN([ *** OpenSSL library required for SSL support. ***

      Many of the Medusa modules depend on the OpenSSL library and header files. If
      multiple modules are unexpectedly disabled, this is likely the cause. Make sure
      to install libssl-dev, openssl-devel or whatever package your distribution uses
      to distribute these files.

      If the headers are installed in a non-standard location, specify the path with
      "--with-ssl".

    ])]
  )],
  [AC_MSG_WARN([ *** OpenSSL header files required for SSL support. ***
  
    Many of the Medusa modules depend on the OpenSSL library and header files. If
    multiple modules are unexpectedly disabled, this is likely the cause. Make sure
    to install libssl-dev, openssl-devel or whatever package your distribution uses
    to distribute these files.
  
    If the headers are installed in a non-standard location, specify the path with
    "--with-ssl".

  ])]
)

AC_MSG_NOTICE([*** Checking module dependencies and enabling accordingly ***])

dnl ********** AFP Medusa Module Option Checks ********** 
check_module_afp="false"

AS_MESSAGE([checking for AFPFS-NG Library and Header files...])
AC_CHECK_HEADER([afpfs-ng/afp_protocol.h], 
  [AC_CHECK_LIB(afpclient, main,
    [AC_DEFINE(HAVE_LIBAFPFS, 1, [Found AFPFS-NG Library]) MODULE_LIBS="$MODULE_LIBS -lafpclient" check_module_afp="true"],
    [AC_MSG_WARN([ *** AFPFS-NG library required for AFP module. ***
      
      The AFPFS-NG package must be installed for the AFP module to function. This includes
      both the library and header files. AFPFS-NG is available at the following site:
      http://alexthepuffin.googlepages.com/. The AFP module will NOT be built.

    ])]
  )],
  [AC_MSG_WARN([ *** AFPFS-NG header files required for AFP module. ***
    
    The AFPFS-NG package must be installed for the AFP module to function. This includes
    both the library and header files. AFPFS-NG is available at the following site:
    http://alexthepuffin.googlepages.com/. The AFP module will NOT be built.
  
  ])]
)

AC_MSG_CHECKING(whether to enable AFP module)
AC_ARG_ENABLE(module-afp, 
              [  --enable-module-afp=[no/yes]            Enable AFP module (default=no)],
              [case "${enableval}" in
                yes) enable_module_afp=true ;;
                no)  enable_module_afp=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-afp]) ;;
              esac],
              [enable_module_afp=$check_module_afp])

AM_CONDITIONAL(BUILD_MODULE_AFP, test x"$enable_module_afp" = "xtrue")
if test x"$enable_module_afp" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** CVS Medusa Module Option Checks ********** 
AC_MSG_CHECKING(whether to enable CVS module)
AC_ARG_ENABLE(module-cvs, 
              [  --enable-module-cvs=[no/yes]            Enable CVS module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_cvs=true ;;
                no)  enable_module_cvs=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-cvs]) ;;
              esac],
              [enable_module_cvs="true"])

AM_CONDITIONAL(BUILD_MODULE_CVS, test x"$enable_module_cvs" = "xtrue")
if test x"$enable_module_cvs" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** FTP Medusa Module ********** 
AC_MSG_CHECKING(whether to enable FTP module)
AC_ARG_ENABLE(module-ftp, 
              [  --enable-module-ftp=[no/yes]            Enable FTP module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_ftp=true ;;
                no)  enable_module_ftp=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-ftp]) ;;
              esac],
              [enable_module_ftp="true"])

AM_CONDITIONAL(BUILD_MODULE_FTP, test x"$enable_module_ftp" = "xtrue")
if test x"$enable_module_ftp" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** HTTP Medusa Module ********** 
check_module_http=$check_libssl

AC_MSG_CHECKING(whether to enable HTTP module)
AC_ARG_ENABLE(module-http, 
              [  --enable-module-http=[no/yes]           Enable HTTP module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_http=true ;;
                no)  enable_module_http=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-http]) ;;
              esac],
              [enable_module_http=$check_module_http])

AM_CONDITIONAL(BUILD_MODULE_HTTP, test x"$enable_module_http" = "xtrue")
if test x"$enable_module_http" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** IMAP Medusa Module ********** 
AC_MSG_CHECKING(whether to enable IMAP module)
AC_ARG_ENABLE(module-imap, 
              [  --enable-module-imap=[no/yes]           Enable IMAP module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_imap=true ;;
                no)  enable_module_imap=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-imap]) ;;
              esac],
              [enable_module_imap="true"])

AM_CONDITIONAL(BUILD_MODULE_IMAP, test x"$enable_module_imap" = "xtrue")
if test x"$enable_module_imap" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** MSSQL Medusa Module ********** 
check_module_mssql=$check_libssl

AC_MSG_CHECKING(whether to enable MSSQL module)
AC_ARG_ENABLE(module-mssql, 
              [  --enable-module-mssql=[no/yes]          Enable MSSQL module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_mssql=true ;;
                no)  enable_module_mssql=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-mssql]) ;;
              esac],
              [enable_module_mssql=$check_module_mssql])

AM_CONDITIONAL(BUILD_MODULE_MSSQL, test x"$enable_module_mssql" = "xtrue")
if test x"$enable_module_mssql" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** MYSQL Medusa Module ********** 
AC_MSG_CHECKING(whether to enable MYSQL module)
AC_ARG_ENABLE(module-mysql, 
              [  --enable-module-mysql=[no/yes]          Enable MYSQL module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_mysql=true ;;
                no)  enable_module_mysql=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-mysql]) ;;
              esac],
              [enable_module_mysql="true"])

AM_CONDITIONAL(BUILD_MODULE_MYSQL, test x"$enable_module_mysql" = "xtrue")
if test x"$enable_module_mysql" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** NCP Medusa Module ********** 
check_module_ncp="false"

AS_MESSAGE([checking for NCPFS Library and Header files...])
AC_CHECK_HEADER([ncp/nwcalls.h], 
  [AC_CHECK_LIB(ncp, main,
    [AC_DEFINE(HAVE_LIBNCP, 1, [Found NCP Library]) MODULE_LIBS="$MODULE_LIBS -lncp" check_module_ncp="true"],
    [AC_MSG_WARN([ *** NCPFS library required for NCP module. ***
      
      The NCPFS package must be installed for the NCP module to function. This includes
      both the library and header files. If your distribution does not include these
      files or offer a ncpfs-devel package, the files can be manually installed using 
      "make install-dev" within the NCPFS source. The NCP module will NOT be built.

    ])]
  )],
  [AC_MSG_WARN([ *** NCPFS header files required for NCP module. ***
    
    The NCPFS package must be installed for the NCP module to function. This includes
    both the library and header files. If your distribution does not include these
    files or offer a ncpfs-devel package, the files can be manually installed using 
    "make install-dev" within the NCPFS source. The NCP module will NOT be built.
  
  ])]
)

AC_MSG_CHECKING(whether to enable NCP module)
AC_ARG_ENABLE(module-ncp, 
              [  --enable-module-ncp=[no/yes]            Enable NCP module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_ncp=true ;;
                no)  enable_module_ncp=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-ncp]) ;;
              esac],
              [enable_module_ncp=$check_module_ncp])

AM_CONDITIONAL(BUILD_MODULE_NCP, test x"$enable_module_ncp" = "xtrue")
if test x"$enable_module_ncp" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** NNTP Medusa Module ********** 
AC_MSG_CHECKING(whether to enable NNTP module)
AC_ARG_ENABLE(module-nntp, 
              [  --enable-module-nntp=[no/yes]           Enable NNTP module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_nntp=true ;;
                no)  enable_module_nntp=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-nntp]) ;;
              esac],
              [enable_module_nntp="true"])

AM_CONDITIONAL(BUILD_MODULE_NNTP, test x"$enable_module_nntp" = "xtrue")
if test x"$enable_module_nntp" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** PCANYWHERE Medusa Module ********** 
AC_MSG_CHECKING(whether to enable PCANYWHERE module)
AC_ARG_ENABLE(module-pcanywhere, 
              [  --enable-module-pcanywhere=[no/yes]     Enable PCANYWHERE module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_pcanywhere=true ;;
                no)  enable_module_pcanywhere=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-pcanywhere]) ;;
              esac],
              [enable_module_pcanywhere="true"])

AM_CONDITIONAL(BUILD_MODULE_PCANYWHERE, test x"$enable_module_pcanywhere" = "xtrue")
if test x"$enable_module_pcanywhere" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** POP3 Medusa Module ********** 
AC_MSG_CHECKING(whether to enable POP3 module)
AC_ARG_ENABLE(module-pop3, 
              [  --enable-module-pop3=[no/yes]           Enable POP3 module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_pop3=true ;;
                no)  enable_module_pop3=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-pop3]) ;;
              esac],
              [enable_module_pop3="true"])

AM_CONDITIONAL(BUILD_MODULE_POP3, test x"$enable_module_pop3" = "xtrue")
if test x"$enable_module_pop3" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** POSTGRES Medusa Module ********** 
check_module_postgres="false"

AS_MESSAGE([checking for PostgreSQL Library and Header files...])
AC_CHECK_HEADER([libpq-fe.h], 
  [AC_CHECK_LIB(pq, main,
    [AC_DEFINE(HAVE_LIBPQ, 1, [Found PostgreSQL Library]) MODULE_LIBS="$MODULE_LIBS -lpq" check_module_postgres="true"],
    [AC_MSG_WARN([ *** LIBPQ library required for PostgreSQL module. ***
     
      The PostgreSQL package must be installed for the PostgreSQL module to function. This 
      includes both the library and header files. Your distribution may offer a package
      such as libpq-devel or postgresql-devel, which will provide these files.

    ])]
  )],
  [AC_MSG_WARN([ *** LIBPQ header files required for PostgreSQL module. ***
     
      The PostgreSQL package must be installed for PostgreSQL module to function. This 
      includes both the library and header files. Your distribution may offer a package
      such as libpq-devel or postgresql-devel, which will provide these files.
  
  ])]
)

AC_MSG_CHECKING(whether to enable POSTGRES module)
AC_ARG_ENABLE(module-postgres, 
              [  --enable-module-postgres=[no/yes]       Enable POSTGRES module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_postgres=true ;;
                no)  enable_module_postgres=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-postgres]) ;;
              esac],
              [enable_module_postgres=$check_module_postgres])

AM_CONDITIONAL(BUILD_MODULE_POSTGRES, test x"$enable_module_postgres" = "xtrue")
if test x"$enable_module_postgres" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** RDP Medusa Module ********** 
check_module_rdp="false"
module_rdp_headers="false"

dnl https://ci.freerdp.com - Nightly FreeRDP master builds 
if test -d "/opt/freerdp-nightly"; then
  CPPFLAGS="$CPPFLAGS -I/opt/freerdp-nightly/include"
  LDFLAGS="$LDFLAGS -L/opt/freerdp-nightly/lib"
fi

case "$target" in
  *apple-darwin*)
    LDFLAGS="$LDFLAGS -L/usr/local/lib/freerdp"
    RDP_LIBS="-lfreerdp -lwinpr -lfreerdp-client -laudin-client -ldisp-client -lecho-client -lrdpei-client -lrdpgfx-client -ltsmf-client -lcliprdr-client -ldrdynvc-client -lencomsp-client -lrail-client -lrdpdr-client -lrdpsnd-client -lremdesk-client -ldrive-client -lparallel-client -lserial-client -lsmartcard-client"
    ;;
  *)
    ;;
esac
MODULE_LIBS="$MODULE_LIBS $RDP_LIBS"

AS_MESSAGE([checking for FreeRDP Library and Header files...])
module_rdp_headers="false"

AC_CHECK_HEADER([freerdp/freerdp.h], [module_rdp_headers="true"],
  [
    AC_MSG_WARN([ *** FreeRDP header files required for RDP module. ***

        The FreeRDP package must be installed for RDP module to function. This
        includes both the library and header files. Your distribution may offer
        packages such as freerdp and libfreerdp-dev, which will provide these files.

    ])
  ]
)

if test x"$module_rdp_headers" = "xtrue"; then
  AC_MSG_NOTICE([ *** Checking for FreeRDP libraries. *** ])
  AC_CHECK_LIB(winpr, main, [], [])
  AC_CHECK_LIB(freerdp, main, [], [])
  AC_CHECK_LIB(freerdp-channels, main, [], [])
  AC_CHECK_LIB(freerdp-client, main, [], [])
  AC_CHECK_LIB(freerdp-core, main, [], [])
  AC_CHECK_LIB(freerdp-gdi, main, [], [])

  AS_MESSAGE([checking for FreeRDP library version 1.2...])
  AC_SEARCH_LIBS(WLog_CallbackAppender_SetCallbacks, winpr,
    [
      AC_DEFINE(HAVE_LIBFREERDP12, 1, [Found FreeRDP Library (version >= 1.2)])
      AC_MSG_NOTICE([ *** Detected FreeRDP library version 1.2. *** ])
      check_module_rdp="true"
    ],
    [],
    [$MODULE_LIBS $RDP_LIBS]
  )

  if test x"$check_module_rdp" = "xfalse"; then
    AS_MESSAGE([checking for FreeRDP library version 1.1 (with pass-the-hash)...])
    AC_SEARCH_LIBS(nego_set_restricted_admin_mode_required, freerdp-client,
      [
        AC_DEFINE(HAVE_LIBFREERDP11PTH, 1, [Found FreeRDP Library (version 1.1 PTH)])
        AC_MSG_NOTICE([ *** Detected FreeRDP library version 1.1 (with pass-the-hash). *** ])
        check_module_rdp="true"
      ],
      [],
      [$MODULE_LIBS $RDP_LIBS]
    )
  fi

  if test x"$check_module_rdp" = "xfalse"; then
    AS_MESSAGE([checking for FreeRDP library version 1.1...])
    AC_CHECK_LIB(freerdp-client, main,
      [
        AC_DEFINE(HAVE_LIBFREERDP11, 1, [Found FreeRDP Library (version 1.1)])
        AC_MSG_WARN([ *** Detected FreeRDP library version 1.1. *** 
       
            FreeRDP introduced pass-the-hash support with version 1.2. The version
            detected on this system is prior to that release. The RDP module will
            function, but the pass-the-hash option will be disabled.

        ])
        check_module_rdp="true"
      ],
      []
    )
  fi

  if test x"$check_module_rdp" = "xfalse"; then
    AS_MESSAGE([checking for FreeRDP library version 1.0...])
    AC_CHECK_LIB(freerdp-core, main,
      [
        AC_DEFINE(HAVE_LIBFREERDP10, 1, [Found FreeRDP Library (version 1.0)])
        AC_MSG_WARN([ *** Detected FreeRDP library version 1.0. *** 
       
            FreeRDP introduced pass-the-hash support with version 1.2. The version
            detected on this system is prior to that release. The RDP module will
            function, but the pass-the-hash option will be disabled.

            It should also be noted that FreeRDP 1.0 prints all error messages
            to stdout. Medusa is unable to suppress these, which can lead to 
            extraneous information being displayed.

        ])
        check_module_rdp="true"
      ],
      [
        AC_MSG_WARN([ *** FreeRDP library required for RDP module. *** 

            The FreeRDP package must be installed for the RDP module to function. This
            includes both the library and header files. Your distribution may offer 
            packages such as freerdp and libfreerdp-dev, which will provide these files.

        ])
      ]
    )
  fi
fi

case "$target" in
  *apple-darwin*)
    AS_MESSAGE([RDP module is currently broken on OS X and disabled by default.])
    check_module_rdp="false"
    ;;
esac

AC_MSG_CHECKING(whether to enable RDP module)
AC_ARG_ENABLE(module-rdp, 
              [  --enable-module-rdp=[no/yes]            Enable RDP module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_rdp=true ;;
                no)  enable_module_rdp=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-rdp]) ;;
              esac],
              [enable_module_rdp=$check_module_rdp])

AM_CONDITIONAL(BUILD_MODULE_RDP, test x"$enable_module_rdp" = "xtrue")
if test x"$enable_module_rdp" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** REXEC Medusa Module ********** 
AC_MSG_CHECKING(whether to enable REXEC module)
AC_ARG_ENABLE(module-rexec, 
              [  --enable-module-rexec=[no/yes]          Enable REXEC module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_rexec=true ;;
                no)  enable_module_rexec=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-rexec]) ;;
              esac],
              [enable_module_rexec="true"])

AM_CONDITIONAL(BUILD_MODULE_REXEC, test x"$enable_module_rexec" = "xtrue")
if test x"$enable_module_rexec" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** RLOGIN Medusa Module ********** 
AC_MSG_CHECKING(whether to enable RLOGIN module)
AC_ARG_ENABLE(module-rlogin, 
              [  --enable-module-rlogin=[no/yes]         Enable RLOGIN module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_rlogin=true ;;
                no)  enable_module_rlogin=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-rlogin]) ;;
              esac],
              [enable_module_rlogin="true"])

AM_CONDITIONAL(BUILD_MODULE_RLOGIN, test x"$enable_module_rlogin" = "xtrue")
if test x"$enable_module_rlogin" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** RSH Medusa Module ********** 
AC_MSG_CHECKING(whether to enable RSH module)
AC_ARG_ENABLE(module-rsh, 
              [  --enable-module-rsh=[no/yes]            Enable RSH module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_rsh=true ;;
                no)  enable_module_rsh=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-rsh]) ;;
              esac],
              [enable_module_rsh="true"])

AM_CONDITIONAL(BUILD_MODULE_RSH, test x"$enable_module_rsh" = "xtrue")
if test x"$enable_module_rsh" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** SMBNT Medusa Module ********** 
check_module_smbnt=$check_libssl

AC_MSG_CHECKING(whether to enable SMBNT module)
AC_ARG_ENABLE(module-smbnt, 
              [  --enable-module-smbnt=[no/yes]          Enable SMBNT module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_smbnt=true ;;
                no)  enable_module_smbnt=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-smbnt]) ;;
              esac],
              [enable_module_smbnt=$check_module_smbnt])

AM_CONDITIONAL(BUILD_MODULE_SMBNT, test x"$enable_module_smbnt" = "xtrue")
if test x"$enable_module_smbnt" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** SMTP Medusa Module ********** 
AC_MSG_CHECKING(whether to enable SMTP module)
AC_ARG_ENABLE(module-smtp, 
              [  --enable-module-smtp=[no/yes]           Enable SMTP module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_smtp=true ;;
                no)  enable_module_smtp=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-smtp]) ;;
              esac],
              [enable_module_smtp="true"])

AM_CONDITIONAL(BUILD_MODULE_SMTP, test x"$enable_module_smtp" = "xtrue")
if test x"$enable_module_smtp" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** SMTP-VRFY Medusa Module ********** 
AC_MSG_CHECKING(whether to enable SMTP-VRFY module)
AC_ARG_ENABLE(module-smtp-vrfy, 
              [  --enable-module-smtp-vrfy=[no/yes]      Enable SMTP-VRFY module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_smtp_vrfy=true ;;
                no)  enable_module_smtp_vrfy=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-smtp-vrfy]) ;;
              esac],
              [enable_module_smtp_vrfy="true"])

AM_CONDITIONAL(BUILD_MODULE_SMTP_VRFY, test x"$enable_module_smtp_vrfy" = "xtrue")
if test x"$enable_module_smtp_vrfy" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** SNMP Medusa Module ********** 
AC_MSG_CHECKING(whether to enable SNMP module)
AC_ARG_ENABLE(module-snmp, 
              [  --enable-module-snmp=[no/yes]           Enable SNMP module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_snmp=true ;;
                no)  enable_module_snmp=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-snmp]) ;;
              esac],
              [enable_module_snmp="true"])

AM_CONDITIONAL(BUILD_MODULE_SNMP, test x"$enable_module_snmp" = "xtrue")
if test x"$enable_module_snmp" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** SSH Medusa Module ********** 
check_module_ssh="false"

AS_MESSAGE([checking for Libssh2 Library files...])
AC_CHECK_LIB(ssh2, main, 
             [AC_DEFINE(HAVE_LIBSSH2, 1, [Found SSH2 Library]) MODULE_LIBS="$MODULE_LIBS -lssh2" check_module_ssh="true"],
             [AC_MSG_WARN([ *** Libssh2 required for SSH2 module. ***

  Libssh2 (http://www.libssh2.org) is not the same as libssh (http://0xbadc0de.be).
  Make sure you have the correct library. The SSH2 module will NOT be built.

  ])]
)

dnl Test whether libssh2 was built with libgcrypt
if test x"$check_module_ssh" = "xtrue"; then
  check_libgcrypt="false"
  
  if test -f "/usr/lib/libssh2.so"; then
    LIBSSH2_PATH="/usr/lib/libssh2.so"
  elif test -f "/usr/local/lib/libssh2.so"; then
    LIBSSH2_PATH="/usr/local/lib/libssh2.so"
  elif test -f "/usr/lib/x86_64-linux-gnu/libssh2.so"; then
    LIBSSH2_PATH="/usr/lib/x86_64-linux-gnu/libssh2.so"
  elif test -f "/opt/local/lib/libssh2.dylib"; then
    LIBSSH2_PATH="/opt/local/lib/libssh2.dylib"
  elif test -f "/usr/local/lib/libssh2.dylib"; then
    LIBSSH2_PATH="/usr/local/lib/libssh2.dylib"
  else
    AC_MSG_WARN([ LIBSSH2 path not found. Assuming it was... ])
  fi  

  dnl Use otool on Mac OS X
  if test -f "`which ldd`"; then
    LDD="ldd"
  elif test -f "`which otool`"; then
    LDD="otool -L"
  else
    AC_MSG_WARN([ No ldd detected. Unable to test whether Libssh2 was compiled to use libgcrypt. Assuming it was... ])
    check_libgcrypt="true"
  fi

  if test ! -z "`$LDD $LIBSSH2_PATH |grep libgcrypt`"; then
    AC_MSG_WARN([ Libssh2 compiled using libgcrypt. Checking additional dependencies. ])
    check_libgcrypt="true"
  fi

 if test x"$check_libgcrypt" = "xtrue"; then
    AS_MESSAGE([checking for Libgrcypt Library files...])
    AC_CHECK_LIB(gcrypt, gcry_control, 
                 [AC_DEFINE(HAVE_LIBGCRYPT, 1, [Found Libgcrypt Library]) LIBS="$LIBS -lgcrypt"],
                 [AC_MSG_WARN([ *** Libgcrypt required for installed version of Libssh2 ***

        The default build of Libssh2 is to use OpenSSL for crypto. Several Linux
        distributions (e.g. Debian, Ubuntu) build it to use Libgcrypt. In order to
        use libssh2 in a thread-safe manner, we need to link to Libgcrypt and 
        properly initialize it.

        Make sure you have the Libgcrypt/GnuTLS libraries and headers (e.g. libgcrypt11-dev). 
        The SSH2 module will NOT be built.

      ]) 
      check_module_ssh="false"
    ])

    AS_MESSAGE([checking for GnuTLS Library files...])
    AC_CHECK_LIB(gnutls, gnutls_handshake, 
                 [AC_DEFINE(HAVE_GNUTLS, 1, [Found GnuTLS Library]) LIBS="$LIBS -lgnutls"],
                 [AC_MSG_WARN([ *** GnuTLS required for installed version of Libssh2 ***

        The default build of Libssh2 is to use OpenSSL for crypto. Several Linux
        distributions (e.g. Debian, Ubuntu) build it to use Libgcrypt. In order to
        use libssh2 in a thread-safe manner, we need to link to Libgcrypt and 
        properly initialize it.

        Make sure you have the Libgcrypt/GnuTLS libraries and headers (e.g. libgnutls-dev). 
        The SSH2 module will NOT be built.

      ]) 
      check_module_ssh="false"
    ])
  fi 
fi

AC_MSG_CHECKING(whether to enable SSH module)
AC_ARG_ENABLE(module-ssh, 
              [  --enable-module-ssh=[no/yes]            Enable SSH module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_ssh=true ;;
                no)  enable_module_ssh=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-ssh]) ;;
              esac],
              [enable_module_ssh=$check_module_ssh])

AM_CONDITIONAL(BUILD_MODULE_SSH, test x"$enable_module_ssh" = "xtrue")
if test x"$enable_module_ssh" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** SVN Medusa Module ********** 
check_module_svn="false"

AS_MESSAGE([checking for Subversion Library and Header files...])
AC_PATH_PROG(APR_CONFIG, apr-1-config)
if test -z "$APR_CONFIG"; then
  AC_PATH_PROG(APR_CONFIG, apr-config)
  if test -z "$APR_CONFIG"; then
    AC_MSG_WARN([ *** apr-config/apr-1-config not found and required for SVN module ***

      Make sure to install libapr1-dev or whatever package your distribution uses
      to distribute this file.

    ])
  fi
fi
  
if test -n "$APR_CONFIG"; then

  if test x`$APR_CONFIG --cc` = "xcc"; then
    AC_MSG_WARN([ *** Apache (apr) was compiled using Sun C compiler and not GNU gcc. *** 
      
    "$APR_CONFIG --cc" responded with "cc", which usually means that your build of Apache 
    was compiled with Sun C compiler and not with gcc. This means that the version of libtool 
    embedded within Apache installation is also configured for Sun C compiler and not gcc. 
    The Sun C compiler setup is incompatible because the options to each compiler are
    different for building shared objects and libraries. Specifically, the Sun compiler
    supports the "-mt" flag, whereas gcc does not. In order to build the SVN Medusa 
    module, rebuild $APR_CONFIG using gcc, or remove the "-mt" CPPFLAGS flag from the
    autogenerated Medusa configuration files.

    ])
  else
    APR_INCLUDE_DIR=`$APR_CONFIG --includedir`
    AC_SUBST(APR_INCLUDE_DIR)
    CPPFLAGS="$CPPFLAGS `$APR_CONFIG --includes --cppflags`"

    AC_CHECK_HEADER([$APR_INCLUDE_DIR/apr_tables.h], 
      [AC_CHECK_HEADER([subversion-1/svn_client.h], 
        [AC_CHECK_LIB(svn_client-1, main,
          [AC_DEFINE(HAVE_LIBSVN_CLIENT_1, 1, [Found SVN Library]) MODULE_LIBS="$MODULE_LIBS -lsvn_client-1" check_module_svn="true"],
          [AC_MSG_WARN([ *** Subversion libsvn library required for SVN module. *** ])]
        )],
        [AC_MSG_WARN([ *** Subversion header files required for SVN module. (e.g., libsvn-dev) *** ])])],
      [AC_MSG_WARN([ *** APR header files required for SVN module. (e.g., libapr1-dev) *** ])]
    )
  fi
else
  check_module_svn="false"
fi

if test x"$check_module_svn" = "xtrue"; then
  AC_CHECK_LIB(svn_client-1, svn_client_list3,
    [AC_DEFINE(HAVE_SVN_CLIENT_LIST3, 1, [Found SVN Library version 1.8 or greater])],
    [AC_MSG_WARN([Found SVN Library older than version 1.8])]
  )
fi
    

AC_MSG_CHECKING(whether to enable SVN module)
AC_ARG_ENABLE(module-svn, 
              [  --enable-module-svn=[no/yes]            Enable SVN module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_svn=true ;;
                no)  enable_module_svn=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-svn]) ;;
              esac],
              [enable_module_svn=$check_module_svn])

AM_CONDITIONAL(BUILD_MODULE_SVN, test x"$enable_module_svn" = "xtrue")
if test x"$enable_module_svn" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** TELNET Medusa Module ********** 
AC_MSG_CHECKING(whether to enable TELNET module)
AC_ARG_ENABLE(module-telnet, 
              [  --enable-module-telnet=[no/yes]         Enable TELNET module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_telnet=true ;;
                no)  enable_module_telnet=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-telnet]) ;;
              esac],
              [enable_module_telnet="true"])

AM_CONDITIONAL(BUILD_MODULE_TELNET, test x"$enable_module_telnet" = "xtrue")
if test x"$enable_module_telnet" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** VMAUTHD Medusa Module ********** 
AC_MSG_CHECKING(whether to enable VMAUTHD module)
AC_ARG_ENABLE(module-vmauthd, 
              [  --enable-module-vmauthd=[no/yes]        Enable VMAUTHD module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_vmauthd=true ;;
                no)  enable_module_vmauthd=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-vmauthd]) ;;
              esac],
              [enable_module_vmauthd="true"])

AM_CONDITIONAL(BUILD_MODULE_VMAUTHD, test x"$enable_module_vmauthd" = "xtrue")
if test x"$enable_module_vmauthd" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** VNC Medusa Module ********** 
check_module_vnc=$check_libssl

AC_MSG_CHECKING(whether to enable VNC module)
AC_ARG_ENABLE(module-vnc, 
              [  --enable-module-vnc=[no/yes]            Enable VNC module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_vnc=true ;;
                no)  enable_module_vnc=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-vnc]) ;;
              esac],
              [enable_module_vnc=$check_module_vnc])

AM_CONDITIONAL(BUILD_MODULE_VNC, test x"$enable_module_vnc" = "xtrue")
if test x"$enable_module_vnc" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** WRAPPER Medusa Module ********** 
AC_MSG_CHECKING(whether to enable WRAPPER module)
AC_ARG_ENABLE(module-wrapper, 
              [  --enable-module-wrapper=[no/yes]        Enable WRAPPER module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_wrapper=true ;;
                no)  enable_module_wrapper=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-wrapper]) ;;
              esac],
              [enable_module_wrapper="true"])

AM_CONDITIONAL(BUILD_MODULE_WRAPPER, test x"$enable_module_wrapper" = "xtrue")
if test x"$enable_module_wrapper" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ********** Web Form Medusa Module ********** 
check_module_web_form=$check_libssl

AC_MSG_CHECKING(whether to enable WEB-FORM module)
AC_ARG_ENABLE(module-web-form, 
              [  --enable-module-web-form=[no/yes]       Enable WEB-FORM module (default=yes)],
              [case "${enableval}" in
                yes) enable_module_web_form=true ;;
                no)  enable_module_web_form=false ;;
                *)   AC_MSG_ERROR([bad value ${enableval} for --enable-module-web-form]) ;;
              esac],
              [enable_module_web_form=$check_module_web_form])

AM_CONDITIONAL(BUILD_MODULE_WEB_FORM, test x"$enable_module_web_form" = "xtrue")
if test x"$enable_module_web_form" = "xtrue"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

AC_MSG_NOTICE([])
AC_MSG_NOTICE([*******************************************************])
AC_MSG_NOTICE([    Medusa Module Build Summary])
AC_MSG_NOTICE([])

show_build_status()
{
  if test "$1" = "true" ; then
    AC_MSG_NOTICE([$2 Enabled])
  else
    AC_MSG_NOTICE([$2 ** Disabled **])
  fi
}

show_build_status "${enable_module_afp}"        "    AFP            "
show_build_status "${enable_module_cvs}"        "    CVS            "
show_build_status "${enable_module_ftp}"        "    FTP            "
show_build_status "${enable_module_http}"       "    HTTP           "
show_build_status "${enable_module_imap}"       "    IMAP           "
show_build_status "${enable_module_mssql}"      "    MSSQL          "
show_build_status "${enable_module_mysql}"      "    MYSQL          "
show_build_status "${enable_module_ncp}"        "    NCP            "
show_build_status "${enable_module_nntp}"       "    NNTP           "
show_build_status "${enable_module_pcanywhere}" "    PCANYWHERE     "
show_build_status "${enable_module_pop3}"       "    POP3           "
show_build_status "${enable_module_postgres}"   "    POSTGRES       "
show_build_status "${enable_module_rdp}"        "    RDP            "
show_build_status "${enable_module_rexec}"      "    REXEC          "
show_build_status "${enable_module_rlogin}"     "    RLOGIN         "
show_build_status "${enable_module_rsh}"        "    RSH            "
show_build_status "${enable_module_smbnt}"      "    SMBNT          "
show_build_status "${enable_module_smtp}"       "    SMTP           "
show_build_status "${enable_module_smtp_vrfy}"  "    SMTP-VRFY      "
show_build_status "${enable_module_snmp}"       "    SNMP           "
show_build_status "${enable_module_ssh}"        "    SSH            "
show_build_status "${enable_module_svn}"        "    SVN            "
show_build_status "${enable_module_telnet}"     "    TELNET         "
show_build_status "${enable_module_vmauthd}"    "    VMAUTHD        "
show_build_status "${enable_module_vnc}"        "    VNC            "
show_build_status "${enable_module_wrapper}"    "    WRAPPER        "
show_build_status "${enable_module_web_form}"   "    WEB-FORM       "

AC_MSG_NOTICE([])
AC_MSG_NOTICE([ If a module is unexpectedly marked as disabled, check ])
AC_MSG_NOTICE([ above output and verify dependancies were satisfied. ])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([ It should also be noted that, by default, not all of ])
AC_MSG_NOTICE([ the modules are built. Incomplete modules or modules ])
AC_MSG_NOTICE([ which have not been sufficiently tested may be ])
AC_MSG_NOTICE([ disabled. To enable non-default modules, use the ])
AC_MSG_NOTICE([ "--enable-module-MODULE_NAME" configure option.])
AC_MSG_NOTICE([*******************************************************])
AC_MSG_NOTICE([])

AC_CHECK_FUNCS(strcasestr)
AC_CHECK_FUNCS(asprintf)
AC_CHECK_FUNCS(vasprintf)

dnl -lm --> mysql/floor(), http/log()
dnl -lrt --> clock_gettime()

case "$target" in
  *linux*)
    LIBDL="-ldl -lrt -lm"
    RDYNAMIC="-rdynamic"
    MODULE_LIBS="$MODULE_LIBS -shared"
    EXTRA_LDFLAGS=""
    ;;
  *freebsd*)
    LIBDL="-lm"
    RDYNAMIC="-rdynamic"
    MODULE_LIBS="$MODULE_LIBS -shared"
    EXTRA_LDFLAGS=""
    ;;
  *netbsd*)
    LIBDL="-lm"
    RDYNAMIC="-rdynamic"
    MODULE_LIBS="$MODULE_LIBS -shared"
    EXTRA_LDFLAGS=""
    ;;
  *openbsd*)
    LIBDL="-lm"
    RDYNAMIC="-rdynamic"
    MODULE_LIBS="$MODULE_LIBS -shared"
    EXTRA_LDFLAGS="-g -Wl,-E"
    ;;
  *apple-darwin*)
    # Modules will segfault when executed (show usage works) if medusa core
    # is not linked to CoreFoundation (starting with 10.6). This is believed to
    # be due to libsvn linking to CoreFoundation and our modules linked via 
    # "-lsvn_client-1". See http://www.openradar.me/7209349 for more info.
    LIBDL="-ldl -framework CoreFoundation"
    # OS X Lion marked OpenSSL as deprecated. We're disabling these warnings 
    # for now. We'll need to figure out if it's worth supporting Common Crypto
    # or simply requiring users to install their own OpenSSL in the future.
    CFLAGS="$CFLAGS -Wno-deprecated-declarations"
    RDYNAMIC=""
    MODULE_LIBS="$MODULE_LIBS -bundle -flat_namespace -undefined suppress"
    EXTRA_LDFLAGS=""
    ;;
  *solaris*)
    CPPFLAGS="$CPPFLAGS -D_REENTRANT"
    LDFLAGS="$LDFLAGS -R/usr/local/lib -R/usr/local/ssl/lib -L/usr/local/ssl/lib"
    LIBDL="-ldl -lm -lrt -lnsl -lsocket"
    RDYNAMIC="-Rdynamic"
    EXTRA_LDFLAGS=""
    MODULE_LIBS="$MODULE_LIBS -G"
    ;;
  *cygwin*)
    CPPFLAGS="$CPPFLAGS -DCYGWIN"
    LIBDL="-ldl"
    RDYNAMIC=""
    MODULE_LIBS="$MODULE_LIBS -shared"
    ;;
  *)
    LIBDL="-ldl -lm"
    RDYNAMIC="-rdynamic"
    MODULE_LIBS="$MODULE_LIBS -shared"
    EXTRA_LDFLAGS=""
    ;;
esac

AC_SUBST([MODULE_LIBS])
LDFLAGS="$LDFLAGS $RDYNAMIC $EXTRA_LDFLAGS"
LIBS="$LIBS $LIBDL"

test "$prefix" = NONE && prefix=${ac_default_prefix}
_default_mod_path="${prefix}/lib/medusa/modules"
AC_ARG_WITH(default-mod-path, AS_HELP_STRING([--with-default-mod-path=path],[Location of medusa module files (default = /usr/local/lib/medusa/modules)]),[_default_mod_path="$withval"])
AC_DEFINE_UNQUOTED(DEFAULT_MOD_PATH, "$_default_mod_path", [Location of medusa module files])
AC_SUBST(DEFAULT_MOD_PATH)

AC_CONFIG_FILES([Makefile src/Makefile src/modsrc/Makefile])
AC_OUTPUT
