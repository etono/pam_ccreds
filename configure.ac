AC_INIT([pam_ccreds],[10])
AC_CANONICAL_TARGET
AC_PREFIX_DEFAULT()

AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])
AM_MAINTAINER_MODE

AC_PROG_GREP
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL

PKG_PROG_PKG_CONFIG

AC_ARG_VAR([LIBGCRYPT_CONFIG], [path to libgcrypt-config utility])
AC_ARG_VAR([LIBGCRYPT_CFLAGS], [C compiler flags for libgcrypt])
AC_ARG_VAR([LIBGCRYPT_LIBS], [linker flags for libcrypt])

AC_DEFINE_UNQUOTED(CCREDS_FILE, "/var/cache/.security.db", [Credentials cache file])
AC_DEFINE_UNQUOTED(CCREDS_VALIDATE, "/sbin/ccreds_chkpwd", [Verify password with this program])

AC_ARG_WITH(ccreds-file, [  --with-ccreds-file=PATH path to cached credentials file], [AC_DEFINE_UNQUOTED(CCREDS_FILE, "$with_ccreds_file")])

AC_ARG_WITH(crypto-backend,
[AS_HELP_STRING([--with-crypto-backend=LIB],[specify which cryptographic back-end to use, supported backends: openssl, libgcrypt and nettle @<:@default=openssl@:>@])],
[case "${withval}" in
  openssl*) crypto_backend=openssl ;;
  libgcrypt*) crypto_backend=libgcrypt ;;
  nettle*) crypto_backend=nettle ;;
  *) AC_MSG_ERROR(bad value ${withval} for --with-crypto-backend) ;;
esac],[crypto_backend=openssl])

AC_ARG_ENABLE([test], [AS_HELP_STRING([--enable-test],[build a program which can be used to test the module's functionality @<:@default=yes@:>@])],
[case "${enableval}" in
  yes) build_test=true ;;
  no)  build_test=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-test]) ;;
esac], [build_test=true])

if test "$ac_cv_c_compiler_gnu" = "yes"; then CFLAGS="$CFLAGS -Wall -fPIC"; fi

case "$target_os" in
freebsd*) CPPFLAGS="$CPPFLAGS -DPIC -D_REENTRANT" ;;
aix*) CPPFLAGS="$CPPFLAGS -D_THREAD_SAFE" ;;
*) CPPFLAGS="$CPPFLAGS -D_REENTRANT" ;;
esac

case "$target_os" in
aix*) pam_ccreds_so_LD="ld"
  pam_ccreds_so_LDFLAGS="-bM:SRE -bnoentry -bE:\$(srcdir)/exports.aix"
  TARGET_OS="AIX" ;;
darwin*) pam_ccreds_so_LDFLAGS="-bundle" ;;
hpux*) pam_ccreds_so_LD="/bin/ld"
  pam_ccreds_so_LDFLAGS="-b -dynamic -G `cat exports.hpux`"
  TARGET_OS="HPUX" ;;
solaris*) pam_ccreds_so_LD="/usr/ccs/bin/ld"
  pam_ccreds_so_LDFLAGS="-B dynamic -M \$(srcdir)/exports.solaris -G -B group -lc" ;;
linux*) pam_ccreds_so_LDFLAGS="-shared -Wl,-Bdynamic -Wl,--version-script,\$(srcdir)/exports.linux"
  TARGET_OS="LINUX" ;;
*) pam_ccreds_so_LDFLAGS="-shared" ;;
esac

AC_SUBST(pam_ccreds_so_LD)
AC_SUBST(pam_ccreds_so_LDFLAGS)

AM_CONDITIONAL(USE_NATIVE_LINKER, test -n "$pam_ccreds_so_LD")
AM_CONDITIONAL(EXTENSION_SO, test "$TARGET_OS" = "LINUX")
AM_CONDITIONAL(EXTENSION_1, test "$TARGET_OS" = "HPUX")
AM_CONDITIONAL(BUILD_TEST, test "x$build_test" = "xtrue")

have_sha1=0
have_sha256=0
have_sha512=0

AS_CASE([$crypto_backend],
	[openssl*],
	 [ AC_DEFINE([USE_OPENSSL], [1], [Define to 1 if you want to use openssl])
	   PKG_CHECK_MODULES([OPENSSL], [openssl], [], [])

	   LIBS="$OPENSSL_LIBS $LIBS" 
	   CPPFLAGS="$OPENSSL_CFLAGS $CPPFLAGS" 

	   AC_CHECK_HEADERS(openssl/opensslconf.h, , AC_MSG_ERROR(could not locate <openssl/opensslconf.h>))
  	   AC_CHECK_FUNC([PKCS5_PBKDF2_HMAC_SHA1], have_sha1=1)
	   AC_CHECK_FUNC([PKCS5_PBKDF2_HMAC], [AC_CHECK_FUNC([EVP_sha256], have_sha256=1)
	   				       AC_CHECK_FUNC([EVP_sha512], have_sha512=1)])],
	[libgcrypt*],
	 [ AC_DEFINE([USE_LIBGCRYPT], [1], [Define to 1 if you want to use libgcrypt])	
	   AC_PATH_PROG(LIBGCRYPT_CONFIG, libgcrypt-config) 
	   AS_IF([test "x$LIBGCRYPT_LIBS$LIBGCRYPT_CFLAGS" == "x"],
	   	   [ LIBGCRYPT_CFLAGS=`$LIBGCRYPT_CONFIG --cflags`
             	     LIBGCRYPT_LIBS=`$LIBGCRYPT_CONFIG --libs`])

	   LIBS="$LIBGCRYPT_LIBS $LIBS" 
	   CPPFLAGS="$LIBGCRYPT_CFLAGS $CPPFLAGS" 

	   AC_CHECK_HEADERS([gcrypt.h], , AC_MSG_ERROR(could not locate <gcrypt.h>))
	   AC_CHECK_FUNCS([gcry_kdf_derive],,[AC_MSG_ERROR(could not find gcry_kdf_derive. we require libgcrypt >= 1.5.0)])
	   CC_CHECK_LIBGCRYPT_HASH([sha1], $LIBGCRYPT_CONFIG, have_sha1=1) 
	   CC_CHECK_LIBGCRYPT_HASH([sha256], $LIBGCRYPT_CONFIG, have_sha256=1) 
	   CC_CHECK_LIBGCRYPT_HASH([sha512], $LIBGCRYPT_CONFIG, have_sha512=1)],
	[nettle*],
	 [ AC_DEFINE([USE_NETTLE], [1], [Define to 1 if you want to use nettle])
	   PKG_CHECK_MODULES([NETTLE], [nettle], [], [])

	   LIBS="$NETTLE_LIBS $LIBS" 
	   CPPFLAGS="$NETTLE_CFLAGS $CPPFLAGS" 

	   AC_CHECK_HEADERS([nettle/pbkdf2.h], , AC_MSG_ERROR(could not locate <nettle/pbkdf2.h>. we require nettle >= 2.6))
	   AC_CHECK_HEADERS([nettle/hmac.h], , AC_MSG_ERROR(could not locate <nettle/hmac.h>))
	   AC_CHECK_FUNC([nettle_pbkdf2_hmac_sha1],have_sha1=1)
	   AC_CHECK_FUNC([nettle_pbkdf2_hmac_sha256], have_sha256=1)
	   AC_CHECK_FUNC([nettle_pbkdf2],
			 AC_CHECK_FUNC([nettle_hmac_sha512_update],
				AC_CHECK_FUNC([nettle_hmac_sha512_digest], have_sha512=1)))
	 ])

if [ test "x$have_sha1" = "x0" ] && [ test "x$have_sha256" = "x0" ] && [ test "x$have_sha512" = "x0" ]; then
   AC_MSG_ERROR([no hash algorithms supported])
fi

AS_IF([test "x$build_test" = "xtrue"], 
	   [ AC_CHECK_HEADER([getopt.h], , AC_MSG_ERROR(could not locate <getopt.h>))
	     AC_CHECK_FUNC([getopt_long], , AC_MSG_ERROR(could not locate getopt_long)) ])

AC_DEFINE_UNQUOTED([HAVE_SHA1], $have_sha1, [ Define to 1 if you have SHA1 support in the crypto backend ])
AC_DEFINE_UNQUOTED([HAVE_SHA256], $have_sha256, [ Define to 1 if you have SHA2-256 support in the crypto backend ])
AC_DEFINE_UNQUOTED([HAVE_SHA512], $have_sha512, [ Define to 1 if you have SHA2-512 support in the crypto backend ])

AC_CHECK_HEADERS(security/pam_appl.h security/pam_misc.h security/pam_modules.h)
AC_CHECK_HEADERS(pam/pam_appl.h pam/pam_misc.h pam/pam_modules.h)

AC_CHECK_HEADERS(db.h)

AC_CHECK_LIB(db, main,[LIBS="-ldb $LIBS" found_db_lib=yes],,$LIBS)
if test -z "$found_db_lib"; then
	AC_CHECK_LIB(db1, main,[LIBS="-ldb1 $LIBS" found_db_lib=yes],,$LIBS)
fi

AC_CHECK_LIB(pam, pam_start)
AC_CHECK_LIB(pam_misc, misc_conv)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

