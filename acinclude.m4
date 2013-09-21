m4_define_default([PKG_PROG_PKG_CONFIG],
 [AC_MSG_CHECKING([pkg-config])
 AC_MSG_RESULT([no])])
 
m4_define_default([PKG_CHECK_MODULES],
 [AC_MSG_CHECKING([$1])
 AC_MSG_RESULT([no])
 $4])

dnl CC_CHECK_LIBGCRYPT_HASH([ALGORITHM], [PROGRAM]
dnl                         [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl
dnl This function will use libgcrypt-config --algorithm to determine if the
dnl requested hash function is supported by libgcrypt.
AC_DEFUN([CC_CHECK_LIBGCRYPT_HASH],
	[ AC_MSG_CHECKING([for $1 support in libgcrypt])
	  if test "x`$2 --algorithms | $GREP Message | $GREP $1 | wc -l`" = "x0"; then
	     AC_MSG_RESULT(no)
	     $4
	  else
	     AC_MSG_RESULT(yes)
	     $3
	  fi])
