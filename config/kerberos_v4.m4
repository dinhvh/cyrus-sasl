dnl checking for kerberos 4 libraries

AC_DEFUN(SASL_KERBEROS_V4_CHK, [
  AC_MSG_CHECKING(KERBEROS_V4)
  if test "$krb4" != no; then
    AC_MSG_RESULT(enabled)
    SASL_MECHS="$SASL_MECHS libkerberos4.la"
    SASL_STATIC_OBJS="$SASL_STATIC_OBJS ../plugins/kerberos4.o"
    AC_DEFINE(STATIC_KERBEROS4)
    AC_DEFINE(HAVE_KRB)
    SASL_KRB_LIB="-lkrb -ldes $COM_ERR"
  else
    AC_MSG_RESULT(disabled)
  fi
  AC_SUBST(SASL_KRB_LIB)
])

