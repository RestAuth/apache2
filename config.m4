APACHE_MODPATH_INIT(authn_url)

AC_DEFUN([CHECK_CURL], [
  curl_found="no"
  AC_ARG_WITH(curl, APACHE_HELP_STRING([--with-curl=PREFIX],
                                  [CURL library]),
  [
    if test "$withval" = "yes" ; then
      AC_MSG_ERROR([--with-curl requires an argument.])
    else
      curl_prefix=$withval
      save_cflags="$CFLAGS"
      CFLAGS="$CFLAGS $APR_INCLUDES $APU_INCLUDES -I$curl_prefix/include"
      AC_CHECK_HEADERS(curl/curl.h,[
        save_ldflags="$LDFLAGS"
        LDFLAGS="$LDFLAGS -L$curl_prefix/lib"
        AC_CHECK_LIB(curl, curl_easy_setopt,[curl_found="yes"])
        LDFLAGS="$save_ldflags"])
      CFLAGS="$save_cflags"
    fi
  ],[
    AC_CHECK_HEADERS(curl/curl.h,[AC_CHECK_LIB(curl, curl_easy_setopt, [curl_found="yes"])])
  ])

  if test "$curl_found" = "yes"; then
    MOD_AUTHN_URL_LDADD="-L$curl_prefix/lib -lcurl"
    APR_ADDTO(INCLUDES, ["-I$curl_prefix/include"])
  else
    AC_MSG_ERROR(unable to find curl)
  fi
])

APACHE_MODULE(authn_url, REST based basic authentication provider, , , no, [CHECK_CURL])
APACHE_MODPATH_FINISH
