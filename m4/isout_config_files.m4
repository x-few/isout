


AC_DEFUN([ISOUT_CONFIG_FILES],
[
  AC_REQUIRE([AC_DISABLE_OPTION_CHECKING])
  AS_LITERAL_IF([$1], [], [AC_DIAGNOSE([syntax], [$0: you should use literals])])

  isout_files="$1"
  isout_opts="$2"
  for isout_file in $isout_files
  do
    if test -f "$isout_file"; then
      AC_MSG_NOTICE([ISOUT_CONFIG_FILES: $isout_file "$isout_opts"])
      $isout_file "$isout_opts"
      if [ $? -ne 0 ]; then
        AC_MSG_ERROR([$isout_file "$isout_opts"])
        exit 1
      fi
    else
      AC_MSG_ERROR([$isout_file: no such configure file])
    fi
  done
])