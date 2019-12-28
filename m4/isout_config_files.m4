


AC_DEFUN([ISOUT_CONFIG_FILES],
[
  AC_REQUIRE([AC_DISABLE_OPTION_CHECKING])
  AS_LITERAL_IF([$1], [], [AC_DIAGNOSE([syntax], [$0: you should use literals])])

  isout_files="$1"
  isout_opts="$2"
  save_path=`pwd`
  for isout_file in $isout_files
  do
    isout_dir=`dirname $isout_file`
    isout_file="./`basename $isout_file`"
    cd $isout_dir
    if test -f "$isout_file"; then
      cmd="$isout_file $isout_opts"
      AC_MSG_NOTICE([running cmd: $cmd])
      $cmd
      if test $? -ne 0; then
        AC_MSG_ERROR([error: $cmd])
      fi
    else
      AC_MSG_ERROR([$isout_file: no such configure file])
    fi
    cd $save_path
  done
])