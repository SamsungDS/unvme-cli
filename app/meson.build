fs = import('fs')

fio = get_option('with-fio')

if fio != ''
  if not fs.is_absolute(fio)
    error('"' + fio + '" is not absolute path.')
  endif

  if fs.exists(fio) and fs.is_dir(fio)
    subdir('fio')
  else
    error('"' + fio + '" does not exist.')
  endif
endif
