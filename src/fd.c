#include <caml/mlvalues.h>

#include <unistd.h>
#include <fcntl.h>

CAMLprim value
caml_next_fd (value unit) {
  int fd ;
  fd = open("/", O_RDONLY) ;
  close(fd) ;
  return Val_int(fd);
}
