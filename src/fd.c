#include <caml/mlvalues.h>

#include <unistd.h>
#include <sys/socket.h>

CAMLprim value
caml_next_fd (value unit) {
  int fd ;
  fd = socket(PF_INET, SOCK_STREAM, 0) ;
  close(fd) ;
  return Val_int(fd);
}
