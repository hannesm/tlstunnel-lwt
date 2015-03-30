
open Lwt
open Lwt_unix

let server_cert = "server.pem"
let server_key  = "server.key"

let serve_ssl port callback =
  X509_lwt.private_of_pems ~cert:server_cert ~priv_key:server_key >>= fun cert ->
  let config = Tls.Config.server ~certificates:(`Single cert) () in

  let s = socket PF_INET SOCK_STREAM 0 in
  setsockopt s SO_REUSEADDR true ;
  bind s (ADDR_INET (Unix.inet_addr_any, port)) ;
  listen s 10 ;

  let rec loop () =
    Tls_lwt.accept_ext config s >>= fun (channels, addr) ->
    Lwt.async (fun () -> callback channels addr) ;
    loop ()
  in
  loop ()

let rec read_write buf ic oc =
  Lwt_io.read_into ic buf 0 4096 >>= fun l ->
  let s = Bytes.sub buf 0 l in
  Printf.printf "read %s\n" s ;
  Lwt_io.write oc s >>= fun () ->
  Printf.printf "wrote %s\n" s ;
  read_write buf ic oc

let resolve name port =
  gethostbyname name >|= fun he ->
  if Array.length he.h_addr_list > 0 then
    ADDR_INET (he.h_addr_list.(0), port)
  else
    let msg = "no address for " ^ name in
    invalid_arg msg

let serve port target targetport =
  Tls_lwt.rng_init () >>= fun () ->
  resolve target targetport >>= fun server_sockaddr ->

  serve_ssl port (fun (ic, oc) addr ->
      let fd = socket PF_INET SOCK_STREAM 0 in
      connect fd server_sockaddr >>= fun () ->
      let pic = Lwt_io.of_fd ~mode:Lwt_io.Input fd
      and poc = Lwt_io.of_fd ~mode:Lwt_io.Output fd
      in
      Lwt.choose [ read_write (Bytes.create 4096) ic poc ;
                   read_write (Bytes.create 4096) pic oc ])

let () =
  Printf.printf "hello\n" ;
  let port = 4433
  and target = "127.0.0.1"
  and targetport = 8080
  in
  Lwt_main.run (serve port target targetport)
