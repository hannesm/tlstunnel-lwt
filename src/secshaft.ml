
open Lwt
open Lwt_unix

let server_cert = "server.pem"
let server_key  = "server.key"

let server_config =
  X509_lwt.private_of_pems ~cert:server_cert ~priv_key:server_key >|= fun cert ->
  Tls.Config.server ~certificates:(`Single cert) ()

let serve_ssl port callback =
  server_config >>= fun config ->

  let s = socket PF_INET SOCK_STREAM 0 in
  setsockopt s SO_REUSEADDR true ;
  bind s (ADDR_INET (Unix.inet_addr_any, port)) ;
  listen s 10 ;

  let rec loop () =
    Tls_lwt.Unix.accept config s >>= fun (t, addr) ->
    Lwt.async (fun () -> callback t addr) ;
    loop ()
  in
  loop ()

let safe op arg =
  try_lwt (op arg >> return_unit) with _ -> return_unit

let rec read_write closing close cnt buf ic oc =
  if !closing then
    close ()
  else
    try_lwt
      (Lwt_io.read_into ic buf 0 4096 >>= fun l ->
       cnt l ;
       if l > 0 then
         let s = Bytes.sub buf 0 l in
         Lwt_io.write oc s >>= fun () ->
         read_write closing close cnt buf ic oc
       else
         (closing := true ;
          close ()))
    with _ -> closing := true ; close ()


let resolve name port =
  gethostbyname name >|= fun he ->
  if Array.length he.h_addr_list > 0 then
    ADDR_INET (he.h_addr_list.(0), port)
  else
    let msg = "no address for " ^ name in
    invalid_arg msg

type stats = {
  mutable read : int ;
  mutable write : int
}

let epoch_data t =
  match Tls_lwt.Unix.epoch t with
  | `Ok data -> (data.Tls.Engine.protocol_version, data.Tls.Engine.ciphersuite)
  | `Error -> assert false

let worker log server t addr =
  let ic, oc = Tls_lwt.of_t t in
  let data =
    let version, cipher = epoch_data t in
    let v = Tls.Printer.tls_version_to_string version
    and c = Sexplib.Sexp.to_string_hum (Tls.Ciphersuite.sexp_of_ciphersuite cipher)
    in
    v ^ ", " ^ c
  in
  log addr ("connection established (" ^ data ^ ")") ;
  let fd = socket PF_INET SOCK_STREAM 0 in

  let stats = ref ({ read = 0 ; write = 0 }) in
  let closing = ref false in
  let close () =
    closing := true ;
    safe Lwt_unix.close fd >>= fun () ->
    safe Tls_lwt.Unix.close t
  in

  (try_lwt
     (connect fd server >>= fun () ->
      log addr "connection forwarded" ;
      let pic = Lwt_io.of_fd ~close ~mode:Lwt_io.Input fd
      and poc = Lwt_io.of_fd ~close ~mode:Lwt_io.Output fd
      in
      Lwt.join [
        read_write closing close (fun x -> !stats.read <- !stats.read + x) (Bytes.create 4096) ic poc ;
        read_write closing close (fun x -> !stats.write <- !stats.write + x) (Bytes.create 4096) pic oc
      ])
   with Unix.Unix_error (e, f, _) -> log addr (Unix.error_message e ^ " while calling " ^ f) ; close ()) >|= fun () ->
   let stats = "read " ^ (string_of_int !stats.read) ^ " bytes, wrote " ^ (string_of_int !stats.write) ^ " bytes" in
   log addr ("connection closed " ^ stats)

let log out addr event =
  let lt = Unix.localtime (Unix.time ()) in
  let source =
    match addr with
    | ADDR_INET (x, p) -> Unix.string_of_inet_addr x ^ ":" ^ string_of_int p
    | ADDR_UNIX s -> s
  in
  Printf.fprintf out "[%02d:%02d:%02d] %s: %s\n%!"
    lt.Unix.tm_hour lt.Unix.tm_min lt.Unix.tm_sec
    source event

let init () =
  Printexc.register_printer (function
      | Tls_lwt.Tls_alert x -> Some ("TLS alert: " ^ Tls.Packet.alert_type_to_string x)
      | Tls_lwt.Tls_failure f -> Some ("TLS failure: " ^ Tls.Engine.string_of_failure f)
      | _ -> None) ;

  Lwt.async_exception_hook := (fun exn ->
    Printf.printf "async error %s\n%!" (Printexc.to_string exn))

let serve port target targetport =
  Tls_lwt.rng_init () >>= fun () ->
  resolve target targetport >>= fun server ->

  let log = log (Unix.out_channel_of_descr Unix.stdin) in
  serve_ssl port (worker log server)


let inetd logfile target targetport =
  (* we get the socket via stdin/stdout! *)
  let sock = Lwt_unix.stdin in
  let addrinfo = Lwt_unix.getpeername sock in

  resolve target targetport >>= fun server ->
  let logfd = Unix.openfile logfile Unix.([O_WRONLY ; O_APPEND; O_CREAT]) 0o644 in
  let log = log (Unix.out_channel_of_descr logfd) in
  server_config >>= fun config ->
  Tls_lwt.Unix.server_of_fd config sock >>= fun t ->
  worker log server t addrinfo >|= fun () ->
  Unix.close logfd


let () =
  Printf.printf "hello\n" ;
  init () ;
  let port = 4433
  and target = "127.0.0.1"
  and targetport = 8080
  in
  (*  Lwt_main.run (serve port target targetport) *)
  Lwt_main.run (inetd "/home/hannes/foo.txt" target targetport)
