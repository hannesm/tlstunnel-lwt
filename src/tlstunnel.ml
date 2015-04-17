
open Lwt
open Lwt_unix

let server_config cert priv_key =
  X509_lwt.private_of_pems ~cert ~priv_key >|= fun cert ->
  Tls.Config.server ~certificates:(`Single cert) ()

let serve_tcp log_raw log_conn frontend callback =
  let s = socket PF_INET SOCK_STREAM 0 in
  setsockopt s SO_REUSEADDR true ;
  bind s frontend ;
  listen s 10 ;

  log_raw "listener started on " frontend ;

  let rec loop () =
    Lwt_unix.accept s >>= fun (s, addr) ->
    Lwt.async (fun () -> callback (log_conn addr) s addr) ;
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


type stats = {
  mutable read : int ;
  mutable write : int
}

let epoch_data t =
  match Tls_lwt.Unix.epoch t with
  | `Ok data -> (data.Tls.Engine.protocol_version, data.Tls.Engine.ciphersuite)
  | `Error -> assert false

let worker config backend log s addr =
  (try_lwt
     Tls_lwt.Unix.server_of_fd config s
   with Tls_lwt.Tls_alert _ | Tls_lwt.Tls_failure _ as exn ->
     log ("failed to establish TLS connection: " ^ Printexc.to_string exn);
     raise exn) >>= fun t ->

  let ic, oc = Tls_lwt.of_t t in
  let data =
    let version, cipher = epoch_data t in
    let v = Tls.Printer.tls_version_to_string version
    and c = Sexplib.Sexp.to_string_hum (Tls.Ciphersuite.sexp_of_ciphersuite cipher)
    in
    v ^ ", " ^ c
  in
  log ("connection established (" ^ data ^ ")") ;
  let fd = socket PF_INET SOCK_STREAM 0 in

  let stats = ref ({ read = 0 ; write = 0 }) in
  let closing = ref false in
  let close () =
    closing := true ;
    safe Lwt_unix.close fd >>= fun () ->
    safe Tls_lwt.Unix.close t
  in

  (try_lwt
     connect fd backend
   with Unix.Unix_error (e, f, _) ->
     log ("backend refused connection: " ^  Unix.error_message e ^ " while calling " ^ f) ;
     close ()) >|= fun () ->

  (try_lwt
     (let pic = Lwt_io.of_fd ~close ~mode:Lwt_io.Input fd
      and poc = Lwt_io.of_fd ~close ~mode:Lwt_io.Output fd
      in
      Lwt.join [
        read_write closing close (fun x -> !stats.read <- !stats.read + x) (Bytes.create 4096) ic poc ;
        read_write closing close (fun x -> !stats.write <- !stats.write + x) (Bytes.create 4096) pic oc
      ])
   with Unix.Unix_error (e, f, _) ->
     log (Unix.error_message e ^ " while calling " ^ f) ;
     close ()) >|= fun () ->

  let stats =
    "read " ^ (string_of_int !stats.read) ^ " bytes, " ^
    "wrote " ^ (string_of_int !stats.write) ^ " bytes"
  in
  log ("connection closed " ^ stats)

module Log = struct
  let inet_to_string = function
    | ADDR_INET (x, p) -> Unix.string_of_inet_addr x ^ ":" ^ string_of_int p
    | ADDR_UNIX s -> s

  let log_raw out event =
    match out with
    | None -> ()
    | Some out ->
      let lt = Unix.localtime (Unix.time ()) in
      Printf.fprintf out "[%02d:%02d:%02d] %s\n%!"
        lt.Unix.tm_hour lt.Unix.tm_min lt.Unix.tm_sec
        event

  let log out addr event =
    let source = inet_to_string addr in
    log_raw out (source ^ ": " ^ event)

  let log_initial out back event front =
    let listen = inet_to_string front
    and forward = inet_to_string back
    in
    log_raw out (event ^ listen ^ ", forwarding to " ^ forward)

end

let init out =
  Printexc.register_printer (function
      | Tls_lwt.Tls_alert x -> Some ("TLS alert: " ^ Tls.Packet.alert_type_to_string x)
      | Tls_lwt.Tls_failure f -> Some ("TLS failure: " ^ Tls.Engine.string_of_failure f)
      | _ -> None) ;
  let out = match out with
    | None -> Unix.out_channel_of_descr Unix.stdout
    | Some x -> x
  in
  Lwt.async_exception_hook := (function
      | Tls_lwt.Tls_alert _
      | Tls_lwt.Tls_failure _ -> ()
      | exn -> Printf.fprintf out "async error %s\n%!" (Printexc.to_string exn))

let serve (fip, fport) (bip, bport) certificate privkey logfd =
  let logchan = match logfd with
    | Some fd -> Some (Unix.out_channel_of_descr fd)
    | None -> None
  in
  init logchan ;
  let frontend = ADDR_INET (fip, fport)
  and backend = ADDR_INET (bip, bport)
  in
  Tls_lwt.rng_init () >>= fun () ->

  server_config certificate privkey >>= fun config ->
  serve_tcp
    (Log.log_initial logchan backend)
    (Log.log logchan)
    frontend
    (worker config backend)

let run_server frontend backend certificate privkey log quiet =
  Sys.(set_signal sigpipe Signal_ignore) ;
  let logfd = match quiet, log with
    | true, None -> None
    | false, None -> Some Unix.stdout
    | false, Some x -> Some (Unix.openfile x Unix.([O_WRONLY ; O_APPEND; O_CREAT]) 0o640)
    | true, Some _ -> invalid_arg "cannot specify logfile and quiet"
  in
  let c, p = match certificate, privkey with
    | Some c, Some p -> (c, p)
    | Some c, None -> (c, c)
    | None, _ -> invalid_arg "missing certificate file"
  in
  Lwt_main.run (serve frontend backend c p logfd)

open Cmdliner

let resolve name =
  let he = Unix.gethostbyname name in
  if Array.length he.h_addr_list > 0 then
    he.h_addr_list.(0)
  else
    let msg = "no address for " ^ name in
    invalid_arg msg

let host_port default : (Unix.inet_addr * int) Arg.converter =
  let parse s =
    let host, port =
      try
        let colon = String.index s ':' in
        let hostname =
          if colon > 1 then
            resolve (String.sub s 0 colon)
          else
            default
        in
        let csucc = succ colon in
        (hostname, String.(sub s csucc (length s - csucc)))
      with
        Not_found -> (default, s)
    in
    let port = int_of_string port in
    `Ok (host, port)
  in
  parse, fun ppf (h, p) -> Format.fprintf ppf "%s:%d" (Unix.string_of_inet_addr h) p

let backend =
  let default = Unix.inet_addr_loopback in
  let hp = host_port default in
  Arg.(value & opt hp (default, 8080) & info ["b" ; "backend"]
         ~docv:"backend"
         ~doc:"The hostname and port of the backend [connect] service (default is [127.0.0.1]:8080)")

let frontend =
  let default = Unix.inet_addr_any in
  let hp = host_port default in
  Arg.(value & opt hp (default, 4433) & info ["f" ; "frontend"]
         ~docv:"frontend"
         ~doc:"The hostname and port to listen on for incoming connections (default is [*]:4433")

let certificate =
  Arg.(value & opt (some string) None & info ["cert"] ~docv:"certificate_chain"
         ~doc:"The full path to PEM encoded certificate chain")

let privkey =
  Arg.(value & opt (some string) None & info ["key"] ~docv:"private_key"
         ~doc:"The full path to PEM encoded unencrypted private key (defaults to certificate file)")

let log =
  Arg.(value & opt (some string) None & info ["l"; "logfile"] ~docv:"FILE"
         ~doc:"Write accesses to FILE (by default, logging is done to standard output).")

let quiet =
  Arg.(value & flag & info ["q"; "quiet"]
         ~doc:"Be quiet, no logging of accesses.")

let cmd =
  let doc = "Proxy TLS connections to a standard TCP service" in
  let man = [
    `S "DESCRIPTION" ;
    `P "$(tname) listens on a given port and forwards request to the specified hostname" ;
    `S "BUGS" ;
    `P "Please report bugs on the issue tracker at <https://github.com/hannesm/tlstunnel/issues>" ;
    `S "SEE ALSO" ;
    `P "$(b,stunnel)(1), $(b,stud)(1)" ]
  in
  Term.(pure run_server $ frontend $ backend $ certificate $ privkey $ log $ quiet),
  Term.info "tlstunnel" ~version:"0.1.0" ~doc ~man

let () =
  match Term.eval cmd
  with `Error _ -> exit 1 | _ -> exit 0
