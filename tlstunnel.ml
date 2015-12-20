
open Lwt.Infix

module Log = struct
  let inet_to_string = function
    | Lwt_unix.ADDR_INET (x, p) -> Unix.string_of_inet_addr x ^ ":" ^ string_of_int p
    | Lwt_unix.ADDR_UNIX s -> s

  let log_raw out event =
    match out with
    | None -> ()
    | Some out ->
      let open Unix in
      let lt = gmtime (time ()) in
      Printf.fprintf out "[%04d-%02d-%02dT%02d:%02d:%02dZ] %s\n%!"
        (lt.tm_year + 1900) (succ lt.tm_mon) lt.tm_mday
        lt.tm_hour lt.tm_min lt.tm_sec
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

module Stats = struct
  type stats = {
    mutable read : int ;
    mutable written : int
  }

  let new_stats () = { read = 0 ; written = 0 }

  let inc_read s v = s.read <- s.read + v
  let inc_written s v = s.written <- s.written + v

  let print_stats stats =
    "read " ^ (string_of_int stats.read) ^ " bytes, " ^
    "wrote " ^ (string_of_int stats.written) ^ " bytes"
end

module Fd_logger = struct
  let fds = ref []
  let count = ref 0

  let add_fd fd =
    fds := fd :: !fds ;
    count := succ !count

  let aborted_to_string ab =
    match Lwt_unix.state ab with
      | Aborted exn -> Printexc.to_string exn
      | _ -> ""

  let log () =
    let opened, closed, aborted =
      List.fold_left (fun (o, c, a) x -> match Lwt_unix.state x with
          | Opened -> (x :: o, c, a)
          | Closed -> (o, x :: c, a)
          | Aborted _ -> (o, c, x :: a))
        ([], [], []) !fds
    in
    fds := List.append opened aborted ;
    Printf.sprintf "fds: count %d, active %d, open %d, closed %d, aborted %d%s"
      !count (List.length !fds) (List.length opened) (List.length closed) (List.length aborted)
      (if List.length aborted > 0 then
         "\n" ^ (String.concat "\n  " (List.map aborted_to_string aborted))
       else
         "")

  let start logger () =
    Lwt_engine.on_timer 60. true (fun _ -> logger (log ()))
end

let server_config cert priv_key =
  X509_lwt.private_of_pems ~cert ~priv_key >|= fun cert ->
  Tls.Config.server ~certificates:(`Single cert) ()

let init_socket log_raw frontend =
  Unix.handle_unix_error (fun () ->
      let open Lwt_unix in
      let s = socket PF_INET SOCK_STREAM 0 in
      setsockopt s SO_REUSEADDR true ;
      bind s frontend ;
      listen s 10 ;
      log_raw "listener started on " frontend ;
      s) ()

let bufsize = 4096

type res = Stop | Continue

let rec read_write debug log closing close cnt ic oc =
  if !closing then
    close ()
  else
    let doit () =
      let buf = Bytes.create bufsize in
      Lwt_io.read_into ic buf 0 bufsize >>= fun l ->
      cnt l ;
      if l > 0 then
        let s = Bytes.sub buf 0 l in
        (if debug then log ("read " ^ string_of_int l ^ " bytes: " ^ s)) ;
        Lwt_io.write oc s >|= fun () ->
        (if debug then log "wrote them") ;
        Continue
      else
        begin
          (if debug then log "closing") ;
          close () >|= fun () ->
          Stop
        end
    in
    Lwt.catch doit
      (function
        | Unix.Unix_error (Unix.EBADF, _, _) ->
           (if debug then log "EBADF, closing") ;
           close () >|= fun () -> Stop
        | exn ->
          log ("failed in read_write " ^ Printexc.to_string exn) ;
          close () >|= fun () ->
          Stop)
    >>= function
    | Stop -> Lwt.return_unit
    | Continue -> read_write debug log closing close cnt ic oc

let tls_info t =
  let v, c =
    match Tls_lwt.Unix.epoch t with
    | `Ok data -> (data.Tls.Core.protocol_version, data.Tls.Core.ciphersuite)
    | `Error -> assert false
  in
  let version = Tls.Printer.tls_version_to_string v
  and cipher = Sexplib.Sexp.to_string_hum (Tls.Ciphersuite.sexp_of_ciphersuite c)
  in
  version ^ ", " ^ cipher

let safe_close closing tls fd () =
  closing := true ;
  let safely f x =
    Lwt.catch (fun _ -> f x) (fun _ -> Lwt.return_unit)
  in
  (match tls with
   | Some x -> safely Tls_lwt.Unix.close x
   | None -> Lwt.return_unit) >>= fun () ->
  safely Lwt_unix.close fd

let worker config backend log s logfds debug trace () =
  let closing = ref false in
  Lwt.catch (fun () ->
    Tls_lwt.Unix.server_of_fd config ?trace s >>= fun t ->
    let ic, oc = Tls_lwt.of_t t in
    log ("connection established (" ^ (tls_info t) ^ ")") ;
    let stats = Stats.new_stats () in

    let fd = Lwt_unix.socket PF_INET SOCK_STREAM 0 in
    if logfds then Fd_logger.add_fd fd ;
    let close = safe_close closing (Some t) fd in

    Lwt.catch (fun () ->
      Lwt_unix.connect fd backend >>= fun () ->
      let pic = Lwt_io.of_fd ~close ~mode:Lwt_io.Input fd
      and poc = Lwt_io.of_fd ~close ~mode:Lwt_io.Output fd
      in
      Lwt.join [
        read_write debug log closing close (Stats.inc_read stats) ic poc ;
        read_write debug log closing close (Stats.inc_written stats) pic oc
      ] >|= fun () ->
      log ("connection closed " ^ (Stats.print_stats stats))
      )
      (function
        | Unix.Unix_error (e, f, _) ->
          let msg = Unix.error_message e in
          log ("backend refused connection: " ^  msg ^ " while calling " ^ f) ;
          close ()
        | exn ->
          close () >|= fun () ->
          log ("received inner exception " ^ Printexc.to_string exn)))
    (fun exn ->
       safe_close closing None s () >|= fun () ->
       log ("failed to establish TLS connection: " ^ Printexc.to_string exn))

let init out =
  Printexc.register_printer (function
      | Tls_lwt.Tls_alert x -> Some ("TLS alert: " ^ Tls.Packet.alert_type_to_string x)
      | Tls_lwt.Tls_failure f -> Some ("TLS failure: " ^ Tls.Engine.string_of_failure f)
      | _ -> None) ;
  let out = match out with
    | None -> Unix.out_channel_of_descr Unix.stdout
    | Some x -> x
  in
  Lwt.async_exception_hook := (fun exn ->
      Printf.fprintf out "async error %s\n%!" (Printexc.to_string exn))

let accept_loop s log_raw log_conn tls_config backend logfds debug trace =
  let rec loop () =
    Lwt.catch (fun () ->
      Lwt_unix.accept s >>= fun (client_socket, addr) ->
      (* log_conn addr "accepted incoming connection" ; *)
      if logfds then Fd_logger.add_fd client_socket ;
      Lwt.async (worker tls_config backend (log_conn addr) client_socket logfds debug trace) ;
      loop ())
      (function
        | Unix.Unix_error (e, f, _) ->
          let msg = Unix.error_message e in
          log_raw ("accept failed " ^ msg ^ " in " ^ f) ;
          loop ()
        | exn ->
          log_raw ("failure in accept_loop: " ^ Printexc.to_string exn) ;
          loop ())
  in
  loop ()

let serve (fip, fport) (bip, bport) certificate privkey logfd logfds debug =
  let logchan = match logfd with
    | Some fd -> Some (Unix.out_channel_of_descr fd)
    | None -> None
  in
  init logchan ;
  let frontend = Lwt_unix.ADDR_INET (fip, fport)
  and backend = Lwt_unix.ADDR_INET (bip, bport)
  in
  server_config certificate privkey >>= fun tls_config ->
  let server_socket = init_socket (Log.log_initial logchan backend) frontend in
  let raw_log = Log.log_raw logchan in
  if logfds then ignore (Fd_logger.start raw_log ()) ;
  let trace =
    if debug then
      let out = match logchan with
        | None -> Unix.out_channel_of_descr Unix.stdout
        | Some x -> x
      in
      Some (fun sexp -> Printf.fprintf out "%s\n" Sexplib.Sexp.(to_string_hum sexp))
    else
      None
  in
  (* drop privileges here! *)
  accept_loop server_socket raw_log (Log.log logchan) tls_config backend logfds debug trace

let run_server frontend backend certificate privkey log quiet logfds debug =
  Sys.(set_signal sigpipe Signal_ignore) ;
  let logfd = match quiet, log with
    | true, None -> None
    | false, None -> Some Unix.stdout
    | false, Some x -> Some (Unix.openfile x [Unix.O_WRONLY ; Unix.O_APPEND; Unix.O_CREAT] 0o640)
    | true, Some _ -> invalid_arg "cannot specify logfile and quiet"
  in
  let c, p = match certificate, privkey with
    | Some c, Some p -> (c, p)
    | Some c, None -> (c, c)
    | None, _ -> invalid_arg "missing certificate file"
  in
  Lwt_main.run (serve frontend backend c p logfd logfds debug)

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
  Arg.(value & opt (some string) None & info ["cert"] ~docv:"FILE"
         ~doc:"The full path to PEM encoded certificate chain FILE (may also include the private key)")

let privkey =
  Arg.(value & opt (some string) None & info ["key"] ~docv:"FILE"
         ~doc:"The full path to PEM encoded unencrypted private key in FILE (defaults to certificate_chain)")

let log =
  Arg.(value & opt (some string) None & info ["l"; "logfile"] ~docv:"FILE"
         ~doc:"Write accesses to FILE (by default, logging is done to standard output).")

let logfds =
  Arg.(value & flag & info ["logfds"] ~doc:"Log file descriptors")

let debug =
  Arg.(value & flag & info ["debug"] ~doc:"Debug, show full traces")

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
  Term.(pure run_server $ frontend $ backend $ certificate $ privkey $ log $ quiet $ logfds $ debug),
  Term.info "tlstunnel" ~version:"0.1.0" ~doc ~man

let () =
  match Term.eval cmd
  with `Error _ -> exit 1 | _ -> exit 0
