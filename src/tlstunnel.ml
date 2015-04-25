
open Lwt
open Lwt_unix

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
    match state ab with
      | Aborted exn -> Printexc.to_string exn
      | _ -> ""

  external next_fd : unit -> int = "caml_next_fd"

  let log () =
    let opened, closed, aborted =
      List.fold_left (fun (o, c, a) x -> match state x with
          | Opened -> (x :: o, c, a)
          | Closed -> (o, x :: c, a)
          | Aborted _ -> (o, c, x :: a))
        ([], [], []) !fds
    in
    fds := List.append opened aborted ;
    Printf.sprintf "fds: count %d, next %d, active %d, open %d, closed %d, aborted %d%s"
      !count (next_fd ()) (List.length !fds)
      (List.length opened) (List.length closed) (List.length aborted)
      (if List.length aborted > 0 then
         "\n" ^ (String.concat "\n  " (List.map aborted_to_string aborted))
       else
         "")

  let start logger () =
    Lwt_engine.on_timer 3. true (fun _ -> logger (log ()))
end

let server_config cert priv_key =
  X509_lwt.private_of_pems ~cert ~priv_key >|= fun cert ->
  Tls.Config.server ~certificates:(`Single cert) ()

let init_socket log_raw frontend =
  Unix.handle_unix_error (fun () ->
      let s = socket PF_INET SOCK_STREAM 0 in
      setsockopt s SO_REUSEADDR true ;
      bind s frontend ;
      listen s 10 ;
      log_raw "listener started on " frontend ;
      s) ()

let rec read_write closing close cnt buf ic oc =
  if !closing then
    close ()
  else
    catch (fun () ->
        Lwt_io.read_into ic buf 0 4096 >>= fun l ->
        cnt l ;
        if l > 0 then
          let s = Bytes.sub buf 0 l in
          Lwt_io.write oc s >>= fun () ->
          read_write closing close cnt buf ic oc
        else
          (closing := true ;
           close ()))
      (fun _ -> closing := true ; close ())

let tls_info t =
  let v, c =
    match Tls_lwt.Unix.epoch t with
    | `Ok data -> (data.Tls.Engine.protocol_version, data.Tls.Engine.ciphersuite)
    | `Error -> assert false
  in
  let version = Tls.Printer.tls_version_to_string v
  and cipher = Sexplib.Sexp.to_string_hum (Tls.Ciphersuite.sexp_of_ciphersuite c)
  in
  version ^ ", " ^ cipher

let safe_close closing tls fds () =
  closing := true ;
  let safe_close fd =
    try_lwt (Lwt_unix.close fd)
    with _ -> return_unit
  in
  (match tls with
   | Some x -> Tls_lwt.Unix.close x
   | None -> return_unit) >>= fun () ->
  Lwt.join (List.map safe_close fds)

let worker config backend log s addr logfds () =
  catch (fun () ->
    Tls_lwt.Unix.server_of_fd config s >>= fun t ->
    let ic, oc = Tls_lwt.of_t t in
    log ("connection established (" ^ (tls_info t) ^ ")") ;
    let stats = Stats.new_stats () in

    let fd = socket PF_INET SOCK_STREAM 0 in
    if logfds then Fd_logger.add_fd fd ;
    let closing = ref false in
    let close = safe_close closing (Some t) [ s ; fd ] in

    catch (fun () ->
      connect fd backend >>= fun () ->
      let pic = Lwt_io.of_fd ~close ~mode:Lwt_io.Input fd
      and poc = Lwt_io.of_fd ~close ~mode:Lwt_io.Output fd
      in
      Lwt.join [
        read_write closing close (Stats.inc_read stats) (Bytes.create 4096) ic poc ;
        read_write closing close (Stats.inc_written stats) (Bytes.create 4096) pic oc
      ] >|= fun () ->
      log ("connection closed " ^ (Stats.print_stats stats))
      )
      (function
        | Unix.Unix_error (e, f, _) ->
          let msg = Unix.error_message e in
          log ("backend refused connection: " ^  msg ^ " while calling " ^ f) ;
          close ()
        | exn -> raise exn)
    )
    (function
      | Tls_lwt.Tls_alert _ | Tls_lwt.Tls_failure _ as exn ->
        log ("failed to establish TLS connection: " ^ Printexc.to_string exn) ;
        (* Tls_lwt has already closed the underlying file descriptor *)
        return_unit
      | exn -> raise exn)

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

let accept_loop s log_conn tls_config backend logfds =
  let rec loop () =
    Lwt_unix.accept s >>= fun (client_socket, addr) ->
    (* log_conn addr "accepted incoming connection" ; *)
    if logfds then Fd_logger.add_fd client_socket ;
    Lwt.async (worker tls_config backend (log_conn addr) client_socket addr logfds) ;
    loop ()
  in
  loop ()

let serve (fip, fport) (bip, bport) certificate privkey logfd logfds =
  let logchan = match logfd with
    | Some fd -> Some (Unix.out_channel_of_descr fd)
    | None -> None
  in
  init logchan ;
  let frontend = ADDR_INET (fip, fport)
  and backend = ADDR_INET (bip, bport)
  in
  Tls_lwt.rng_init () >>= fun () ->
  server_config certificate privkey >>= fun tls_config ->
  let server_socket = init_socket (Log.log_initial logchan backend) frontend in
  if logfds then ignore (Fd_logger.start (Log.log_raw logchan) ()) ;
  (* drop privileges here! *)
  accept_loop server_socket (Log.log logchan) tls_config backend logfds

let run_server frontend backend certificate privkey log quiet logfds =
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
  Lwt_main.run (serve frontend backend c p logfd logfds)

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

let logfds =
  Arg.(value & flag & info ["logfds"] ~doc:"Log file descriptors")

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
  Term.(pure run_server $ frontend $ backend $ certificate $ privkey $ log $ quiet $ logfds),
  Term.info "tlstunnel" ~version:"0.1.0" ~doc ~man

let () =
  match Term.eval cmd
  with `Error _ -> exit 1 | _ -> exit 0
