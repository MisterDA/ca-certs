let src = Logs.Src.create "ca-certs" ~doc:"CA certificates"

module Log = (val Logs.src_log src : Logs.LOG)

let issue =
  {|Please report an issue at https://github.com/mirage/ca-certs, including:
- the output of uname -s
- the distribution you use
- the location of default trust anchors (if known)
|}

let detect_one path =
  let path' = Fpath.v path in
  match Bos.OS.Path.exists path' with
  | Ok true -> Bos.OS.File.read path'
  | _ ->
      Error
        (`Msg
          ( "ca-certs: no trust anchor file found, looked into " ^ path ^ ".\n"
          ^ issue ))

let detect_list paths =
  let rec one = function
    | [] ->
        Error
          (`Msg
            ( "ca-certs: no trust anchor file found, looked into "
            ^ String.concat ", " paths ^ ".\n" ^ issue ))
    | path :: paths -> (
        match detect_one path with Ok data -> Ok data | Error _ -> one paths )
  in
  one paths

(* from https://golang.org/src/crypto/x509/root_linux.go *)
let linux_locations =
  [
    (* Debian/Ubuntu/Gentoo etc. *)
    "/etc/ssl/certs/ca-certificates.crt";
    (* CentOS/RHEL 7 *)
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem";
    (* OpenSUSE *)
    "/etc/ssl/ca-bundle.pem";
  ]

(* from https://golang.org/src/crypto/x509/root_bsd.go *)
let openbsd_location = "/etc/ssl/cert.pem"

let freebsd_location = "/usr/local/share/certs/ca-root-nss.crt"

let macos_keychain_location =
  "/System/Library/Keychains/SystemRootCertificates.keychain"

external windows_trust_anchors_der : unit -> string list = "ca_certs_windows_trust_anchors_der"

let rec map_m f l =
  match l with
  | [] -> Ok []
  | x::xs ->
    let open Rresult.R in
    f x >>= fun y ->
    map_m f xs >>| fun ys ->
    y::ys

let windows_trust_anchors () =
  let open Rresult.R in
  let der_list = windows_trust_anchors_der () in
  let cert_list_result =
    map_m (fun der ->
      Cstruct.of_string der
      |> X509.Certificate.decode_der
      ) der_list
  in
  cert_list_result >>| fun cert_list ->
  X509.Certificate.encode_pem_multiple cert_list
  |> Cstruct.to_string

let trust_anchors () =
  let open Rresult.R.Infix in
  if Sys.win32 then
    windows_trust_anchors ()
  else
    let cmd = Bos.Cmd.(v "uname" % "-s") in
    Bos.OS.Cmd.(run_out cmd |> out_string |> success) >>= function
    | "FreeBSD" -> detect_one freebsd_location
    | "OpenBSD" -> detect_one openbsd_location
    | "Linux" -> detect_list linux_locations
    | "Darwin" ->
        let cmd =
          Bos.Cmd.(
            v "security" % "find-certificate" % "-a" % "-p"
            % macos_keychain_location)
        in
        Bos.OS.Cmd.(run_out cmd |> out_string |> success)
    | s -> Error (`Msg ("ca-certs: unknown system " ^ s ^ ".\n" ^ issue))

let authenticator ?crls ?hash_whitelist () =
  let open Rresult.R.Infix in
  trust_anchors () >>= fun data ->
  let time () = Some (Ptime_clock.now ()) in
  (* we cannot use decode_pem_multiple since this fails on the first
     undecodable certificate - while we'd like to stay operational, and ignore
     some certificates *)
  let sep = "-----END CERTIFICATE-----" in
  let certs = Astring.String.cuts ~sep ~empty:false data in
  let cas =
    List.fold_left
      (fun acc data ->
        let data = data ^ sep in
        match X509.Certificate.decode_pem (Cstruct.of_string data) with
        | Ok ca -> ca :: acc
        | Error (`Msg msg) ->
            Log.warn (fun m -> m "Failed to decode a trust anchor %s." msg);
            Log.debug (fun m -> m "Full certificate:@.%s" data);
            acc)
      [] certs
  in
  let cas = List.rev cas in
  match cas with
  | [] -> Error (`Msg ("ca-certs: empty trust anchors.\n" ^ issue))
  | _ -> Ok (X509.Authenticator.chain_of_trust ?crls ?hash_whitelist ~time cas)
