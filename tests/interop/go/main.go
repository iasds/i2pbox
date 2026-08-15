// Command interop_go cross-validates i2pbox outputs against the go-i2p
// implementation's independent codecs and parsers.
//
// Subcommands (called by tests/interop/run_interop.sh):
//
//	base64-encode <hex>                 I2P base64 encode of raw bytes
//	base64-decode <b64> <expected-hex>  I2P base64 decode, compare to bytes
//	destination <dest-b64> <expected-b32> <expected-hash-b64>
//	                                    parse a Destination, recompute its
//	                                    sha256 hash and b32, compare
//	router-info <file>                  parse a router.info, verify signature
//	offline <file> <dest-sigtype>       parse an offline signing key file
package main

import (
	"encoding/base32"
	"encoding/hex"
	"strings"
	"fmt"
	"os"

	"github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/offline_signature"
	"github.com/go-i2p/common/router_info"
)

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "interop_go: "+format+"\n", args...)
	os.Exit(1)
}

func hexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		die("bad hex %q: %v", s, err)
	}
	return b
}

func cmdBase64Encode(args []string) {
	if len(args) != 1 {
		die("usage: base64-encode <hex>")
	}
	fmt.Println(base64.EncodeToString(hexBytes(args[0])))
}

func cmdBase64Decode(args []string) {
	if len(args) != 2 {
		die("usage: base64-decode <b64> <expected-hex>")
	}
	raw, err := base64.DecodeString(args[0])
	if err != nil {
		die("decode failed: %v", err)
	}
	want := hexBytes(args[1])
	if hex.EncodeToString(raw) != hex.EncodeToString(want) {
		die("decode mismatch: got %x want %x", raw, want)
	}
	fmt.Println("ok")
}

func cmdDestination(args []string) {
	if len(args) != 3 {
		die("usage: destination <dest-b64> <expected-b32> <expected-hash-b64>")
	}
	raw, err := base64.DecodeString(args[0])
	if err != nil {
		die("destination base64 decode failed: %v", err)
	}
	dest, _, err := destination.NewDestinationFromBytes(raw)
	if err != nil {
		die("destination parse failed: %v", err)
	}
	if !dest.IsValid() {
		die("destination failed validation")
	}
	h, err := dest.Hash()
	if err != nil {
		die("destination hash failed: %v", err)
	}
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:])
	// I2P convention is lowercase with a .b32.i2p suffix; go-i2p emits
	// uppercase. Normalize both sides before comparing.
	got := strings.ToLower(b32)
	want := strings.ToLower(strings.TrimSuffix(args[1], ".b32.i2p"))
	if got != want {
		die("b32 mismatch: go-i2p=%s i2pbox=%s", b32, args[1])
	}
	hb64 := base64.EncodeToString(h[:])
	if hb64 != args[2] {
		die("hash base64 mismatch: go-i2p=%s i2pbox=%s", hb64, args[2])
	}
	fmt.Println("ok")
}

func cmdRouterInfo(args []string) {
	if len(args) != 1 {
		die("usage: router-info <file>")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		die("read: %v", err)
	}
	ri, _, err := router_info.ReadRouterInfo(data)
	if err != nil {
		die("router.info parse failed: %v", err)
	}
	ok, err := ri.VerifySignature()
	if err != nil {
		die("router.info signature verify error: %v", err)
	}
	if !ok {
		die("router.info signature invalid")
	}
	fmt.Println("ok")
}

func cmdOffline(args []string) {
	if len(args) != 2 {
		die("usage: offline <file> <dest-sigtype>")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		die("read: %v", err)
	}
	var sigType uint16
	if _, err := fmt.Sscanf(args[1], "%d", &sigType); err != nil {
		die("bad sigtype: %v", err)
	}
	_, _, err = offline_signature.ReadOfflineSignature(data, sigType)
	if err != nil {
		die("offline signature parse failed: %v", err)
	}
	fmt.Println("ok")
}

func main() {
	if len(os.Args) < 2 {
		die("usage: interop_go <subcommand>")
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "base64-encode":
		cmdBase64Encode(args)
	case "base64-decode":
		cmdBase64Decode(args)
	case "destination":
		cmdDestination(args)
	case "router-info":
		cmdRouterInfo(args)
	case "offline":
		cmdOffline(args)
	default:
		die("unknown subcommand %q", cmd)
	}
}
