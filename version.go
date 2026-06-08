package main

// Build-time stamps, populated via
//
//	-ldflags "-X main.version=… -X main.commit=… -X main.date=…"
//
// (see Taskfile build / the release workflow). Defaults keep `go run`
// and bare `go build` working.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)
