package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/cmd/relay/stream"
	"github.com/gorilla/websocket"
)

type captureIndex struct {
	File string `json:"file"`
	Kind string `json:"kind"`
	Seq  int64  `json:"seq"`
	DID  string `json:"did"`
}

func eventSummary(event *stream.XRPCStreamEvent) (string, int64, string, error) {
	switch {
	case event.RepoIdentity != nil:
		return "identity", event.RepoIdentity.Seq, event.RepoIdentity.Did, nil
	case event.RepoAccount != nil:
		return "account", event.RepoAccount.Seq, event.RepoAccount.Did, nil
	case event.RepoSync != nil:
		return "sync", event.RepoSync.Seq, event.RepoSync.Did, nil
	case event.RepoCommit != nil:
		return "commit", event.RepoCommit.Seq, event.RepoCommit.Repo, nil
	case event.RepoInfo != nil:
		return "info", -1, "", nil
	case event.Error != nil:
		return "error", -1, "", errors.New("relay returned an error frame")
	default:
		return "", -1, "", errors.New("unsupported relay frame")
	}
}

func serveHandleDID(path string, address string) {
	if address != "127.0.0.1:2583" {
		fmt.Fprintln(os.Stderr, "handle proof listener must use the fixed laboratory address")
		os.Exit(64)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		fmt.Fprintln(os.Stderr, "handle proof DID file must be a mode 0600 regular file")
		os.Exit(64)
	}
	raw, err := os.ReadFile(path)
	did := strings.TrimSpace(string(raw))
	if err != nil || len(did) > 2048 || !strings.HasPrefix(did, "did:plc:") || strings.ContainsAny(did, " \t\r\n") {
		fmt.Fprintln(os.Stderr, "handle proof DID is invalid")
		os.Exit(64)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/atproto-did", func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			response.Header().Set("Allow", http.MethodGet)
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(response, did)
	})
	server := &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       5 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "handle proof listener failed")
		os.Exit(1)
	}
}

func servePLCLoopbackProxy() {
	target, err := url.Parse("http://reference-plc:2582")
	if err != nil {
		panic("fixed PLC target is invalid")
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(response http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(response, "PLC proxy unavailable", http.StatusBadGateway)
	}
	server := &http.Server{
		Addr:              "127.0.0.1:2582",
		Handler:           proxy,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       10 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "PLC loopback proxy failed")
		os.Exit(1)
	}
}

func main() {
	var endpoint string
	var outputDirectory string
	var timeout time.Duration
	var handleDIDFile string
	var handleListenAddress string
	var plcLoopbackProxy bool
	flag.StringVar(&endpoint, "url", "", "wss subscribeRepos endpoint")
	flag.StringVar(&outputDirectory, "output-directory", "", "owner-only output directory")
	flag.DurationVar(&timeout, "timeout", 10*time.Minute, "bounded capture duration")
	flag.StringVar(&handleDIDFile, "serve-handle-did-file", "", "serve a fixed laboratory handle proof DID")
	flag.StringVar(&handleListenAddress, "handle-listen", "127.0.0.1:2583", "fixed laboratory handle proof address")
	flag.BoolVar(&plcLoopbackProxy, "serve-plc-loopback-proxy", false, "proxy the pinned PLC service through Swan loopback")
	flag.Parse()
	if plcLoopbackProxy {
		if endpoint != "" || outputDirectory != "" || handleDIDFile != "" {
			fmt.Fprintln(os.Stderr, "capture, handle proof, and PLC proxy modes are mutually exclusive")
			os.Exit(64)
		}
		servePLCLoopbackProxy()
		return
	}
	if handleDIDFile != "" {
		if endpoint != "" || outputDirectory != "" {
			fmt.Fprintln(os.Stderr, "capture and handle proof modes are mutually exclusive")
			os.Exit(64)
		}
		serveHandleDID(handleDIDFile, handleListenAddress)
		return
	}
	if endpoint == "" || outputDirectory == "" || timeout <= 0 || timeout > 30*time.Minute {
		fmt.Fprintln(os.Stderr, "capture URL, output directory, and bounded timeout are required")
		os.Exit(64)
	}
	if info, err := os.Stat(outputDirectory); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		fmt.Fprintln(os.Stderr, "capture output directory must already exist at mode 0700")
		os.Exit(64)
	}
	indexPath := filepath.Join(outputDirectory, "index.jsonl")
	index, err := os.OpenFile(indexPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "capture index is unavailable")
		os.Exit(1)
	}
	defer index.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	connection, response, err := websocket.DefaultDialer.DialContext(ctx, endpoint, nil)
	if err != nil {
		if response != nil {
			fmt.Fprintf(os.Stderr, "relay capture upgrade failed: HTTP %d\n", response.StatusCode)
		} else {
			fmt.Fprintln(os.Stderr, "relay capture connection failed")
		}
		os.Exit(1)
	}
	defer connection.Close()
	connection.SetReadLimit(16 * 1024 * 1024)
	readyPath := filepath.Join(outputDirectory, "ready")
	ready, err := os.OpenFile(readyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "relay capture readiness marker is unavailable")
		os.Exit(1)
	}
	if err := ready.Sync(); err != nil {
		_ = ready.Close()
		fmt.Fprintln(os.Stderr, "relay capture readiness marker sync failed")
		os.Exit(1)
	}
	if err := ready.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "relay capture readiness marker close failed")
		os.Exit(1)
	}
	encoder := json.NewEncoder(index)
	for ordinal := 1; ; ordinal++ {
		if deadline, ok := ctx.Deadline(); ok {
			_ = connection.SetReadDeadline(deadline)
		}
		messageType, payload, err := connection.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fmt.Fprintln(os.Stderr, "relay capture read failed")
			os.Exit(1)
		}
		if messageType != websocket.BinaryMessage || len(payload) == 0 || len(payload) > 16*1024*1024 {
			fmt.Fprintln(os.Stderr, "relay capture received an invalid frame")
			os.Exit(1)
		}
		var event stream.XRPCStreamEvent
		if err := event.Deserialize(bytes.NewReader(payload)); err != nil {
			fmt.Fprintln(os.Stderr, "relay capture received an undecodable frame")
			os.Exit(1)
		}
		kind, sequence, did, err := eventSummary(&event)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		name := fmt.Sprintf("frame-%06d.bin", ordinal)
		path := filepath.Join(outputDirectory, name)
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "relay capture frame write failed")
			os.Exit(1)
		}
		if err := encoder.Encode(captureIndex{File: name, Kind: kind, Seq: sequence, DID: did}); err != nil {
			fmt.Fprintln(os.Stderr, "relay capture index write failed")
			os.Exit(1)
		}
		if err := index.Sync(); err != nil {
			fmt.Fprintln(os.Stderr, "relay capture index sync failed")
			os.Exit(1)
		}
	}
}
