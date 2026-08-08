package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type observation struct {
	Path           string `json:"path"`
	Host           string `json:"host"`
	ForwardedHost  string `json:"forwardedHost"`
	ForwardedProto string `json:"forwardedProto"`
	ForwardedFor   string `json:"forwardedFor"`
	UserAgent      string `json:"userAgent"`
}

type proofServer struct {
	observed chan struct{}
	acked    chan struct{}
	once     sync.Once
	ackOnce  sync.Once
	result   observation
	err      error
}

func (s *proofServer) health(response http.ResponseWriter, _ *http.Request) {
	response.WriteHeader(http.StatusOK)
}

func (s *proofServer) subscribe(response http.ResponseWriter, request *http.Request) {
	result := observation{
		Path:           request.URL.Path,
		Host:           request.Host,
		ForwardedHost:  request.Header.Get("X-Forwarded-Host"),
		ForwardedProto: request.Header.Get("X-Forwarded-Proto"),
		ForwardedFor:   request.Header.Get("X-Forwarded-For"),
		UserAgent:      request.UserAgent(),
	}

	var proofErr error
	if result.Path != "/xrpc/com.atproto.sync.subscribeRepos" {
		proofErr = fmt.Errorf("unexpected path %q", result.Path)
	} else if !strings.EqualFold(request.Header.Get("Upgrade"), "websocket") {
		proofErr = errors.New("missing WebSocket Upgrade header")
	} else if request.Header.Get("Sec-WebSocket-Version") != "13" {
		proofErr = fmt.Errorf("unexpected WebSocket version %q", request.Header.Get("Sec-WebSocket-Version"))
	} else if request.Header.Get("Sec-WebSocket-Key") == "" {
		proofErr = errors.New("missing WebSocket key")
	}
	if proofErr != nil {
		s.record(result, proofErr)
		http.Error(response, proofErr.Error(), http.StatusBadRequest)
		return
	}

	hijacker, ok := response.(http.Hijacker)
	if !ok {
		s.record(result, errors.New("HTTP server does not support hijacking"))
		http.Error(response, "WebSocket hijacking unavailable", http.StatusInternalServerError)
		return
	}
	connection, buffer, err := hijacker.Hijack()
	if err != nil {
		s.record(result, fmt.Errorf("hijack WebSocket: %w", err))
		return
	}
	defer connection.Close()

	acceptHash := sha1.Sum([]byte(request.Header.Get("Sec-WebSocket-Key") + websocketGUID))
	accept := base64.StdEncoding.EncodeToString(acceptHash[:])
	if _, err := fmt.Fprintf(buffer,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nServer: swan-slurper-proof\r\n\r\n",
		accept,
	); err != nil {
		s.record(result, fmt.Errorf("write WebSocket handshake: %w", err))
		return
	}
	if err := buffer.Flush(); err != nil {
		s.record(result, fmt.Errorf("flush WebSocket handshake: %w", err))
		return
	}

	s.record(result, nil)
	<-s.acked
}

func (s *proofServer) record(result observation, err error) {
	s.once.Do(func() {
		s.result = result
		s.err = err
		close(s.observed)
	})
}

func (s *proofServer) proof(response http.ResponseWriter, request *http.Request) {
	timer := time.NewTimer(4 * time.Second)
	defer timer.Stop()
	select {
	case <-s.observed:
	case <-request.Context().Done():
		http.Error(response, request.Context().Err().Error(), http.StatusGatewayTimeout)
		return
	case <-timer.C:
		http.Error(response, "timed out waiting for production Slurper subscribeRepos request", http.StatusGatewayTimeout)
		return
	}

	s.ackOnce.Do(func() { close(s.acked) })
	if s.err != nil {
		http.Error(response, s.err.Error(), http.StatusBadRequest)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(s.result); err != nil {
		log.Printf("encode observation: %v", err)
	}
}

func serve() error {
	proof := &proofServer{
		observed: make(chan struct{}),
		acked:    make(chan struct{}),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", proof.health)
	mux.HandleFunc("GET /proof", proof.proof)
	mux.HandleFunc("GET /xrpc/com.atproto.sync.subscribeRepos", proof.subscribe)
	server := &http.Server{
		Addr:              "0.0.0.0:3000",
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}
	log.Println("reference relay Slurper proof upstream listening on :3000")
	return server.ListenAndServe()
}

func health(rawURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("health endpoint returned %s", response.Status)
	}
	return nil
}

func prepareTrust(source, destination string) error {
	contents, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read Caddy root: %w", err)
	}
	if !bytes.HasPrefix(contents, []byte("-----BEGIN CERTIFICATE-----\n")) {
		return errors.New("Caddy root is not a PEM certificate")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create trust directory: %w", err)
	}
	if err := os.WriteFile(destination, contents, 0o444); err != nil {
		return fmt.Errorf("write Caddy trust root: %w", err)
	}
	if err := os.Chmod(destination, 0o444); err != nil {
		return fmt.Errorf("set Caddy trust root mode: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	})
	server := &http.Server{
		Addr:              "127.0.0.1:3001",
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}
	log.Printf("Caddy trust root prepared at %s", destination)
	return server.ListenAndServe()
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: reference-relay-slurper-proof serve | health URL | prepare-trust SOURCE DESTINATION")
	}
	var err error
	switch os.Args[1] {
	case "serve":
		if len(os.Args) != 2 {
			log.Fatal("usage: reference-relay-slurper-proof serve")
		}
		err = serve()
	case "health":
		if len(os.Args) != 3 {
			log.Fatal("usage: reference-relay-slurper-proof health URL")
		}
		err = health(os.Args[2])
	case "prepare-trust":
		if len(os.Args) != 4 {
			log.Fatal("usage: reference-relay-slurper-proof prepare-trust SOURCE DESTINATION")
		}
		err = prepareTrust(os.Args[2], os.Args[3])
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}
