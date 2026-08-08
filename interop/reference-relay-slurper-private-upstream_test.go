package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/cmd/relay/relay/models"
	"github.com/bluesky-social/indigo/cmd/relay/stream"
)

type privateUpstreamObservation struct {
	Path           string `json:"path"`
	Host           string `json:"host"`
	ForwardedHost  string `json:"forwardedHost"`
	ForwardedProto string `json:"forwardedProto"`
	ForwardedFor   string `json:"forwardedFor"`
	UserAgent      string `json:"userAgent"`
}

func TestReferenceRelaySlurperPrivateWSS(t *testing.T) {
	observerURL := os.Getenv("SLURPER_PROOF_OBSERVER_URL")
	if observerURL == "" {
		t.Fatal("SLURPER_PROOF_OBSERVER_URL is required")
	}

	config := DefaultSlurperConfig()
	config.UserAgent = "reference-relay-slurper-proof"
	config.PersistCursorPeriod = time.Hour
	config.PersistCursorCallback = func(context.Context, *[]HostCursor) error { return nil }
	config.PersistHostStatusCallback = func(context.Context, uint64, models.HostStatus) error { return nil }

	slurper, err := NewSlurper(func(context.Context, *stream.XRPCStreamEvent, string, uint64) error {
		return nil
	}, config)
	if err != nil {
		t.Fatalf("construct production Slurper: %v", err)
	}
	t.Cleanup(func() {
		_ = slurper.KillUpstreamConnection(context.Background(), "swan.test", false)
		if err := slurper.Shutdown(); err != nil {
			t.Errorf("shut down production Slurper: %v", err)
		}
	})

	if err := slurper.Subscribe(&models.Host{
		ID:       1,
		Hostname: "swan.test",
		NoSSL:    false,
		LastSeq:  -1,
	}); err != nil {
		t.Fatalf("subscribe production Slurper: %v", err)
	}

	client := &http.Client{Timeout: 6 * time.Second}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, observerURL, nil)
	if err != nil {
		t.Fatalf("construct observation request: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("wait for production Slurper connection: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		t.Fatalf("read observation response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("production Slurper did not reach the private WSS upstream: observer status %s: %s", response.Status, strings.TrimSpace(string(body)))
	}

	var observation privateUpstreamObservation
	if err := json.Unmarshal(body, &observation); err != nil {
		t.Fatalf("decode observation: %v", err)
	}
	want := privateUpstreamObservation{
		Path:           "/xrpc/com.atproto.sync.subscribeRepos",
		Host:           "swan.test",
		ForwardedHost:  "swan.test",
		ForwardedProto: "https",
		ForwardedFor:   "172.30.0.8",
		UserAgent:      "reference-relay-slurper-proof",
	}
	if observation != want {
		t.Fatalf("private WSS route mismatch\n got: %+v\nwant: %+v", observation, want)
	}

	fmt.Println("REFERENCE RELAY SLURPER PRIVATE WSS PROOF OK")
}
