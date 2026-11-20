package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testDashboard(t *testing.T, body string, code int) *dashboard {
	t.Helper()
	d, err := newDashboard("http://127.0.0.1:8080", "synthetic-server-key")
	if err != nil {
		t.Fatal(err)
	}
	d.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.String() != "http://127.0.0.1:8080/api/v1/node" || r.Header.Get("Authorization") != "Bearer synthetic-server-key" {
			t.Errorf("unexpected upstream request")
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	return d
}

func TestShowsLiveNodesWithoutLeakingKeysOrHTML(t *testing.T) {
	d := testDashboard(t, `{"nodes":[{"givenName":"<script>alert(1)</script>","ipAddresses":["fd7a::2","100.64.0.2"],"online":true,"lastSeen":"2026-11-19T20:00:00Z","expiry":"2027-02-17T20:00:00Z","tags":["tag:work"],"nodeKey":"NODE-KEY-MUST-NOT-RENDER","preAuthKey":{"key":"ENROLLMENT-KEY-MUST-NOT-RENDER"}}]}`, 200)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	s := w.Body.String()
	if w.Code != 200 || !strings.Contains(s, "100.64.0.2") || !strings.Contains(s, "Connected now") || !strings.Contains(s, "&lt;script&gt;") {
		t.Fatalf("unexpected page status or content: %d", w.Code)
	}
	for _, secret := range []string{"<script>", "NODE-KEY-MUST-NOT-RENDER", "ENROLLMENT-KEY-MUST-NOT-RENDER", "synthetic-server-key"} {
		if strings.Contains(s, secret) {
			t.Errorf("unsafe value rendered: %s", secret)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Error("missing protection headers")
	}
}

func TestUpstreamFailureNeverLooksHealthy(t *testing.T) {
	for _, body := range []string{`{"error":"synthetic-server-key"}`, "not json", `{}`, strings.Repeat("x", (1<<20)+1)} {
		code := 200
		if strings.HasPrefix(body, `{"error"`) {
			code = 401
		}
		d := testDashboard(t, body, code)
		w := httptest.NewRecorder()
		d.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
		if w.Code != 502 || strings.Contains(w.Body.String(), "synthetic-server-key") {
			t.Errorf("upstream error not safely handled: %d", w.Code)
		}
	}
}

func TestRejectsMutationsAndUnknownRoutes(t *testing.T) {
	d := testDashboard(t, `{"nodes":[]}`, 200)
	for _, tc := range []struct {
		method, path string
		code         int
	}{{"POST", "/", 405}, {"GET", "/api/v1/node", 404}, {"GET", "/healthz", 204}, {"HEAD", "/", 200}} {
		w := httptest.NewRecorder()
		d.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.code {
			t.Errorf("%s %s: %d", tc.method, tc.path, w.Code)
		}
		if tc.method == "HEAD" && w.Body.Len() != 0 {
			t.Error("HEAD returned a body")
		}
	}
}

func TestPrivateBindingAndLocalAPIOnly(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8091", ":8091", "[::]:8091", "203.0.113.10:8091", "localhost:8091"} {
		if privateListen(addr) {
			t.Errorf("accepted non-private bind %s", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:8091", "100.64.0.5:8091"} {
		if !privateListen(addr) {
			t.Errorf("rejected private bind %s", addr)
		}
	}
	for _, endpoint := range []string{"https://example.com", "http://127.0.0.1:8080/other", "http://127.0.0.1:8080?next=other"} {
		if _, err := newDashboard(endpoint, "synthetic"); err == nil {
			t.Errorf("accepted API override")
		}
	}
}

func TestCancellation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer upstream.Close()
	d, _ := newDashboard("http://127.0.0.1:8080", "synthetic")
	d.endpoint = upstream.URL
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := d.nodes(ctx); err == nil {
		t.Fatal("canceled upstream request succeeded")
	}
}

func TestRedirectDoesNotForwardCredential(t *testing.T) {
	leaked := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true; w.WriteHeader(200) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer source.Close()
	d, _ := newDashboard("http://127.0.0.1:8080", "synthetic")
	d.endpoint = source.URL
	if _, err := d.nodes(context.Background()); err == nil {
		t.Error("redirect accepted")
	}
	if leaked {
		t.Error("credential forwarded to redirect target")
	}
}
