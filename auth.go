package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

const sessionLifetime = 12 * time.Hour
const sessionCookie = "headscale_ui_session"

type loginHandler struct {
	next               http.Handler
	username, password [32]byte
	origin, prefix     string
	secure             bool
	mu                 sync.Mutex
	sessions           map[[32]byte]time.Time
}

func newLogin(next http.Handler, username string, password []byte, publicURL string) (*loginHandler, error) {
	u, err := url.Parse(publicURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return nil, errors.New("PUBLIC_URL must be the browser-facing HTTP(S) URL without credentials or query")
	}
	if u.Scheme == "http" && !loopbackHost(u.Hostname()) {
		ipHost := u.Hostname()
		if !privateListen(ipHost + ":80") {
			return nil, errors.New("Public browser access requires HTTPS")
		}
	}
	prefix := path.Clean("/" + strings.Trim(u.Path, "/"))
	if prefix != "/" {
		prefix += "/"
	}
	return &loginHandler{next: next, username: sha256.Sum256([]byte(username)), password: sha256.Sum256(password), origin: u.Scheme + "://" + u.Host, prefix: prefix, secure: u.Scheme == "https", sessions: make(map[[32]byte]time.Time)}, nil
}

func (h *loginHandler) valid(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	key := sha256.Sum256([]byte(c.Value))
	h.mu.Lock()
	defer h.mu.Unlock()
	expiry, ok := h.sessions[key]
	if ok && time.Now().Before(expiry) {
		return true
	}
	delete(h.sessions, key)
	return false
}

func (h *loginHandler) cookie(w http.ResponseWriter, token string, expires time.Time, age int) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: h.prefix, Expires: expires, MaxAge: age, HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteStrictMode})
}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	if r.Method == http.MethodPost && r.Header.Get("Origin") != h.origin {
		http.Error(w, "Invalid request origin", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/login":
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			if h.valid(r) {
				http.Redirect(w, r, h.prefix, http.StatusSeeOther)
				return
			}
			h.form(w, r, false)
		case http.MethodPost:
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Invalid login form", http.StatusBadRequest)
				return
			}
			user, pass := sha256.Sum256([]byte(r.PostForm.Get("username"))), sha256.Sum256([]byte(r.PostForm.Get("password")))
			if subtle.ConstantTimeCompare(user[:], h.username[:])&subtle.ConstantTimeCompare(pass[:], h.password[:]) != 1 {
				h.form(w, r, true)
				return
			}
			tokenBytes := make([]byte, 32)
			if _, err := rand.Read(tokenBytes); err != nil {
				http.Error(w, "Login unavailable", http.StatusServiceUnavailable)
				return
			}
			token := base64.RawURLEncoding.EncodeToString(tokenBytes)
			expiry := time.Now().Add(sessionLifetime)
			h.mu.Lock()
			for key, until := range h.sessions {
				if !time.Now().Before(until) {
					delete(h.sessions, key)
				}
			}
			if c, err := r.Cookie(sessionCookie); err == nil {
				delete(h.sessions, sha256.Sum256([]byte(c.Value)))
			}
			if len(h.sessions) >= 256 {
				h.mu.Unlock()
				http.Error(w, "Too many active sessions", http.StatusServiceUnavailable)
				return
			}
			h.sessions[sha256.Sum256([]byte(token))] = expiry
			h.mu.Unlock()
			h.cookie(w, token, expiry, int(sessionLifetime.Seconds()))
			http.Redirect(w, r, h.prefix, http.StatusSeeOther)
		default:
			w.Header().Set("Allow", "GET, HEAD, POST")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	case "/logout":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if c, err := r.Cookie(sessionCookie); err == nil {
			h.mu.Lock()
			delete(h.sessions, sha256.Sum256([]byte(c.Value)))
			h.mu.Unlock()
		}
		h.cookie(w, "", time.Unix(1, 0), -1)
		http.Redirect(w, r, h.prefix+"login", http.StatusSeeOther)
	default:
		if !h.valid(r) {
			if r.URL.Path == "/healthz" {
				http.Error(w, "Login required", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, h.prefix+"login", http.StatusSeeOther)
			return
		}
		h.next.ServeHTTP(w, r)
	}
}

func (h *loginHandler) form(w http.ResponseWriter, r *http.Request, failed bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if failed {
		w.WriteHeader(http.StatusUnauthorized)
	}
	if r.Method == http.MethodHead {
		return
	}
	_ = loginPage.Execute(w, struct {
		Prefix string
		Failed bool
	}{h.prefix, failed})
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in · Headscale</title><style>:root{font-family:system-ui,sans-serif;color:#e8edf5;background:#0c111b;color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px}main{width:100%;max-width:410px;padding:34px;border:1px solid #29374e;border-radius:16px;background:#111a28}small{color:#94afd2;text-transform:uppercase;letter-spacing:.12em}h1{font-size:28px;letter-spacing:-.03em;margin:14px 0}p{font-size:14px;color:#a3b0c5;line-height:1.6}label{display:block;margin:22px 0 8px;font-size:14px}input{width:100%;font:inherit;padding:12px;border:1px solid #40516c;border-radius:8px;background:#0c1420;color:#edf3fc}input:focus{outline:2px solid #8bb6ff;outline-offset:2px}button{width:100%;font:inherit;font-weight:600;padding:12px;border:0;border-radius:8px;background:#a7c9ff;color:#10213c;margin-top:26px;cursor:pointer}.error{padding:12px;border-radius:8px;background:#42242a;color:#ffd1d1}</style></head><body><main><small>Headscale / Private network</small><h1>Welcome back</h1><p>Sign in to view your machines and network status.</p>{{if .Failed}}<p class="error" role="alert">The username or password is incorrect.</p>{{end}}<form method="post" action="{{.Prefix}}login"><label for="username">Username</label><input id="username" name="username" autocomplete="username" required maxlength="128" autofocus><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required maxlength="256"><button type="submit">Sign in</button></form></main></body></html>`))
