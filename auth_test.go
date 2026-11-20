package main

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLoginSessionAndLogout(t *testing.T) {
	d := testDashboard(t, `{"nodes":[]}`, 200)
	h, err := newLogin(d, "admin", []byte("SYNTHETIC-password-for-tests-only"), "https://dashboard.example.com/ui/")
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, form, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(form))
		if form != "" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := request("GET", "/", "", "", nil)
	if w.Code != 303 || w.Header().Get("Location") != "/ui/login" || w.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("expected form login redirect without browser prompt")
	}
	w = request("GET", "/login", "", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `type="password"`) || !strings.Contains(w.Body.String(), `action="/ui/login"`) {
		t.Fatal("missing login form")
	}
	form := url.Values{"username": {"admin"}, "password": {"SYNTHETIC-password-for-tests-only"}}.Encode()
	for _, origin := range []string{"", "https://other.example.com"} {
		if request("POST", "/login", form, origin, nil).Code != 403 {
			t.Error("cross-origin login accepted")
		}
	}
	w = request("POST", "/login", "username=admin&password=wrong", "https://dashboard.example.com", nil)
	if w.Code != 401 || !strings.Contains(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(w.Body.String(), "incorrect") {
		t.Error("invalid login should render safe error form")
	}
	w = request("POST", "/login", form, "https://dashboard.example.com", nil)
	cookies := w.Result().Cookies()
	if w.Code != 303 || len(cookies) != 1 {
		t.Fatal("login did not create session")
	}
	cookie := cookies[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/ui/" || cookie.MaxAge != 43200 {
		t.Fatal("unsafe session cookie")
	}
	if strings.Contains(cookie.Value, "SYNTHETIC") || len(cookie.Value) < 40 {
		t.Error("session is not opaque")
	}
	if request("GET", "/", "", "", cookie).Code != 200 {
		t.Error("session did not authenticate dashboard")
	}
	if request("GET", "/logout", "", "", cookie).Code != 405 {
		t.Error("GET logout should not mutate state")
	}
	if request("POST", "/logout", "", "https://other.example.com", cookie).Code != 403 {
		t.Error("cross-origin logout accepted")
	}
	if request("POST", "/logout", "", "https://dashboard.example.com", cookie).Code != 303 {
		t.Error("logout failed")
	}
	if request("GET", "/", "", "", cookie).Code != 303 {
		t.Error("old session still works after logout")
	}
}

func TestSessionExpiryAndRejectedOrigins(t *testing.T) {
	h, _ := newLogin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }), "admin", []byte("synthetic"), "https://dashboard.example.com/")
	token := "synthetic-session"
	h.sessions[sha256.Sum256([]byte(token))] = time.Now().Add(-time.Second)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Error("expired session accepted")
	}
	for _, raw := range []string{"http://public.example.com/", "https://user:pass@example.com/", "https://example.com/?key=x", "javascript:alert(1)"} {
		if _, err := newLogin(h, "admin", []byte("synthetic"), raw); err == nil {
			t.Errorf("unsafe public URL accepted")
		}
	}
}
