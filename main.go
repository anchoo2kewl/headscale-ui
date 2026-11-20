package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type node struct {
	Name      string    `json:"name"`
	GivenName string    `json:"givenName"`
	IPs       []string  `json:"ipAddresses"`
	Online    bool      `json:"online"`
	LastSeen  time.Time `json:"lastSeen"`
	Expiry    time.Time `json:"expiry"`
	Tags      []string  `json:"tags"`
	User      struct {
		Name string `json:"name"`
	} `json:"user"`
}

type row struct {
	Name, IP, Tags, Owner, Seen, Expires string
	Online                               bool
}
type page struct {
	Rows       []row
	Online     int
	Updated    string
	Monitoring string
	Auth       bool
}
type dashboard struct {
	client                    *http.Client
	endpoint, key, monitoring string
	view                      *template.Template
	authenticated             bool
}

func newDashboard(endpoint, key string) (*dashboard, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || !loopbackHost(u.Hostname()) || u.Port() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("HEADSCALE_URL must be an HTTP loopback address with an explicit port")
	}
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("Headscale API key is required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &dashboard{
		endpoint: endpoint + "/api/v1/node", key: strings.TrimSpace(key),
		client: &http.Client{Timeout: 5 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		view:   template.Must(template.New("dashboard").Parse(html)),
	}, nil
}

func (d *dashboard) nodes(ctx context.Context) ([]node, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+d.key)
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, errors.New("Headscale API unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Headscale API refused the request")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		return nil, errors.New("Headscale response exceeded limit")
	}
	var result struct {
		Nodes *[]node `json:"nodes"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, errors.New("Headscale returned invalid node data")
	}
	if result.Nodes == nil {
		return nil, errors.New("Headscale response has no node list")
	}
	return *result.Nodes, nil
}

func (d *dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/" && r.URL.Path != "/healthz" {
		http.NotFound(w, r)
		return
	}
	nodes, err := d.nodes(r.Context())
	if err != nil {
		http.Error(w, "Headscale is unavailable. Check the control server or dashboard API key.", http.StatusBadGateway)
		return
	}
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	p := page{Updated: time.Now().UTC().Format("15:04:05 UTC"), Monitoring: d.monitoring, Auth: d.authenticated}
	for _, n := range nodes {
		name := n.GivenName
		if name == "" {
			name = n.Name
		}
		item := row{Name: name, Online: n.Online, Tags: strings.Join(n.Tags, ", "), Owner: n.User.Name, Seen: "Never", Expires: "Never"}
		for _, raw := range n.IPs {
			ip, e := netip.ParseAddr(raw)
			if e == nil && ip.Is4() {
				item.IP = ip.String()
				break
			}
		}
		if !n.LastSeen.IsZero() {
			item.Seen = n.LastSeen.UTC().Format("02 Jan 2006, 15:04 UTC")
		}
		if n.Online {
			item.Seen = "Connected now"
			p.Online++
		}
		if !n.Expiry.IsZero() {
			item.Expires = n.Expiry.UTC().Format("02 Jan 2006")
		}
		p.Rows = append(p.Rows, item)
	}
	sort.Slice(p.Rows, func(i, j int) bool { return p.Rows[i].Name < p.Rows[j].Name })
	var out bytes.Buffer
	if err := d.view.Execute(&out, p); err != nil {
		http.Error(w, "Dashboard rendering failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodGet {
		_, _ = w.Write(out.Bytes())
	}
}

func loopbackHost(host string) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func privateListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.IsLoopback() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

func main() {
	listen := os.Getenv("LISTEN")
	if listen == "" {
		listen = "127.0.0.1:8091"
	}
	if !privateListen(listen) {
		log.Fatal("LISTEN must use loopback or the Tailscale IPv4 range")
	}
	key, err := os.ReadFile(os.Getenv("HEADSCALE_KEY_FILE"))
	if err != nil {
		log.Fatal("Cannot read dashboard API credential")
	}
	endpoint := os.Getenv("HEADSCALE_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	d, err := newDashboard(endpoint, string(key))
	if err != nil {
		log.Fatal(err)
	}
	if raw := os.Getenv("MONITORING_URL"); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			log.Fatal("MONITORING_URL must be an HTTP(S) URL without credentials")
		}
		d.monitoring = raw
	}
	var handler http.Handler = d
	username, passwordFile := os.Getenv("HEADSCALE_UI_USERNAME"), os.Getenv("HEADSCALE_UI_PASSWORD_FILE")
	if username != "" || passwordFile != "" {
		password, err := os.ReadFile(passwordFile)
		password = bytes.TrimRight(password, "\r\n")
		if err != nil || username == "" || strings.ContainsAny(username, ":\r\n") || len(password) < 20 || len(password) > 256 || bytes.ContainsAny(password, "\r\n") {
			log.Fatal("Authentication requires a username and a password file containing 20–256 characters on one line")
		}
		publicURL := os.Getenv("PUBLIC_URL")
		if publicURL == "" {
			publicURL = "http://" + listen + "/"
		}
		handler, err = newLogin(d, username, password, publicURL)
		if err != nil {
			log.Fatal(err)
		}
		d.authenticated = true
	} else {
		host, _, _ := net.SplitHostPort(listen)
		if !loopbackHost(host) {
			log.Fatal("Mesh bindings require HEADSCALE_UI_USERNAME and HEADSCALE_UI_PASSWORD_FILE")
		}
	}
	server := &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	log.Print("Private Headscale dashboard listening on ", listen)
	log.Fatal(server.ListenAndServe())
}

const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="30"><title>Headscale · Machines</title><style>
:root{font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;color:#e8edf5;background:#0c111b;color-scheme:dark}*{box-sizing:border-box}body{margin:0}main{max-width:1180px;margin:auto;padding:42px 24px}header{display:flex;justify-content:space-between;align-items:center;gap:24px;margin-bottom:36px}.brand{font-size:12px;letter-spacing:.14em;color:#8ba6c8;text-transform:uppercase}h1{font-size:34px;letter-spacing:-.04em;margin:8px 0}p{color:#9cabc0;margin:8px 0;line-height:1.6}a{color:#a7c9ff;text-decoration:none}a:hover{text-decoration:underline}.actions{display:flex;gap:12px;flex-wrap:wrap}.button{font:inherit;cursor:pointer;display:inline-block;padding:10px 15px;border:1px solid #31425d;border-radius:9px;background:#172234}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:26px}.stat,.panel{border:1px solid #263247;background:#111a28;border-radius:12px}.stat{padding:20px}.stat strong{display:block;font-size:30px;line-height:1.3}.stat span{font-size:13px;color:#9cabc0}.panel{overflow:auto}table{width:100%;border-collapse:collapse;text-align:left}th{font-size:11px;color:#93a6c2;text-transform:uppercase;letter-spacing:.08em;background:#141f30}th,td{padding:18px 20px;white-space:nowrap;border-bottom:1px solid #243046}tr:last-child td{border:0}.name{font-weight:650}.sub{font-size:12px;color:#91a0b6;margin-top:5px}.status{font-size:12px;padding:5px 9px;border-radius:99px;display:inline-block}.up{color:#99ebc0;background:#143b2c}.down{color:#c1cada;background:#2c3544}code{font:13px ui-monospace,monospace;color:#c4d5ed}.notes{margin-top:24px;display:flex;justify-content:space-between;gap:24px;font-size:12px}.empty{text-align:center;padding:40px}.tag{font-size:12px;color:#a4b3c9}@media(max-width:700px){main{padding:26px 16px}header{align-items:flex-start;flex-direction:column}.stats{gap:8px}.stat{padding:14px}h1{font-size:29px}.notes{flex-direction:column;gap:4px}th,td{padding:15px}}
</style></head><body><main><header><div><div class="brand">Headscale / Private network</div><h1>Machines</h1><p>Your workstations and infrastructure, connected through Headscale.</p></div><nav class="actions" aria-label="Dashboard links">{{if .Monitoring}}<a class="button" href="{{.Monitoring}}">Open monitoring ↗</a>{{end}}<a class="button" href="./">Refresh</a>{{if .Auth}}<form method="post" action="./logout"><button class="button" type="submit">Log out</button></form>{{end}}</nav></header><section class="stats" aria-label="Network summary"><div class="stat"><strong>{{len .Rows}}</strong><span>Enrolled devices</span></div><div class="stat"><strong>{{.Online}}</strong><span>Online now</span></div><div class="stat"><strong>Headscale</strong><span>Private team network</span></div></section><section class="panel" aria-label="Enrolled machines"><table><thead><tr><th>Machine</th><th>Status</th><th>Mesh address</th><th>Access</th><th>Last seen / key expiry</th></tr></thead><tbody>{{range .Rows}}<tr><td><div class="name">{{.Name}}</div><div class="sub">{{.Owner}}</div></td><td>{{if .Online}}<span class="status up">● Online</span>{{else}}<span class="status down">○ Offline</span>{{end}}</td><td><code>{{.IP}}</code></td><td class="tag">{{if .Tags}}{{.Tags}}{{else}}Personal device{{end}}</td><td><div class="sub">{{.Seen}}</div><div class="sub">Expires {{.Expires}}</div></td></tr>{{else}}<tr><td class="empty" colspan="5">No devices enrolled yet.</td></tr>{{end}}</tbody></table></section><footer class="notes"><p>Updated {{.Updated}} · Refreshes every 30 seconds.<br>Online means connected to Headscale; it does not certify desktop or disk health.</p><p>Use a machine’s mesh address in RustDesk or SSH.<br>This dashboard is read-only. Headscale must be connected.</p></footer></main></body></html>`
