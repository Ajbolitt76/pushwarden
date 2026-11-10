package main

// Relay: registers devices, forwards opaque E2E ciphertext, wakes phones. PROTOCOL.md §3.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"github.com/gorilla/websocket"
)

const (
	maxBody              = 8 * 1024
	maxFrame             = 16 * 1024
	maxBufferedBytes     = 256 * 1024 // per recipient socket; a reader this far behind is dropped
	queueTTLMs           = 120_000
	queueMax             = 20
	sendsPerMin          = 60
	registrationsPerHour = 10
	authTimeout          = 10 * time.Second
	pingInterval         = 30 * time.Second
	writeTimeout         = 10 * time.Second
	wakeMinIntervalMs    = 5_000
	maxPushToken         = 4096
	idAlphabet           = "0123456789abcdefghjkmnpqrstvwxyz" // Crockford base32, lowercase
)

var (
	b64Pattern = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)
	devicePath = regexp.MustCompile(`^/v1/devices/([0-9a-z]{4}-[0-9a-z]{4})$`)
)

// Options configures a Relay.
type Options struct {
	DB         *DB
	Push       Push // nil: phones aren't woken
	TrustProxy bool // take the client IP from X-Forwarded-For
	Now        func() int64
	Log        func(format string, args ...any)
}

// Relay is the relay's HTTP and WebSocket handler.
type Relay struct {
	db        *DB
	push      Push
	trust     bool
	now       func() int64
	log       func(string, ...any)
	upgrader  websocket.Upgrader
	sendLimit *limiter
	regLimit  *limiter
	stop      chan struct{}
	stopOnce  sync.Once

	mu       sync.Mutex
	sockets  map[string]*conn
	lastWake map[string]int64
}

func NewRelay(o Options) *Relay {
	r := &Relay{
		db:    o.DB,
		push:  o.Push,
		trust: o.TrustProxy,
		now:   o.Now,
		log:   o.Log,
		upgrader: websocket.Upgrader{
			// Browser extensions connect from chrome-extension:// origins; auth is the token.
			CheckOrigin: func(*http.Request) bool { return true },
		},
		sendLimit: newLimiter(sendsPerMin, 60_000),
		regLimit:  newLimiter(registrationsPerHour, 3_600_000),
		stop:      make(chan struct{}),
		sockets:   map[string]*conn{},
		lastWake:  map[string]int64{},
	}
	if r.now == nil {
		r.now = func() int64 { return time.Now().UnixMilli() }
	}
	if r.log == nil {
		r.log = func(string, ...any) {}
	}
	go r.sweep()
	return r
}

// Close stops the sweeper and drops every socket.
func (r *Relay) Close() {
	r.stopOnce.Do(func() { close(r.stop) })
	r.mu.Lock()
	socks := make([]*conn, 0, len(r.sockets))
	for _, c := range r.sockets {
		socks = append(socks, c)
	}
	r.mu.Unlock()
	for _, c := range socks {
		c.terminate()
	}
}

func (r *Relay) sweep() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
			now := r.now()
			if err := r.db.Purge(now); err != nil {
				r.log("purge: %v", err)
			}
			r.sendLimit.sweep(now)
			r.regLimit.sweep(now)
			r.mu.Lock()
			for id, at := range r.lastWake {
				if now-at > wakeMinIntervalMs {
					delete(r.lastWake, id)
				}
			}
			r.mu.Unlock()
		}
	}
}

// --- HTTP ---

func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/v1/ws" {
		r.serveWS(w, req)
		return
	}
	if err := r.serveHTTP(w, req); err != nil {
		r.log("http error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal"})
	}
}

func (r *Relay) serveHTTP(w http.ResponseWriter, req *http.Request) error {
	path := req.URL.Path
	switch {
	case req.Method == http.MethodPost && path == "/v1/devices":
		return r.register(w, req)

	case path == "/v1/devices/me":
		me, err := r.authHeader(req)
		if err != nil {
			return err
		}
		if me == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "auth_failed"})
			return nil
		}
		switch req.Method {
		case http.MethodPut:
			b := readJSON(w, req)
			t, present := b["pushToken"]
			var token *string
			ok := present && me.Kind == "phone"
			if s, isStr := t.(string); isStr && utf16Len(s) <= maxPushToken {
				token = &s
			} else if t != nil {
				ok = false
			}
			if b == nil || !ok {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_request"})
				return nil
			}
			if err := r.db.SetPushToken(me.ID, token); err != nil {
				return err
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			if err := r.db.DeleteDevice(me.ID); err != nil {
				return err
			}
			if c := r.current(me.ID); c != nil {
				c.closeWith(4001, "deleted")
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		}
		return nil

	case req.Method == http.MethodGet && devicePath.MatchString(path):
		d, err := r.db.DeviceByID(devicePath.FindStringSubmatch(path)[1])
		if err != nil {
			return err
		}
		if d == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "unknown_device"})
		} else {
			writeJSON(w, http.StatusOK, map[string]any{"id": d.ID, "kind": d.Kind, "publicKey": d.PublicKey})
		}
		return nil

	case req.Method == http.MethodGet && path == "/healthz":
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return nil
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": "not_found"})
	return nil
}

func (r *Relay) register(w http.ResponseWriter, req *http.Request) error {
	if !r.regLimit.allow(r.clientIP(req), r.now()) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate_limited"})
		return nil
	}
	b := readJSON(w, req)
	pk, _ := b["publicKey"].(string)
	kind, _ := b["kind"].(string)
	raw, ok := decodeB64(pk)
	bad := b == nil || !ok || len(raw) != 32 || (kind != "phone" && kind != "ext")
	var push *string
	if t, present := b["pushToken"]; present && !bad {
		s, isStr := t.(string)
		if kind != "phone" || !isStr || utf16Len(s) > maxPushToken {
			bad = true
		}
		push = &s
	}
	if bad {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_request"})
		return nil
	}
	token := b64(randomBytes(32))
	for attempt := 0; attempt < 5; attempt++ {
		d := Device{ID: newID(), Kind: kind, PublicKey: pk, PushToken: push}
		ok, err := r.db.InsertDevice(d, sha256B64(token), r.now())
		if err != nil {
			return err
		}
		if ok {
			writeJSON(w, http.StatusCreated, map[string]any{"id": d.ID, "token": token})
			return nil
		}
	}
	return errors.New("could not allocate a device id")
}

func (r *Relay) authHeader(req *http.Request) (*Device, error) {
	h := req.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil, nil
	}
	return r.db.DeviceByTokenHash(sha256B64(h[len("Bearer "):]))
}

func (r *Relay) clientIP(req *http.Request) string {
	if xff := req.Header.Get("X-Forwarded-For"); r.trust && xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		return host
	}
	return "?"
}

// --- WebSocket ---

// conn is one authenticated (or authenticating) WebSocket. All writes go through out, in
// order, from one writer goroutine; a peer that stops reading is dropped (maxBufferedBytes).
type conn struct {
	ws        *websocket.Conn
	out       chan frame
	buffered  atomic.Int64
	done      chan struct{}
	closeOnce sync.Once
	alive     atomic.Bool
}

type frame struct {
	data      []byte
	closeCode int
	reason    string
}

func (c *conn) terminate() {
	c.closeOnce.Do(func() {
		close(c.done)
		c.ws.Close()
	})
}

func (c *conn) closed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// send queues a JSON frame; false if the socket is gone or was dropped for falling behind.
func (c *conn) send(v any) bool {
	data, _ := json.Marshal(v)
	return c.enqueue(frame{data: data})
}

// closeWith sends a close frame after everything already queued, then drops the socket.
func (c *conn) closeWith(code int, reason string) {
	c.enqueue(frame{closeCode: code, reason: reason})
}

func (c *conn) enqueue(f frame) bool {
	if c.closed() {
		return false
	}
	if c.buffered.Add(int64(len(f.data))) > maxBufferedBytes {
		c.terminate() // stopped reading; later messages go to the bounded offline queue
		return false
	}
	select {
	case c.out <- f:
		return true
	default:
		c.terminate()
		return false
	}
}

func (c *conn) writeLoop() {
	ping := time.NewTicker(pingInterval)
	defer ping.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ping.C:
			if !c.alive.Swap(false) {
				c.terminate()
				return
			}
			_ = c.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeTimeout))
		case f := <-c.out:
			_ = c.ws.SetWriteDeadline(time.Now().Add(writeTimeout))
			if f.closeCode != 0 {
				_ = c.ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(f.closeCode, f.reason))
				c.terminate()
				return
			}
			err := c.ws.WriteMessage(websocket.TextMessage, f.data)
			c.buffered.Add(-int64(len(f.data)))
			if err != nil {
				c.terminate()
				return
			}
		}
	}
}

func (r *Relay) current(id string) *conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sockets[id]
}

type msgFrame struct {
	T      string `json:"t"`
	From   string `json:"from"`
	FromPk string `json:"fromPk"`
	Body   string `json:"body"`
	At     int64  `json:"at"`
}

type errFrame struct {
	T    string `json:"t"`
	Code string `json:"code"`
}

func errorFrame(code string) errFrame { return errFrame{T: "error", Code: code} }

func (r *Relay) serveWS(w http.ResponseWriter, req *http.Request) {
	ws, err := r.upgrader.Upgrade(w, req, nil)
	if err != nil {
		return // the upgrader already answered
	}
	c := &conn{ws: ws, out: make(chan frame, 256), done: make(chan struct{})}
	c.alive.Store(true)
	ws.SetReadLimit(maxFrame)
	ws.SetPongHandler(func(string) error { c.alive.Store(true); return nil })
	go c.writeLoop()

	var me *Device
	authTimer := time.AfterFunc(authTimeout, func() { c.closeWith(4002, "auth timeout") })
	defer func() {
		authTimer.Stop()
		c.terminate()
		if me != nil {
			r.mu.Lock()
			if r.sockets[me.ID] == c {
				delete(r.sockets, me.ID)
			}
			r.mu.Unlock()
		}
	}()

	for {
		kind, data, err := ws.ReadMessage()
		if err != nil {
			return // oversized frame, protocol error or closed
		}
		var f map[string]any
		if kind != websocket.TextMessage || json.Unmarshal(data, &f) != nil || f == nil {
			c.send(errorFrame("bad_request"))
			continue
		}
		if me == nil {
			if me, err = r.authenticate(c, f, authTimer); err != nil {
				r.log("ws auth: %v", err)
				return
			}
			continue
		}
		if err := r.onFrame(c, me, f); err != nil {
			r.log("ws: %v", err)
			return
		}
	}
}

// authenticate handles the first frame; nil device (and nil error) means auth failed.
func (r *Relay) authenticate(c *conn, f map[string]any, authTimer *time.Timer) (*Device, error) {
	var d *Device
	if token, ok := f["token"].(string); ok && f["t"] == "auth" {
		var err error
		if d, err = r.db.DeviceByTokenHash(sha256B64(token)); err != nil {
			return nil, err
		}
	}
	if d == nil {
		c.send(errorFrame("auth_failed"))
		c.closeWith(4003, "auth failed")
		return nil, nil
	}
	authTimer.Stop()
	r.mu.Lock()
	old := r.sockets[d.ID]
	r.sockets[d.ID] = c
	r.mu.Unlock()
	if old != nil {
		old.terminate() // not a close handshake: a closing socket could still send until it completes
	}
	if err := r.db.Touch(d.ID, r.now()); err != nil {
		return nil, err
	}
	c.send(map[string]string{"t": "ready", "id": d.ID})
	queued, err := r.db.Take(d.ID, r.now())
	if err != nil {
		return nil, err
	}
	for _, q := range queued {
		c.send(msgFrame{T: "msg", From: q.Sender, FromPk: q.SenderPk, Body: q.Body, At: q.At})
	}
	return d, nil
}

func (r *Relay) onFrame(c *conn, me *Device, f map[string]any) error {
	// A replaced or closing socket loses its authority immediately.
	if r.current(me.ID) != c || c.closed() {
		return nil
	}
	switch f["t"] {
	case "ping":
		c.send(map[string]string{"t": "pong"})
		return nil
	case "send":
	default:
		c.send(errorFrame("bad_request"))
		return nil
	}
	to, okTo := f["to"].(string)
	body, okBody := f["body"].(string)
	raw, okB64 := decodeB64(body)
	switch {
	case !okTo || !okBody || !okB64:
		c.send(errorFrame("bad_request"))
		return nil
	case len(raw) > maxBody:
		c.send(errorFrame("too_large"))
		return nil
	case !r.sendLimit.allow(me.ID, r.now()):
		c.send(errorFrame("rate_limited"))
		return nil
	}
	dest, err := r.db.DeviceByID(to)
	if err != nil {
		return err
	}
	// Re-check the sender still exists: it may have been deleted while connected.
	self, err := r.db.DeviceByID(me.ID)
	if err != nil {
		return err
	}
	if dest == nil || self == nil {
		c.send(errorFrame("unknown_device"))
		return nil
	}
	return r.deliver(dest, Queued{Sender: me.ID, SenderPk: me.PublicKey, Body: body, At: r.now()})
}

func (r *Relay) deliver(to *Device, m Queued) error {
	if sock := r.current(to.ID); sock != nil &&
		sock.send(msgFrame{T: "msg", From: m.Sender, FromPk: m.SenderPk, Body: m.Body, At: m.At}) {
		return nil
	}
	if err := r.db.Enqueue(to.ID, m, m.At+queueTTLMs, queueMax); err != nil {
		return err
	}
	if to.Kind != "phone" || to.PushToken == nil || r.push == nil {
		return nil
	}
	r.mu.Lock()
	if m.At-r.lastWake[to.ID] < wakeMinIntervalMs {
		r.mu.Unlock()
		return nil
	}
	r.lastWake[to.ID] = m.At
	r.mu.Unlock()
	token := *to.PushToken
	go func() {
		valid, err := r.push.Wake(token)
		if err != nil {
			r.log("wake failed for %s: %v", to.ID, err)
			return
		}
		if valid {
			return
		}
		// Forget the token, unless the phone sent a new one meanwhile.
		if d, err := r.db.DeviceByID(to.ID); err == nil && d != nil && d.PushToken != nil && *d.PushToken == token {
			if err := r.db.SetPushToken(to.ID, nil); err != nil {
				r.log("clear push token: %v", err)
			}
		}
	}()
	return nil
}

// --- helpers ---

// limiter is a fixed-window counter.
// shortcut: in-memory, lost on restart and per process; fine for one instance.
type limiter struct {
	mu       sync.Mutex
	max      int
	windowMs int64
	hits     map[string]*window
}

type window struct {
	n     int
	start int64
}

func newLimiter(max int, windowMs int64) *limiter {
	return &limiter{max: max, windowMs: windowMs, hits: map[string]*window{}}
}

func (l *limiter) allow(key string, now int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	h := l.hits[key]
	if h == nil || now-h.start >= l.windowMs {
		l.hits[key] = &window{n: 1, start: now}
		return true
	}
	h.n++
	return h.n <= l.max
}

func (l *limiter) sweep(now int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, h := range l.hits {
		if now-h.start >= l.windowMs {
			delete(l.hits, k)
		}
	}
}

func newID() string {
	n := new(big.Int).SetBytes(randomBytes(5))
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = idAlphabet[new(big.Int).And(n, big.NewInt(31)).Int64()]
		n.Rsh(n, 5)
	}
	return string(out[:4]) + "-" + string(out[4:])
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func sha256B64(s string) string {
	h := sha256.Sum256([]byte(s))
	return b64(h[:])
}

// decodeB64 accepts only standard padded base64 (Go's decoder alone also skips newlines).
func decodeB64(s string) ([]byte, bool) {
	if !b64Pattern.MatchString(s) {
		return nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	return raw, err == nil
}

func utf16Len(s string) int { return len(utf16.Encode([]rune(s))) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// readJSON returns the request's JSON object, or nil if it is too large or not an object.
func readJSON(w http.ResponseWriter, req *http.Request) map[string]any {
	raw, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxBody))
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}
