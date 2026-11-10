package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type fakePush struct {
	mu    sync.Mutex
	wakes []string
}

func (p *fakePush) Wake(token string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.wakes = append(p.wakes, token)
	return token != "dead-token", nil
}

func (p *fakePush) got() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.wakes...)
}

type env struct {
	t     *testing.T
	db    *DB
	push  *fakePush
	relay *Relay
	srv   *httptest.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	push := &fakePush{}
	relay := NewRelay(Options{DB: db, Push: push})
	srv := httptest.NewServer(relay)
	t.Cleanup(func() {
		relay.Close()
		srv.Close()
		db.Close()
	})
	return &env{t: t, db: db, push: push, relay: relay, srv: srv}
}

var idRE = regexp.MustCompile(`^[0-9a-hjkmnp-tv-z]{4}-[0-9a-hjkmnp-tv-z]{4}$`)

type registered struct{ id, token, publicKey string }

func (e *env) register(kind string, pushToken *string) registered {
	e.t.Helper()
	body := map[string]any{"publicKey": b64(randomBytes(32)), "kind": kind}
	if pushToken != nil {
		body["pushToken"] = *pushToken
	}
	res, out := e.do(http.MethodPost, "/v1/devices", "", body)
	if res != http.StatusCreated {
		e.t.Fatalf("register: %d %v", res, out)
	}
	id, _ := out["id"].(string)
	if !idRE.MatchString(id) {
		e.t.Fatalf("bad id %q", id)
	}
	return registered{id: id, token: out["token"].(string), publicKey: body["publicKey"].(string)}
}

func (e *env) do(method, path, token string, body any) (int, map[string]any) {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// client is a WebSocket that buffers frames so tests can read them in order.
type client struct {
	t      *testing.T
	ws     *websocket.Conn
	frames chan map[string]any
	closed chan int // close code
}

func (e *env) connect(token string) *client {
	e.t.Helper()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(e.srv.URL, "http")+"/v1/ws", nil)
	if err != nil {
		e.t.Fatal(err)
	}
	c := &client{t: e.t, ws: ws, frames: make(chan map[string]any, 256), closed: make(chan int, 1)}
	go func() {
		for {
			_, data, err := ws.ReadMessage()
			if err != nil {
				code := -1
				if ce, ok := err.(*websocket.CloseError); ok {
					code = ce.Code
				}
				c.closed <- code
				return
			}
			var f map[string]any
			_ = json.Unmarshal(data, &f)
			c.frames <- f
		}
	}()
	c.send(map[string]any{"t": "auth", "token": token})
	return c
}

func (c *client) send(v any) {
	c.t.Helper()
	if err := c.ws.WriteJSON(v); err != nil {
		c.t.Fatal(err)
	}
}

func (c *client) next() map[string]any {
	c.t.Helper()
	select {
	case f := <-c.frames:
		return f
	case <-time.After(2 * time.Second):
		c.t.Fatal("timeout waiting for frame")
		return nil
	}
}

func (c *client) expectNone(d time.Duration) {
	c.t.Helper()
	select {
	case f := <-c.frames:
		c.t.Fatalf("unexpected frame %v", f)
	case <-time.After(d):
	}
}

func (c *client) expect(want map[string]any) {
	c.t.Helper()
	if got := c.next(); !reflect.DeepEqual(got, want) {
		c.t.Fatalf("got %v, want %v", got, want)
	}
}

func ptr(s string) *string { return &s }

func zeros(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }

func TestRoutingQueueWakeAndPing(t *testing.T) {
	e := newEnv(t)
	phone := e.register("phone", ptr("push-1"))
	ext := e.register("ext", nil)
	p := e.connect(phone.token)
	p.expect(map[string]any{"t": "ready", "id": phone.id})
	x := e.connect(ext.token)
	if x.next()["t"] != "ready" {
		t.Fatal("ext not ready")
	}

	// The extension looks the phone up by its handle.
	code, info := e.do(http.MethodGet, "/v1/devices/"+phone.id, "", nil)
	if code != 200 || info["kind"] != "phone" || info["publicKey"] != phone.publicKey {
		t.Fatalf("lookup: %d %v", code, info)
	}

	// Both directions, with the sender's id and key attached.
	x.send(map[string]any{"t": "send", "to": phone.id, "body": "AAAA"})
	f := p.next()
	if f["t"] != "msg" || f["from"] != ext.id || f["fromPk"] != ext.publicKey || f["body"] != "AAAA" {
		t.Fatalf("delivered: %v", f)
	}
	p.send(map[string]any{"t": "send", "to": ext.id, "body": "BBBB"})
	if f := x.next(); f["from"] != phone.id || f["body"] != "BBBB" {
		t.Fatalf("reply: %v", f)
	}

	// Phone offline: the message is queued, the phone woken, and delivered on reconnect.
	p.ws.Close()
	time.Sleep(50 * time.Millisecond)
	x.send(map[string]any{"t": "send", "to": phone.id, "body": zeros(64)})
	time.Sleep(50 * time.Millisecond)
	if got := e.push.got(); !reflect.DeepEqual(got, []string{"push-1"}) {
		t.Fatalf("wakes: %v", got)
	}
	p2 := e.connect(phone.token)
	if p2.next()["t"] != "ready" {
		t.Fatal("not ready")
	}
	if q := p2.next(); q["t"] != "msg" || q["from"] != ext.id {
		t.Fatalf("queued: %v", q)
	}

	// Queued messages are delivered once.
	p2.ws.Close()
	p3 := e.connect(phone.token)
	if p3.next()["t"] != "ready" {
		t.Fatal("not ready")
	}
	p3.send(map[string]any{"t": "ping"})
	p3.expect(map[string]any{"t": "pong"})
}

func TestAuthFailuresAndLimits(t *testing.T) {
	e := newEnv(t)
	bad := e.connect("nope")
	bad.expect(map[string]any{"t": "error", "code": "auth_failed"})
	if code := <-bad.closed; code != 4003 {
		t.Fatalf("close code %d", code)
	}

	ext := e.register("ext", nil)
	x := e.connect(ext.token)
	x.next()
	x.send(map[string]any{"t": "send", "to": "zzzz-zzzz", "body": "AAAA"})
	x.expect(map[string]any{"t": "error", "code": "unknown_device"})
	x.send(map[string]any{"t": "send", "to": ext.id, "body": "not base64!"})
	x.expect(map[string]any{"t": "error", "code": "bad_request"})
	x.send(map[string]any{"t": "send", "to": ext.id, "body": "AA\nAA"})
	x.expect(map[string]any{"t": "error", "code": "bad_request"})
	x.send(map[string]any{"t": "send", "to": ext.id, "body": zeros(8*1024 + 3)})
	x.expect(map[string]any{"t": "error", "code": "too_large"})

	// An extension can't set a push token; a phone with a dead token gets it cleared.
	if code, _ := e.do(http.MethodPut, "/v1/devices/me", ext.token, map[string]any{"pushToken": "x"}); code != 400 {
		t.Fatalf("ext PUT: %d", code)
	}
	if code, _ := e.do(http.MethodPost, "/v1/devices", "", map[string]any{"publicKey": zeros(32), "kind": "ext", "pushToken": "x"}); code != 400 {
		t.Fatalf("ext register with push: %d", code)
	}
	if code, _ := e.do(http.MethodPut, "/v1/devices/me", "", map[string]any{"pushToken": "x"}); code != 401 {
		t.Fatalf("PUT without auth: %d", code)
	}
	phone := e.register("phone", ptr("dead-token"))
	x.send(map[string]any{"t": "send", "to": phone.id, "body": "AAAA"})
	time.Sleep(100 * time.Millisecond)
	if d, _ := e.db.DeviceByID(phone.id); d.PushToken != nil {
		t.Fatalf("dead token kept: %v", *d.PushToken)
	}
	if code, _ := e.do(http.MethodPut, "/v1/devices/me", phone.token, map[string]any{"pushToken": "fresh"}); code != 204 {
		t.Fatalf("phone PUT: %d", code)
	}
	if d, _ := e.db.DeviceByID(phone.id); d.PushToken == nil || *d.PushToken != "fresh" {
		t.Fatal("push token not stored")
	}

	// Self-messages: rate limit at 60/min. Counted so far: unknown_device + the send to the phone.
	for i := 0; i < 58; i++ {
		x.send(map[string]any{"t": "send", "to": ext.id, "body": "AAAA"})
	}
	for i := 0; i < 58; i++ {
		if f := x.next(); f["t"] != "msg" {
			t.Fatalf("frame %d: %v", i, f)
		}
	}
	x.send(map[string]any{"t": "send", "to": ext.id, "body": "AAAA"})
	x.expect(map[string]any{"t": "error", "code": "rate_limited"})

	// Delete: socket closed with 4001, device gone.
	if code, _ := e.do(http.MethodDelete, "/v1/devices/me", ext.token, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code := <-x.closed; code != 4001 {
		t.Fatalf("close code %d", code)
	}
	if code, _ := e.do(http.MethodGet, "/v1/devices/"+ext.id, "", nil); code != 404 {
		t.Fatalf("lookup after delete: %d", code)
	}
}

func TestRegistrationValidation(t *testing.T) {
	e := newEnv(t)
	for _, body := range []any{
		map[string]any{"publicKey": zeros(31), "kind": "ext"},
		map[string]any{"publicKey": zeros(32), "kind": "pc"},
		map[string]any{"publicKey": zeros(32), "kind": "phone", "pushToken": nil},
		map[string]any{"publicKey": zeros(32), "kind": "phone", "pushToken": strings.Repeat("x", 4097)},
		[]any{1, 2},
	} {
		if code, _ := e.do(http.MethodPost, "/v1/devices", "", body); code != 400 {
			t.Fatalf("%v: %d", body, code)
		}
	}
	// 10 registrations per IP per hour; the 5 rejected above count too.
	for i := 0; i < 5; i++ {
		e.register("ext", nil)
	}
	if code, out := e.do(http.MethodPost, "/v1/devices", "", map[string]any{"publicKey": zeros(32), "kind": "ext"}); code != 429 {
		t.Fatalf("rate limit: %d %v", code, out)
	}
}

func TestQueueKeepsNewest20AndDropsExpired(t *testing.T) {
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < 25; i++ {
		if err := db.Enqueue("a", Queued{Sender: "b", SenderPk: "k", Body: string(rune('A' + i)), At: int64(i)}, 1000, 20); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Enqueue("a", Queued{Sender: "b", SenderPk: "k", Body: "old", At: 0}, 5, 20)
	got, _ := db.Take("a", 100)
	var bodies []string
	for _, q := range got {
		bodies = append(bodies, q.Body)
	}
	var want []string
	for i := 6; i < 25; i++ {
		want = append(want, string(rune('A'+i)))
	}
	if !reflect.DeepEqual(bodies, want) {
		t.Fatalf("got %v, want %v", bodies, want)
	}
	if again, _ := db.Take("a", 100); len(again) != 0 {
		t.Fatalf("taken twice: %v", again)
	}
}

func TestHostileInputDoesntTakeRelayDown(t *testing.T) {
	e := newEnv(t)
	// Oversized frame before auth.
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(e.srv.URL, "http")+"/v1/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = ws.WriteMessage(websocket.TextMessage, bytes.Repeat([]byte("x"), 16*1024+1))
	_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := ws.ReadMessage(); err == nil {
		t.Fatal("oversized frame not rejected")
	}
	ws.Close()

	// Upgrade request with an unparsable target.
	conn, err := net.Dial("tcp", strings.TrimPrefix(e.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("GET http://[ HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Read(make([]byte, 512))
	conn.Close()

	if code, _ := e.do(http.MethodGet, "/healthz", "", nil); code != 200 {
		t.Fatalf("healthz: %d", code)
	}
}

func TestBodyLimitIsExactAndReplacedSocketCantSend(t *testing.T) {
	e := newEnv(t)
	a := e.register("ext", nil)
	b := e.register("ext", nil)
	first := e.connect(a.token)
	first.next()
	first.send(map[string]any{"t": "send", "to": b.id, "body": zeros(8 * 1024)})
	first.send(map[string]any{"t": "send", "to": b.id, "body": zeros(8*1024 + 1)})
	first.expect(map[string]any{"t": "error", "code": "too_large"})

	second := e.connect(a.token)
	second.next()
	_ = first.ws.WriteJSON(map[string]any{"t": "send", "to": b.id, "body": "AAAA"}) // may race the termination; must be dropped
	<-first.closed

	rb := e.connect(b.token)
	if rb.next()["t"] != "ready" {
		t.Fatal("not ready")
	}
	delivered := rb.next()
	raw, _ := base64.StdEncoding.DecodeString(delivered["body"].(string))
	if len(raw) != 8*1024 {
		t.Fatalf("delivered %d bytes", len(raw))
	}
	rb.expectNone(300 * time.Millisecond) // only the in-limit body
}

func TestWakeMessage(t *testing.T) {
	m := WakeMessage("tok", 1_000_000)["message"].(map[string]any)
	if !reflect.DeepEqual(m["data"], map[string]string{"t": "wake"}) {
		t.Fatalf("data: %v", m["data"])
	}
	if m["android"].(map[string]string)["priority"] != "HIGH" {
		t.Fatal("android priority")
	}
	apns := m["apns"].(map[string]any)
	h := apns["headers"].(map[string]string)
	if h["apns-expiration"] != "1120" || h["apns-push-type"] != "alert" {
		t.Fatalf("apns headers: %v", h)
	}
	// Fixed text: no item, site or PC name ever goes to Google or Apple.
	body := func(m map[string]any) string {
		return m["message"].(map[string]any)["apns"].(map[string]any)["payload"].(map[string]any)["aps"].(map[string]any)["alert"].(map[string]string)["body"]
	}
	if body(WakeMessage("tok", 1)) != body(WakeMessage("other", 0)) {
		t.Fatal("alert text varies")
	}
}
