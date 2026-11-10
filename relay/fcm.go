package main

// FCM HTTP v1 wake-ups. Sends only {"t":"wake"} and a fixed iOS alert; never message content.

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Push wakes a phone. Wake returns false when the token is no longer valid and should be forgotten.
type Push interface {
	Wake(pushToken string) (bool, error)
}

const (
	fcmScope    = "https://www.googleapis.com/auth/firebase.messaging"
	fcmTokenURL = "https://oauth2.googleapis.com/token"
)

// WakeMessage is one FCM message for both platforms. Android gets a data-only high-priority
// message the app handles itself. iOS throttles and drops silent pushes, so iPhones get a
// visible alert with fixed text; tapping it opens the app, which then fetches the queued
// request from the relay.
func WakeMessage(pushToken string, nowMs int64) map[string]any {
	return map[string]any{
		"message": map[string]any{
			"token":   pushToken,
			"data":    map[string]string{"t": "wake"},
			"android": map[string]string{"priority": "HIGH", "ttl": "120s"},
			"apns": map[string]any{
				"headers": map[string]string{
					"apns-priority":  "10",
					"apns-push-type": "alert",
					// The relay keeps the request 120 s; a later alert would open the app for nothing.
					"apns-expiration": strconv.FormatInt(nowMs/1000+120, 10),
				},
				"payload": map[string]any{
					"aps": map[string]any{
						"alert": map[string]string{
							"title": "PushWarden",
							"body":  "A computer is asking to fill a password. Open PushWarden to approve.",
						},
						"sound": "default",
					},
				},
			},
		},
	}
}

type serviceAccount struct {
	ProjectID   string `json:"project_id"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
}

type fcm struct {
	sa      serviceAccount
	key     *rsa.PrivateKey
	client  *http.Client
	mu      sync.Mutex
	token   string
	expires time.Time
}

// FCMFromServiceAccountFile reads a Google service account JSON key.
func FCMFromServiceAccountFile(path string) (Push, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sa serviceAccount
	if err := json.Unmarshal(raw, &sa); err != nil {
		return nil, fmt.Errorf("service account: %w", err)
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, errors.New("service account: no PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("service account key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("service account key is not RSA")
	}
	return &fcm{sa: sa, key: rk, client: &http.Client{Timeout: 15 * time.Second}}, nil
}

func (f *fcm) accessToken() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if f.token != "" && now.Add(time.Minute).Before(f.expires) {
		return f.token, nil
	}
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	unsigned := enc(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." + enc(map[string]any{
		"iss": f.sa.ClientEmail, "scope": fcmScope, "aud": fcmTokenURL,
		"iat": now.Unix(), "exp": now.Unix() + 3600,
	})
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	res, err := f.client.PostForm(fcmTokenURL, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)},
	})
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("FCM auth failed: %d", res.StatusCode)
	}
	var j struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(res.Body).Decode(&j); err != nil {
		return "", err
	}
	f.token, f.expires = j.AccessToken, now.Add(time.Duration(j.ExpiresIn)*time.Second)
	return f.token, nil
}

func (f *fcm) Wake(pushToken string) (bool, error) {
	token, err := f.accessToken()
	if err != nil {
		return true, err
	}
	body, _ := json.Marshal(WakeMessage(pushToken, time.Now().UnixMilli()))
	req, _ := http.NewRequest(http.MethodPost,
		"https://fcm.googleapis.com/v1/projects/"+f.sa.ProjectID+"/messages:send", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := f.client.Do(req)
	if err != nil {
		return true, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		return true, nil
	}
	text, _ := io.ReadAll(io.LimitReader(res.Body, 64*1024))
	// 404/UNREGISTERED: app uninstalled; 400 about the token: it was never valid.
	if res.StatusCode == http.StatusNotFound || bytes.Contains(text, []byte("UNREGISTERED")) {
		return false, nil
	}
	if res.StatusCode == http.StatusBadRequest && strings.Contains(string(text), "registration token") {
		return false, nil
	}
	return true, fmt.Errorf("FCM send failed: %d", res.StatusCode)
}
