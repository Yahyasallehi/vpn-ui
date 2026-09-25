package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func newNodeTestDB(t *testing.T) *NodeService {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	// Each test gets a fresh DB, so GORM's autoincrement restarts at 1 - meaning two
	// tests can each mint a node with the same id. Without this, the SECOND test
	// would reuse the FIRST test's cached *http.Client (and its still-valid session
	// cookie) for that id, silently skipping the login this test means to exercise.
	// Production has no equivalent problem: a real installation's node ids are
	// stable for the life of the process.
	nodeClientsMu.Lock()
	nodeClients = map[int]*http.Client{}
	nodeClientsMu.Unlock()
	return &NodeService{}
}

func TestCreateUpdateDeleteNodeRoundTrip(t *testing.T) {
	s := newNodeTestDB(t)

	n := &model.Node{Name: "node-1", BaseURL: "https://node1.example.com", Username: "admin"}
	if err := s.CreateNode(n, "correct horse"); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if n.EncryptedPassword == "" || n.EncryptedPassword == "correct horse" {
		t.Fatalf("expected the password to be encrypted at rest, got %q", n.EncryptedPassword)
	}

	got, err := s.GetNode(n.Id)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	password, err := s.decryptPassword(got)
	if err != nil {
		t.Fatalf("decryptPassword: %v", err)
	}
	if password != "correct horse" {
		t.Fatalf("round-trip mismatch: got %q", password)
	}

	// Blank password on update means "keep the current one".
	if err := s.UpdateNode(n.Id, "node-1-renamed", got.BaseURL, got.Username, "", true); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	got2, err := s.GetNode(n.Id)
	if err != nil {
		t.Fatalf("GetNode after update: %v", err)
	}
	if got2.Name != "node-1-renamed" {
		t.Fatalf("expected name to update, got %q", got2.Name)
	}
	password2, err := s.decryptPassword(got2)
	if err != nil {
		t.Fatalf("decryptPassword after update: %v", err)
	}
	if password2 != "correct horse" {
		t.Fatalf("expected password to be unchanged, got %q", password2)
	}

	if err := s.DeleteNode(n.Id); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if _, err := s.GetNode(n.Id); err == nil {
		t.Fatalf("expected GetNode to fail after delete")
	}
}

// fakeNode stands in for a real vpn-ui node's HTTP surface: /login,
// /panel/api/server/status, /panel/api/inbounds/list, and
// /panel/api/server/restartXrayService, matching the shape those endpoints actually
// return on a live panel.
type fakeNode struct {
	loginOK           bool
	twoFactorRequired bool
	restartCalled     bool
}

func (f *fakeNode) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			if !f.loginOK {
				obj := map[string]any{}
				if f.twoFactorRequired {
					obj["twoFactorRequired"] = true
				}
				json.NewEncoder(w).Encode(remoteMsg{Success: false, Msg: "no", Obj: mustJSON(obj)})
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "vpn-ui", Value: "sess"})
			json.NewEncoder(w).Encode(remoteMsg{Success: true})
		case "/panel/api/server/status":
			if !hasSessionCookie(r) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			status := Status{Cpu: 12.5, Hostname: "node1"}
			json.NewEncoder(w).Encode(remoteMsg{Success: true, Obj: mustJSON(status)})
		case "/panel/api/inbounds/list":
			if !hasSessionCookie(r) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			inbounds := []model.Inbound{{Id: 1, Remark: "vless-in", Enable: true, Port: 443}}
			json.NewEncoder(w).Encode(remoteMsg{Success: true, Obj: mustJSON(inbounds)})
		case "/panel/api/server/restartXrayService":
			if !hasSessionCookie(r) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			f.restartCalled = true
			json.NewEncoder(w).Encode(remoteMsg{Success: true})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func hasSessionCookie(r *http.Request) bool {
	_, err := r.Cookie("vpn-ui")
	return err == nil
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func newTestNode(t *testing.T, s *NodeService, baseURL string) *model.Node {
	t.Helper()
	n := &model.Node{Name: "test-node", BaseURL: baseURL, Username: "admin", Enabled: true}
	if err := s.CreateNode(n, "test-password"); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	return n
}

func TestPollNodeSuccessPopulatesCache(t *testing.T) {
	s := newNodeTestDB(t)
	fn := &fakeNode{loginOK: true}
	srv := httptest.NewServer(fn.handler())
	defer srv.Close()

	n := newTestNode(t, s, srv.URL)
	if err := s.PollNode(n); err != nil {
		t.Fatalf("PollNode: %v", err)
	}

	got, err := s.GetNode(n.Id)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.LastError != "" {
		t.Fatalf("expected no LastError, got %q", got.LastError)
	}
	if got.LastSeenAt == 0 {
		t.Fatalf("expected LastSeenAt to be set")
	}
	var status Status
	if err := json.Unmarshal([]byte(got.LastStatus), &status); err != nil {
		t.Fatalf("LastStatus is not valid JSON: %v", err)
	}
	if status.Hostname != "node1" {
		t.Fatalf("expected cached status to carry the node's hostname, got %q", status.Hostname)
	}
	var summaries []NodeInboundSummary
	if err := json.Unmarshal([]byte(got.LastInbounds), &summaries); err != nil {
		t.Fatalf("LastInbounds is not valid JSON: %v", err)
	}
	if len(summaries) != 1 || summaries[0].Remark != "vless-in" {
		t.Fatalf("unexpected inbound summary: %+v", summaries)
	}
}

func TestPollNodeWrongCredentialsRecordsError(t *testing.T) {
	s := newNodeTestDB(t)
	fn := &fakeNode{loginOK: false}
	srv := httptest.NewServer(fn.handler())
	defer srv.Close()

	n := newTestNode(t, s, srv.URL)
	if err := s.PollNode(n); err == nil {
		t.Fatalf("expected PollNode to fail with wrong credentials")
	}

	got, err := s.GetNode(n.Id)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.LastError == "" {
		t.Fatalf("expected LastError to be recorded")
	}
}

func TestPollNodeTwoFactorRequiredIsDistinguishable(t *testing.T) {
	s := newNodeTestDB(t)
	fn := &fakeNode{loginOK: false, twoFactorRequired: true}
	srv := httptest.NewServer(fn.handler())
	defer srv.Close()

	n := newTestNode(t, s, srv.URL)
	err := s.PollNode(n)
	if err == nil {
		t.Fatalf("expected PollNode to fail for a 2FA-enabled node")
	}
	if err != ErrNodeTwoFactorRequired {
		t.Fatalf("expected ErrNodeTwoFactorRequired, got %v", err)
	}
}

func TestPollNodeUnreachableRecordsError(t *testing.T) {
	s := newNodeTestDB(t)
	// A URL with nothing listening: connection refused.
	n := newTestNode(t, s, "http://127.0.0.1:1")
	if err := s.PollNode(n); err == nil {
		t.Fatalf("expected PollNode to fail for an unreachable node")
	}
	got, err := s.GetNode(n.Id)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.LastError == "" {
		t.Fatalf("expected LastError to be recorded for an unreachable node")
	}
}

func TestRestartRemoteXrayCallsNodeEndpoint(t *testing.T) {
	s := newNodeTestDB(t)
	fn := &fakeNode{loginOK: true}
	srv := httptest.NewServer(fn.handler())
	defer srv.Close()

	n := newTestNode(t, s, srv.URL)
	if err := s.RestartRemoteXray(n); err != nil {
		t.Fatalf("RestartRemoteXray: %v", err)
	}
	if !fn.restartCalled {
		t.Fatalf("expected the node's restartXrayService endpoint to be called")
	}
}
