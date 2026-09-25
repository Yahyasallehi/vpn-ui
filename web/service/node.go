package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
)

// ErrNodeTwoFactorRequired is returned by PollNode when a node's admin account has 2FA
// enabled. v1 has no way to supply a TOTP code on every poll, so such a node cannot be
// onboarded; the caller should surface this as a clear, specific message rather than a
// generic auth failure.
var ErrNodeTwoFactorRequired = errors.New("node admin account requires 2FA, which the node poller cannot supply; disable 2FA on that account or use a dedicated non-2FA admin for node polling")

// NodeInboundSummary is the reduced shape the master keeps for one of a node's
// inbounds, built client-side from that node's own GET /panel/api/inbounds/list
// response. No new endpoint is added to the node for this - it is the same payload
// the node's own Inbounds page already consumes.
type NodeInboundSummary struct {
	Id          int    `json:"id"`
	Remark      string `json:"remark"`
	Protocol    string `json:"protocol"`
	Enable      bool   `json:"enable"`
	Port        int    `json:"port"`
	ClientCount int    `json:"clientCount"`
}

// remoteMsg mirrors the shape every vpn-ui panel API response takes (entity.Msg),
// decoded locally rather than importing web/entity, since this is the only field of
// it the poller needs.
type remoteMsg struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj"`
}

// nodeClients caches one *http.Client (with its own cookie jar) per node id, so a
// poll reuses a still-valid session cookie instead of logging in on every tick. This
// is a package-level cache, matching the existing xray.Process singleton pattern
// used elsewhere in this codebase for state that must outlive any single service
// value (NodeService itself, like the other *Service types, is a stateless value
// recreated freely by callers).
var (
	nodeClientsMu sync.Mutex
	nodeClients   = map[int]*http.Client{}
)

// NodeService manages the node registry (add/edit/remove/list) and polls each node's
// own, unmodified panel API for status and a reduced inbound summary. It never
// pushes configuration to a node and never touches that node's database, Xray
// process, or RADIUS server - see database/model.Node's doc comment for the full
// scope statement.
type NodeService struct{}

// ListNodes returns every registered node, most recently created first.
func (s *NodeService) ListNodes() ([]model.Node, error) {
	db := database.GetDB()
	var nodes []model.Node
	err := db.Order("id desc").Find(&nodes).Error
	return nodes, err
}

// ListEnabledNodes returns only the nodes the background poller should visit.
func (s *NodeService) ListEnabledNodes() ([]model.Node, error) {
	db := database.GetDB()
	var nodes []model.Node
	err := db.Where("enabled = ?", true).Find(&nodes).Error
	return nodes, err
}

// GetNode loads one node by id.
func (s *NodeService) GetNode(id int) (*model.Node, error) {
	db := database.GetDB()
	node := &model.Node{}
	err := db.Where("id = ?", id).First(node).Error
	if err != nil {
		return nil, err
	}
	return node, nil
}

// CreateNode encrypts plaintextPassword at rest and inserts the new node row.
func (s *NodeService) CreateNode(n *model.Node, plaintextPassword string) error {
	encrypted, err := s.encryptPassword(plaintextPassword)
	if err != nil {
		return err
	}
	n.EncryptedPassword = encrypted
	db := database.GetDB()
	return db.Create(n).Error
}

// UpdateNode updates name/base URL/username/enabled unconditionally. plaintextPassword
// re-encrypts and replaces the stored credential only when non-empty; a blank value
// means "keep the current password", matching the admin-password edit convention
// used elsewhere in this panel.
func (s *NodeService) UpdateNode(id int, name, baseURL, username, plaintextPassword string, enabled bool) error {
	db := database.GetDB()
	updates := map[string]any{
		"name":     name,
		"base_url": baseURL,
		"username": username,
		"enabled":  enabled,
	}
	if plaintextPassword != "" {
		encrypted, err := s.encryptPassword(plaintextPassword)
		if err != nil {
			return err
		}
		updates["encrypted_password"] = encrypted
	}
	return db.Model(&model.Node{}).Where("id = ?", id).Updates(updates).Error
}

// DeleteNode removes a node from the registry and drops its cached HTTP client, if any.
func (s *NodeService) DeleteNode(id int) error {
	db := database.GetDB()
	if err := db.Where("id = ?", id).Delete(&model.Node{}).Error; err != nil {
		return err
	}
	nodeClientsMu.Lock()
	delete(nodeClients, id)
	nodeClientsMu.Unlock()
	return nil
}

// encryptPassword derives the AES key from this panel's own session secret, so no
// second secret needs to be generated or stored for node credentials.
func (s *NodeService) encryptPassword(plaintext string) (string, error) {
	var settingService SettingService
	secret, err := settingService.GetSecret()
	if err != nil {
		return "", fmt.Errorf("reading panel secret: %w", err)
	}
	return crypto.EncryptString(plaintext, secret)
}

func (s *NodeService) decryptPassword(n *model.Node) (string, error) {
	var settingService SettingService
	secret, err := settingService.GetSecret()
	if err != nil {
		return "", fmt.Errorf("reading panel secret: %w", err)
	}
	return crypto.DecryptString(n.EncryptedPassword, secret)
}

// clientFor returns the cached *http.Client for a node, creating one (with its own
// cookie jar) on first use.
func clientFor(nodeId int) *http.Client {
	nodeClientsMu.Lock()
	defer nodeClientsMu.Unlock()
	c, ok := nodeClients[nodeId]
	if !ok {
		jar, _ := cookiejar.New(nil)
		c = &http.Client{
			Jar: jar,
			// A handful of seconds: this is a foreground-adjacent check (the operator
			// is looking at the Nodes page, or a 30s-tick background poll), not a
			// long-running transfer. TLS verification is left at the default
			// transport - it stays ON, deliberately not using the SSRF-blocking
			// transport custom_geo.go uses elsewhere, since a node's BaseURL is
			// entered by the super admin themselves and may legitimately be a
			// private/VPN-only address.
			Timeout: 8 * time.Second,
		}
		nodeClients[nodeId] = c
	}
	return c
}

// loginToNode POSTs the node's own /login endpoint with its stored credentials,
// exactly as that node's own browser session would. On success the client's cookie
// jar holds a valid session cookie for subsequent calls.
func (s *NodeService) loginToNode(n *model.Node, client *http.Client) error {
	password, err := s.decryptPassword(n)
	if err != nil {
		return fmt.Errorf("decrypting stored credential: %w", err)
	}
	form := url.Values{}
	form.Set("username", n.Username)
	form.Set("password", password)

	loginURL := strings.TrimRight(n.BaseURL, "/") + "/login"
	resp, err := client.PostForm(loginURL, form)
	if err != nil {
		return fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading login response: %w", err)
	}
	var msg remoteMsg
	if err := json.Unmarshal(body, &msg); err != nil {
		return fmt.Errorf("unexpected login response (status %d)", resp.StatusCode)
	}
	if !msg.Success {
		var obj struct {
			TwoFactorRequired bool `json:"twoFactorRequired"`
		}
		_ = json.Unmarshal(msg.Obj, &obj)
		if obj.TwoFactorRequired {
			return ErrNodeTwoFactorRequired
		}
		return fmt.Errorf("login rejected: %s", msg.Msg)
	}
	return nil
}

// callNodeAPI GETs or POSTs (form-encoded, when form is non-nil) a
// {baseURL}/panel/api/... path, logging in first if the session looks unauthenticated.
// It retries the call exactly once after a fresh login, never more: a node that is
// wrong twice in a row is left for the next poll tick rather than hammered.
func (s *NodeService) callNodeAPI(n *model.Node, method, path string, form url.Values) (*remoteMsg, error) {
	client := clientFor(n.Id)
	apiURL := strings.TrimRight(n.BaseURL, "/") + path

	doOnce := func() (*remoteMsg, int, error) {
		var resp *http.Response
		var err error
		if method == http.MethodPost {
			resp, err = client.PostForm(apiURL, form)
		} else {
			resp, err = client.Get(apiURL)
		}
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, resp.StatusCode, err
		}
		if resp.StatusCode == http.StatusNotFound {
			// The panel's own checkAPIAuth 404s an unauthenticated request rather
			// than 401ing it, to hide endpoint existence - so a stale/missing
			// session shows up here, not as a 401.
			return nil, resp.StatusCode, nil
		}
		var msg remoteMsg
		if err := json.Unmarshal(body, &msg); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("unexpected response (status %d)", resp.StatusCode)
		}
		return &msg, resp.StatusCode, nil
	}

	msg, status, err := doOnce()
	if err != nil {
		return nil, err
	}
	if msg == nil && status == http.StatusNotFound {
		if err := s.loginToNode(n, client); err != nil {
			return nil, err
		}
		msg, _, err = doOnce()
		if err != nil {
			return nil, err
		}
		if msg == nil {
			return nil, errors.New("still unauthenticated after login")
		}
	}
	return msg, nil
}

// PollNode fetches the node's own server status and a reduced inbound summary, and
// persists the result (or the failure) onto the Node row. It never returns a
// "partial" success: either both calls land and LastError is cleared, or the first
// failure is recorded and the rest of the tick is skipped for this node.
func (s *NodeService) PollNode(n *model.Node) error {
	now := time.Now().UnixMilli()
	db := database.GetDB()

	statusMsg, err := s.callNodeAPI(n, http.MethodGet, "/panel/api/server/status", nil)
	if err != nil {
		db.Model(&model.Node{}).Where("id = ?", n.Id).Updates(map[string]any{
			"last_error": err.Error(),
		})
		return err
	}
	if !statusMsg.Success {
		err := fmt.Errorf("status request rejected: %s", statusMsg.Msg)
		db.Model(&model.Node{}).Where("id = ?", n.Id).Updates(map[string]any{
			"last_error": err.Error(),
		})
		return err
	}

	inboundsMsg, err := s.callNodeAPI(n, http.MethodGet, "/panel/api/inbounds/list", nil)
	if err != nil {
		db.Model(&model.Node{}).Where("id = ?", n.Id).Updates(map[string]any{
			"last_error": err.Error(),
		})
		return err
	}
	var summaries []NodeInboundSummary
	if inboundsMsg.Success {
		var inbounds []model.Inbound
		if err := json.Unmarshal(inboundsMsg.Obj, &inbounds); err == nil {
			summaries = make([]NodeInboundSummary, 0, len(inbounds))
			for _, ib := range inbounds {
				summaries = append(summaries, NodeInboundSummary{
					Id:          ib.Id,
					Remark:      ib.Remark,
					Protocol:    string(ib.Protocol),
					Enable:      ib.Enable,
					Port:        ib.Port,
					ClientCount: len(ib.ClientStats),
				})
			}
		}
	}

	statusJSON, _ := json.Marshal(statusMsg.Obj)
	inboundsJSON, _ := json.Marshal(summaries)

	return db.Model(&model.Node{}).Where("id = ?", n.Id).Updates(map[string]any{
		"last_seen_at":  now,
		"last_status":   string(statusJSON),
		"last_inbounds": string(inboundsJSON),
		"last_error":    "",
	}).Error
}

// RestartRemoteXray proxies the one write action v1 allows: restarting Xray on a
// node, via that node's own existing endpoint.
func (s *NodeService) RestartRemoteXray(n *model.Node) error {
	msg, err := s.callNodeAPI(n, http.MethodPost, "/panel/api/server/restartXrayService", url.Values{})
	if err != nil {
		return err
	}
	if !msg.Success {
		return fmt.Errorf("restart rejected: %s", msg.Msg)
	}
	logger.Infof("node %d: restarted remote Xray", n.Id)
	return nil
}
