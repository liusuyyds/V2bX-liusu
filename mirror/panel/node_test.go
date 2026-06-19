package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/qingsu/atlas/paper"
)

func newTestClient(t *testing.T, server *httptest.Server, nodeType string) *Client {
	t.Helper()
	client, err := New(&conf.ApiConfig{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeType: nodeType,
		NodeID:   19,
	})
	if err != nil {
		t.Fatalf("New client: %v", err)
	}
	return client
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

func TestClientGetNodeInfoParsesExtendedFields(t *testing.T) {
	var gotQuery map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/config" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		gotQuery = map[string]string{
			"node_type": r.URL.Query().Get("node_type"),
			"node_id":   r.URL.Query().Get("node_id"),
			"token":     r.URL.Query().Get("token"),
		}
		w.Header().Set("ETag", "node-etag")
		writeJSON(t, w, map[string]any{
			"server_port": 443,
			"base_config": map[string]any{
				"push_interval": 7,
				"pull_interval": "11",
			},
			"routes":           []any{},
			"tls":              1,
			"network":          "h2",
			"network_settings": map[string]any{"host": []string{"h2.example.com"}, "path": "/h2"},
			"decryption":       "mlkem768x25519plus.native.ticket.padding.private-key",
			"tls_settings": map[string]any{
				"server_name": "node.example.com",
				"alpn":        []string{"h2", "http/1.1"},
				"ech": map[string]any{
					"enabled": true,
					"key":     "ech-key",
					"config":  "ech-config",
				},
			},
			"multiplex": map[string]any{
				"enabled": true,
				"padding": true,
				"brutal":  map[string]any{"enabled": true, "up_mbps": 100, "down_mbps": 200},
			},
		})
	}))
	defer server.Close()

	client := newTestClient(t, server, "vless")
	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node == nil {
		t.Fatal("expected node info, got nil")
	}
	if gotQuery["node_type"] != "vless" || gotQuery["node_id"] != "19" || gotQuery["token"] != "test-token" {
		t.Fatalf("unexpected query params: %#v", gotQuery)
	}
	if node.Type != "vless" || node.Security != Tls || node.Common.ServerPort != 443 {
		t.Fatalf("unexpected node basics: type=%s security=%d port=%d", node.Type, node.Security, node.Common.ServerPort)
	}
	if node.VAllss.Network != "h2" || node.VAllss.Decryption == "" {
		t.Fatalf("expected h2 network and decryption, got network=%q decryption=%q", node.VAllss.Network, node.VAllss.Decryption)
	}
	if !reflect.DeepEqual([]string(node.VAllss.TlsSettings.ALPN), []string{"h2", "http/1.1"}) {
		t.Fatalf("unexpected alpn: %#v", node.VAllss.TlsSettings.ALPN)
	}
	if !node.VAllss.TlsSettings.ECH.Enabled || node.VAllss.TlsSettings.ECH.Key != "ech-key" {
		t.Fatalf("unexpected ech settings: %#v", node.VAllss.TlsSettings.ECH)
	}
	if node.Common.Multiplex == nil || !node.Common.Multiplex.Enabled || !node.Common.Multiplex.Brutal.Enabled {
		t.Fatalf("unexpected multiplex: %#v", node.Common.Multiplex)
	}
	if node.PushInterval.Seconds() != 7 || node.PullInterval.Seconds() != 11 {
		t.Fatalf("unexpected intervals: push=%s pull=%s", node.PushInterval, node.PullInterval)
	}
}

func TestClientGetNodeInfoParsesSimpleProtocols(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/config" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		writeJSON(t, w, map[string]any{
			"server_port": 1080,
			"base_config": map[string]any{
				"push_interval": 1,
				"pull_interval": 1,
			},
			"routes": []any{},
			"tls":    1,
			"tls_settings": map[string]any{
				"server_name": "proxy.example.com",
				"ech":         map[string]any{"enabled": true, "key": "simple-ech-key"},
			},
		})
	}))
	defer server.Close()

	client := newTestClient(t, server, "naive")
	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.Type != "naive" || node.Simple == nil {
		t.Fatalf("expected naive simple node, got type=%s simple=%#v", node.Type, node.Simple)
	}
	if node.Simple.TlsSettings.ECH.Key != "simple-ech-key" {
		t.Fatalf("unexpected simple tls settings: %#v", node.Simple.TlsSettings)
	}
}

func TestClientGetNodeInfoReturnsNilOn304(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	client := newTestClient(t, server, "vmess")
	node, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node != nil {
		t.Fatalf("expected nil node for 304, got %#v", node)
	}
}

func TestClientReportUserTrafficPostsExpectedPayload(t *testing.T) {
	var payload map[int][]int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/push" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.URL.Query().Get("node_type") != "vless" || r.URL.Query().Get("node_id") != "19" || r.URL.Query().Get("token") != "test-token" {
			t.Fatalf("unexpected query params: %s", r.URL.RawQuery)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTestClient(t, server, "vless")
	err := client.ReportUserTraffic([]UserTraffic{
		{UID: 1001, Upload: 123, Download: 456},
		{UID: 1002, Upload: 789, Download: 1011},
	})
	if err != nil {
		t.Fatalf("ReportUserTraffic: %v", err)
	}
	want := map[int][]int64{
		1001: {123, 456},
		1002: {789, 1011},
	}
	if !reflect.DeepEqual(payload, want) {
		t.Fatalf("unexpected payload: want %#v got %#v", want, payload)
	}
}

func TestClientGetUserListJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/user" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("X-Response-Format") != "msgpack" {
			t.Fatalf("expected msgpack request header, got %q", r.Header.Get("X-Response-Format"))
		}
		w.Header().Set("ETag", "user-etag")
		writeJSON(t, w, map[string]any{
			"users": []map[string]any{{
				"id":           7,
				"uuid":         "user-uuid",
				"speed_limit":  10,
				"device_limit": 2,
			}},
		})
	}))
	defer server.Close()

	client := newTestClient(t, server, "vless")
	users, err := client.GetUserList()
	if err != nil {
		t.Fatalf("GetUserList: %v", err)
	}
	if len(users) != 1 || users[0].Id != 7 || users[0].Uuid != "user-uuid" {
		t.Fatalf("unexpected users: %#v", users)
	}
	if client.userEtag != "user-etag" {
		t.Fatalf("expected user etag to update, got %q", client.userEtag)
	}
}
