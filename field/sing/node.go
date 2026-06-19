package sing

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"encoding/json"

	"github.com/qingsu/atlas/mirror/panel"
	"github.com/qingsu/atlas/paper"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"
)

type HttpNetworkConfig struct {
	Header struct {
		Type     string           `json:"type"`
		Request  *json.RawMessage `json:"request"`
		Response *json.RawMessage `json:"response"`
	} `json:"header"`
}

type HttpRequest struct {
	Version string   `json:"version"`
	Method  string   `json:"method"`
	Path    []string `json:"path"`
	Host    []string `json:"host"`
	Headers struct {
		Host []string `json:"Host"`
	} `json:"headers"`
}

type WsNetworkConfig struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

type GrpcNetworkConfig struct {
	ServiceName string `json:"serviceName"`
}

type HttpupgradeNetworkConfig struct {
	Path    string            `json:"path"`
	Host    string            `json:"host"`
	Headers map[string]string `json:"headers"`
}

type H2NetworkConfig struct {
	Host   panel.StringList `json:"host"`
	Path   string           `json:"path"`
	Method string           `json:"method"`
}

func randomAuthUser() auth.User {
	p := make([]byte, 32)
	_, _ = rand.Read(p)
	password := hex.EncodeToString(p)
	return auth.User{
		Username: password,
		Password: password,
	}
}

func panelUsers(users []panel.UserInfo) []auth.User {
	if len(users) == 0 {
		return []auth.User{randomAuthUser()}
	}
	userList := make([]auth.User, len(users))
	for i, user := range users {
		userList[i] = auth.User{
			Username: user.Uuid,
			Password: user.Uuid,
		}
	}
	return userList
}

func buildInboundMultiplex(global *conf.MultiplexConfig, node *panel.Multiplex) *option.InboundMultiplexOptions {
	if node != nil {
		return &option.InboundMultiplexOptions{
			Enabled: node.Enabled,
			Padding: node.Padding,
			Brutal: &option.BrutalOptions{
				Enabled:  node.Brutal.Enabled,
				UpMbps:   node.Brutal.UpMbps,
				DownMbps: node.Brutal.DownMbps,
			},
		}
	}
	if global != nil {
		return &option.InboundMultiplexOptions{
			Enabled: global.Enabled,
			Padding: global.Padding,
			Brutal: &option.BrutalOptions{
				Enabled:  global.Brutal.Enabled,
				UpMbps:   global.Brutal.UpMbps,
				DownMbps: global.Brutal.DownMbps,
			},
		}
	}
	return nil
}

func applyInboundECH(tls *option.InboundTLSOptions, settings panel.ECHSettings) {
	if !settings.Enabled {
		return
	}
	tls.ECH = &option.InboundECHOptions{
		Enabled: true,
		Key:     badoption.Listable[string]{settings.Key},
		KeyPath: settings.KeyPath,
	}
	if settings.Key == "" {
		tls.ECH.Key = nil
	}
}

func nodeTLSSettings(info *panel.NodeInfo) panel.TlsSettings {
	switch info.Type {
	case "vmess", "vless":
		if info.VAllss != nil {
			return info.VAllss.TlsSettings
		}
	case "trojan":
		if info.Trojan != nil {
			return info.Trojan.TlsSettings
		}
	case "socks", "http", "naive":
		if info.Simple != nil {
			return info.Simple.TlsSettings
		}
	}
	return panel.TlsSettings{}
}

func buildV2RayTransport(network string, raw json.RawMessage) (*option.V2RayTransportOptions, error) {
	if network == "" || network == "tcp" && len(raw) == 0 {
		return nil, nil
	}
	t := &option.V2RayTransportOptions{
		Type: network,
	}
	switch network {
	case "tcp":
		networkConfig := HttpNetworkConfig{}
		if len(raw) != 0 {
			if err := json.Unmarshal(raw, &networkConfig); err != nil {
				return nil, fmt.Errorf("decode NetworkSettings error: %s", err)
			}
		}
		if networkConfig.Header.Type != "http" {
			return nil, nil
		}
		t.Type = "http"
		if networkConfig.Header.Request != nil {
			var request HttpRequest
			if err := json.Unmarshal(*networkConfig.Header.Request, &request); err != nil {
				return nil, fmt.Errorf("decode HttpRequest error: %s", err)
			}
			t.HTTPOptions.Host = request.Headers.Host
			if len(request.Path) > 0 {
				t.HTTPOptions.Path = request.Path[0]
			}
			t.HTTPOptions.Method = request.Method
		}
	case "http", "h2":
		t.Type = "http"
		if len(raw) != 0 {
			var h2 H2NetworkConfig
			if err := json.Unmarshal(raw, &h2); err == nil {
				t.HTTPOptions.Host = []string(h2.Host)
				t.HTTPOptions.Path = h2.Path
				t.HTTPOptions.Method = h2.Method
			}
			var request HttpRequest
			if err := json.Unmarshal(raw, &request); err == nil {
				if len(request.Headers.Host) > 0 {
					t.HTTPOptions.Host = request.Headers.Host
				} else if len(request.Host) > 0 {
					t.HTTPOptions.Host = request.Host
				}
				if len(request.Path) > 0 {
					t.HTTPOptions.Path = request.Path[0]
				}
				if request.Method != "" {
					t.HTTPOptions.Method = request.Method
				}
			}
		}
	case "ws":
		var (
			path    string
			ed      int
			headers map[string]badoption.Listable[string]
		)
		if len(raw) != 0 {
			networkConfig := WsNetworkConfig{}
			if err := json.Unmarshal(raw, &networkConfig); err != nil {
				return nil, fmt.Errorf("decode NetworkSettings error: %s", err)
			}
			u, err := url.Parse(networkConfig.Path)
			if err != nil {
				return nil, fmt.Errorf("parse path error: %s", err)
			}
			path = u.Path
			ed, _ = strconv.Atoi(u.Query().Get("ed"))
			headers = make(map[string]badoption.Listable[string], len(networkConfig.Headers))
			for k, v := range networkConfig.Headers {
				headers[k] = badoption.Listable[string]{v}
			}
		}
		t.WebsocketOptions = option.V2RayWebsocketOptions{
			Path:                path,
			EarlyDataHeaderName: "Sec-WebSocket-Protocol",
			MaxEarlyData:        uint32(ed),
			Headers:             headers,
		}
	case "grpc":
		networkConfig := GrpcNetworkConfig{}
		if len(raw) != 0 {
			if err := json.Unmarshal(raw, &networkConfig); err != nil {
				return nil, fmt.Errorf("decode NetworkSettings error: %s", err)
			}
		}
		t.GRPCOptions = option.V2RayGRPCOptions{
			ServiceName: networkConfig.ServiceName,
		}
	case "httpupgrade":
		networkConfig := HttpupgradeNetworkConfig{}
		if len(raw) != 0 {
			if err := json.Unmarshal(raw, &networkConfig); err != nil {
				return nil, fmt.Errorf("decode NetworkSettings error: %s", err)
			}
		}
		t.HTTPUpgradeOptions = option.V2RayHTTPUpgradeOptions{
			Path: networkConfig.Path,
			Host: networkConfig.Host,
		}
		if len(networkConfig.Headers) > 0 {
			t.HTTPUpgradeOptions.Headers = make(map[string]badoption.Listable[string], len(networkConfig.Headers))
			for k, v := range networkConfig.Headers {
				t.HTTPUpgradeOptions.Headers[k] = badoption.Listable[string]{v}
			}
		}
	default:
		return nil, fmt.Errorf("unsupported sing transport type: %s", network)
	}
	return t, nil
}

func getInboundOptions(tag string, info *panel.NodeInfo, c *conf.Options) (option.Inbound, error) {
	addr, err := netip.ParseAddr(c.ListenIP)
	if err != nil {
		return option.Inbound{}, fmt.Errorf("the listen ip not vail")
	}
	listen := option.ListenOptions{
		Listen:      (*badoption.Addr)(&addr),
		ListenPort:  uint16(info.Common.ServerPort),
		TCPFastOpen: c.SingOptions.TCPFastOpen,
	}
	multiplex := buildInboundMultiplex(c.SingOptions.Multiplex, info.Common.Multiplex)
	var tls option.InboundTLSOptions
	switch info.Security {
	case panel.Tls:
		if c.CertConfig == nil {
			return option.Inbound{}, fmt.Errorf("the CertConfig is not vail")
		}
		switch c.CertConfig.CertMode {
		case "none", "":
			break // disable
		default:
			tls.Enabled = true
			tls.CertificatePath = c.CertConfig.CertFile
			tls.KeyPath = c.CertConfig.KeyFile
			settings := nodeTLSSettings(info)
			tls.ALPN = badoption.Listable[string](settings.ALPN)
			applyInboundECH(&tls, settings.ECH)
		}
	case panel.Reality:
		tls.Enabled = true
		settings := nodeTLSSettings(info)
		tls.ServerName = settings.ServerName
		port, _ := strconv.Atoi(settings.ServerPort)
		var dest string
		if settings.Dest != "" {
			dest = settings.Dest
		} else {
			dest = tls.ServerName
		}

		var maxTimeDiff string
		if info.VAllss != nil {
			maxTimeDiff = info.VAllss.RealityConfig.MaxTimeDiff
		}
		mtd, _ := time.ParseDuration(maxTimeDiff)
		tls.Reality = &option.InboundRealityOptions{
			Enabled:    true,
			ShortID:    []string{settings.ShortId},
			PrivateKey: settings.PrivateKey,
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     dest,
					ServerPort: uint16(port),
				},
			},
			MaxTimeDifference: badoption.Duration(mtd),
		}
	}
	in := option.Inbound{
		Tag: tag,
	}
	switch info.Type {
	case "vmess", "vless":
		n := info.VAllss
		t, err := buildV2RayTransport(n.Network, n.NetworkSettings)
		if err != nil {
			return option.Inbound{}, err
		}
		if info.Type == "vless" {
			in.Type = "vless"
			in.Options = &option.VLESSInboundOptions{
				ListenOptions: listen,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &tls,
				},
				Transport: t,
				Multiplex: multiplex,
			}
		} else {
			in.Type = "vmess"
			in.Options = &option.VMessInboundOptions{
				ListenOptions: listen,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &tls,
				},
				Transport: t,
				Multiplex: multiplex,
			}
		}
	case "shadowsocks":
		in.Type = "shadowsocks"
		n := info.Shadowsocks
		var keyLength int
		switch n.Cipher {
		case "2022-blake3-aes-128-gcm":
			keyLength = 16
		case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
			keyLength = 32
		default:
			keyLength = 16
		}
		ssoption := &option.ShadowsocksInboundOptions{
			ListenOptions: listen,
			Method:        n.Cipher,
			Multiplex:     multiplex,
		}
		p := make([]byte, keyLength)
		_, _ = rand.Read(p)
		randomPasswd := string(p)
		if strings.Contains(n.Cipher, "2022") {
			ssoption.Password = n.ServerKey
			randomPasswd = base64.StdEncoding.EncodeToString([]byte(randomPasswd))
		}
		ssoption.Users = []option.ShadowsocksUser{{
			Password: randomPasswd,
		}}
		in.Options = ssoption
	case "trojan":
		n := info.Trojan
		t, err := buildV2RayTransport(n.Network, n.NetworkSettings)
		if err != nil {
			return option.Inbound{}, err
		}
		in.Type = "trojan"
		trojanoption := &option.TrojanInboundOptions{
			ListenOptions: listen,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
			Transport: t,
			Multiplex: multiplex,
		}
		if c.SingOptions.FallBackConfigs != nil {
			// fallback handling
			fallback := c.SingOptions.FallBackConfigs.FallBack
			fallbackPort, err := strconv.Atoi(fallback.ServerPort)
			if err == nil {
				trojanoption.Fallback = &option.ServerOptions{
					Server:     fallback.Server,
					ServerPort: uint16(fallbackPort),
				}
			}
			fallbackForALPNMap := c.SingOptions.FallBackConfigs.FallBackForALPN
			fallbackForALPN := make(map[string]*option.ServerOptions, len(fallbackForALPNMap))
			if err := processFallback(c, fallbackForALPN); err == nil {
				trojanoption.FallbackForALPN = fallbackForALPN
			}
		}
		in.Options = trojanoption
	case "tuic":
		in.Type = "tuic"
		if len(info.Tuic.ALPN) > 0 {
			tls.ALPN = badoption.Listable[string](info.Tuic.ALPN)
		} else {
			tls.ALPN = badoption.Listable[string]{"h3"}
		}
		in.Options = &option.TUICInboundOptions{
			ListenOptions:     listen,
			CongestionControl: info.Tuic.CongestionControl,
			ZeroRTTHandshake:  info.Tuic.ZeroRTTHandshake,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}
	case "anytls":
		in.Type = "anytls"
		in.Options = &option.AnyTLSInboundOptions{
			ListenOptions: listen,
			PaddingScheme: info.AnyTls.PaddingScheme,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}
	case "hysteria":
		in.Type = "hysteria"
		in.Options = &option.HysteriaInboundOptions{
			ListenOptions: listen,
			UpMbps:        info.Hysteria.UpMbps,
			DownMbps:      info.Hysteria.DownMbps,
			Obfs:          info.Hysteria.Obfs,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}
	case "hysteria2":
		in.Type = "hysteria2"
		var obfs *option.Hysteria2Obfs
		if info.Hysteria2.ObfsType != "" && info.Hysteria2.ObfsPassword != "" {
			obfs = &option.Hysteria2Obfs{
				Type:     info.Hysteria2.ObfsType,
				Password: info.Hysteria2.ObfsPassword,
			}
		} else if info.Hysteria2.ObfsType != "" {
			obfs = &option.Hysteria2Obfs{
				Type:     "salamander",
				Password: info.Hysteria2.ObfsType,
			}
		}
		in.Options = &option.Hysteria2InboundOptions{
			ListenOptions:         listen,
			UpMbps:                info.Hysteria2.UpMbps,
			DownMbps:              info.Hysteria2.DownMbps,
			IgnoreClientBandwidth: info.Hysteria2.Ignore_Client_Bandwidth,
			Obfs:                  obfs,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}
	case "socks":
		in.Type = "socks"
		in.Options = &option.SocksInboundOptions{
			ListenOptions: listen,
			Users:         []auth.User{randomAuthUser()},
		}
	case "http":
		in.Type = "http"
		in.Options = &option.HTTPMixedInboundOptions{
			ListenOptions: listen,
			Users:         []auth.User{randomAuthUser()},
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}
	case "naive":
		in.Type = "naive"
		if !tls.Enabled {
			return option.Inbound{}, fmt.Errorf("naive inbound requires tls certificate config")
		}
		in.Options = &option.NaiveInboundOptions{
			ListenOptions: listen,
			Users:         []auth.User{randomAuthUser()},
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}
	}
	return in, nil
}

func (b *Sing) AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error {
	b.nodeReportMinTrafficBytes[tag] = config.ReportMinTraffic * 1024
	c, err := getInboundOptions(tag, info, config)
	if err != nil {
		return err
	}
	in := b.box.Inbound()
	err = in.Create(
		b.ctx,
		b.box.Router(),
		b.logFactory.NewLogger(F.ToString("inbound/", c.Type, "[", tag, "]")),
		tag,
		c.Type,
		c.Options,
	)

	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	return nil
}

func (b *Sing) DelNode(tag string) error {
	b.users.mapLock.Lock()
	if tagUsers, exists := b.users.tagUsers[tag]; exists {
		for uuid := range tagUsers {
			delete(b.users.uidMap, singUIDKey(tag, uuid))
		}
		delete(b.users.tagUsers, tag)
	}
	b.users.mapLock.Unlock()
	delete(b.nodeReportMinTrafficBytes, tag)
	b.hookServer.counter.Delete(tag)
	in := b.box.Inbound()
	err := in.Remove(tag)
	if err != nil {
		return fmt.Errorf("delete inbound error: %s", err)
	}
	return nil
}
