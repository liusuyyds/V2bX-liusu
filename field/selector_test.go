package core

import (
	"errors"
	"testing"

	"github.com/qingsu/atlas/mirror/panel"
	"github.com/qingsu/atlas/paper"
)

type fakeCore struct {
	typeName     string
	protocols    []string
	addErr       error
	addNodeCalls int
	traffic      []panel.UserTraffic
}

func (f *fakeCore) Start() error { return nil }
func (f *fakeCore) Close() error { return nil }
func (f *fakeCore) AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error {
	f.addNodeCalls++
	return f.addErr
}
func (f *fakeCore) DelNode(tag string) error                { return nil }
func (f *fakeCore) AddUsers(p *AddUsersParams) (int, error) { return len(p.Users), nil }
func (f *fakeCore) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	return f.traffic, nil
}
func (f *fakeCore) DelUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) error {
	return nil
}
func (f *fakeCore) Protocols() []string { return f.protocols }
func (f *fakeCore) Type() string        { return f.typeName }

func TestSelectorAddNodeFallsBackToNextCompatibleCore(t *testing.T) {
	xray := &fakeCore{typeName: "xray", protocols: []string{"vless"}, addErr: errors.New("unsupported transport")}
	sing := &fakeCore{typeName: "sing", protocols: []string{"vless"}}
	selector := &Selector{
		cores: map[string]Core{
			"xray": xray,
			"sing": sing,
		},
		order: []string{"xray", "sing"},
	}
	options := &conf.Options{RawOptions: []byte("{\"Core\":\"\",\"ListenIP\":\"0.0.0.0\"}")}
	info := &panel.NodeInfo{Type: "vless"}

	if err := selector.AddNode("node-tag", info, options); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	if xray.addNodeCalls != 1 || sing.addNodeCalls != 1 {
		t.Fatalf("expected both cores to be tried, got xray=%d sing=%d", xray.addNodeCalls, sing.addNodeCalls)
	}
	if options.Core != "sing" {
		t.Fatalf("expected selected core sing, got %q", options.Core)
	}
	stored, ok := selector.nodes.Load("node-tag")
	if !ok || stored != sing {
		t.Fatalf("expected node to be stored on sing, got %#v ok=%v", stored, ok)
	}
}

func TestSelectorAddNodeHonorsExplicitCore(t *testing.T) {
	xray := &fakeCore{typeName: "xray", protocols: []string{"vless"}}
	sing := &fakeCore{typeName: "sing", protocols: []string{"vless"}}
	selector := &Selector{
		cores: map[string]Core{
			"xray": xray,
			"sing": sing,
		},
		order: []string{"xray", "sing"},
	}
	options := &conf.Options{Core: "xray"}
	info := &panel.NodeInfo{Type: "vless"}

	if err := selector.AddNode("node-tag", info, options); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	if xray.addNodeCalls != 1 || sing.addNodeCalls != 0 {
		t.Fatalf("expected only xray to be tried, got xray=%d sing=%d", xray.addNodeCalls, sing.addNodeCalls)
	}
}

func TestSelectorRoutesTrafficThroughSelectedCore(t *testing.T) {
	sing := &fakeCore{
		typeName:  "sing",
		protocols: []string{"vless"},
		traffic:   []panel.UserTraffic{{UID: 1, Upload: 2, Download: 3}},
	}
	selector := &Selector{
		cores: map[string]Core{"sing": sing},
		order: []string{"sing"},
	}
	if err := selector.AddNode("node-tag", &panel.NodeInfo{Type: "vless"}, &conf.Options{}); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	traffic, err := selector.GetUserTrafficSlice("node-tag", true)
	if err != nil {
		t.Fatalf("GetUserTrafficSlice: %v", err)
	}
	if len(traffic) != 1 || traffic[0].UID != 1 || traffic[0].Upload != 2 || traffic[0].Download != 3 {
		t.Fatalf("unexpected traffic: %#v", traffic)
	}
}
