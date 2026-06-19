package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/qingsu/atlas/mirror/panel"
	"github.com/qingsu/atlas/paper"
)

type Selector struct {
	cores map[string]Core
	order []string
	nodes sync.Map
}

func NewSelector(c []conf.CoreConfig) (Core, error) {
	cs := make(map[string]Core, len(c))
	order := make([]string, 0, len(c))
	for _, t := range c {
		f, ok := cores[strings.ToLower(t.Type)]
		if !ok {
			return nil, errors.New("unknown core type: " + t.Type)
		}
		core1, err := f(&t)
		if err != nil {
			return nil, err
		}
		key := t.Name
		if key == "" {
			key = t.Type
		}
		cs[key] = core1
		order = append(order, key)
	}
	return &Selector{
		cores: cs,
		order: order,
	}, nil
}

func (s *Selector) Start() error {
	for i := range s.cores {
		err := s.cores[i].Start()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Selector) Close() error {
	var errs []error
	for i := range s.cores {
		if err := s.cores[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func isSupported(protocol string, protocols []string) bool {
	for i := range protocols {
		if protocol == protocols[i] {
			return true
		}
	}
	return false
}

func (s *Selector) AddNode(tag string, info *panel.NodeInfo, option *conf.Options) error {
	rawOptions := option.RawOptions
	requestedCore := option.Core
	if len(option.CoreName) > 0 {
		// use name to select core
		if c, ok := s.cores[option.CoreName]; ok {
			if err := prepareCoreOptions(option, c, rawOptions); err != nil {
				return err
			}
			if err := c.AddNode(tag, info, option); err != nil {
				return err
			}
			option.RawOptions = nil
			s.nodes.Store(tag, c)
			return nil
		}
		return errors.New("the node core name is not support")
	}

	var errs []error
	for _, name := range s.order {
		c := s.cores[name]
		if requestedCore == "" {
			if !isSupported(info.Type, c.Protocols()) {
				continue
			}
		} else if requestedCore != c.Type() {
			continue
		}
		if err := prepareCoreOptions(option, c, rawOptions); err != nil {
			return err
		}
		if err := c.AddNode(tag, info, option); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.Type(), err))
			option.RawOptions = rawOptions
			continue
		}
		option.RawOptions = nil
		s.nodes.Store(tag, c)
		return nil
	}
	if len(errs) > 0 {
		return fmt.Errorf("add node failed on compatible cores: %w", errors.Join(errs...))
	}
	return errors.New("the node type is not support")
}

func prepareCoreOptions(option *conf.Options, c Core, rawOptions []byte) error {
	if option.Core == c.Type() && rawOptions == nil {
		return nil
	}
	option.Core = c.Type()
	option.RawOptions = rawOptions
	if rawOptions == nil {
		return nil
	}
	patchedOptions, err := injectCoreOption(rawOptions, c.Type())
	if err != nil {
		return fmt.Errorf("inject core option error: %s", err)
	}
	if err := option.UnmarshalJSON(patchedOptions); err != nil {
		return fmt.Errorf("unmarshal option error: %s", err)
	}
	option.Core = c.Type()
	return nil
}

func injectCoreOption(rawOptions []byte, coreType string) ([]byte, error) {
	options := make(map[string]json.RawMessage)
	if err := json.Unmarshal(rawOptions, &options); err != nil {
		return nil, err
	}
	coreValue, err := json.Marshal(coreType)
	if err != nil {
		return nil, err
	}
	options["Core"] = coreValue
	return json.Marshal(options)
}

func (s *Selector) DelNode(tag string) error {
	if t, e := s.nodes.Load(tag); e {
		err := t.(Core).DelNode(tag)
		if err != nil {
			return err
		}
		s.nodes.Delete(tag)
		return nil
	}
	return errors.New("the node is not have")
}

func (s *Selector) AddUsers(p *AddUsersParams) (added int, err error) {
	t, e := s.nodes.Load(p.Tag)
	if !e {
		return 0, errors.New("the node is not have")
	}
	return t.(Core).AddUsers(p)
}

func (s *Selector) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	t, e := s.nodes.Load(tag)
	if !e {
		return nil, errors.New("the node is not have")
	}
	return t.(Core).GetUserTrafficSlice(tag, reset)
}

func (s *Selector) DelUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) error {
	t, e := s.nodes.Load(tag)
	if !e {
		return errors.New("the node is not have")
	}
	return t.(Core).DelUsers(users, tag, info)
}

func (s *Selector) Protocols() []string {
	protocols := make([]string, 0)
	for i := range s.cores {
		protocols = append(protocols, s.cores[i].Protocols()...)
	}
	return protocols
}

func (s *Selector) Type() string {
	t := "Selector("
	var flag bool
	for n, c := range s.cores {
		if flag {
			t += " "
		} else {
			flag = true
		}
		if len(n) == 0 {
			t += c.Type()
		} else {
			t += n
		}
	}
	t += ")"
	return t
}
