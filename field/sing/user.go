package sing

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"unsafe"

	anytlsservice "github.com/anytls/sing-anytls"
	"github.com/gofrs/uuid/v5"
	"github.com/qingsu/atlas/base/counter"
	core "github.com/qingsu/atlas/field"
	"github.com/qingsu/atlas/mirror/panel"
	"github.com/sagernet/sing-box/option"
	sbanytls "github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/hysteria"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing/common/auth"
)

func singUIDKey(tag, uuid string) string {
	return tag + "|" + uuid
}

func cloneTagUsers(users map[string]panel.UserInfo) map[string]panel.UserInfo {
	if len(users) == 0 {
		return make(map[string]panel.UserInfo)
	}
	cloned := make(map[string]panel.UserInfo, len(users))
	for uuid, user := range users {
		cloned[uuid] = user
	}
	return cloned
}

func sortedTagUsers(users map[string]panel.UserInfo) []panel.UserInfo {
	userList := make([]panel.UserInfo, 0, len(users))
	for _, user := range users {
		userList = append(userList, user)
	}
	sort.Slice(userList, func(i, j int) bool {
		if userList[i].Uuid == userList[j].Uuid {
			return userList[i].Id < userList[j].Id
		}
		return userList[i].Uuid < userList[j].Uuid
	})
	return userList
}

func userIndexes(size int) []int {
	indexes := make([]int, size)
	for i := range indexes {
		indexes[i] = i
	}
	return indexes
}

func shadowsocksPassword(cipher, password string) string {
	switch cipher {
	case "2022-blake3-aes-128-gcm":
		return base64.StdEncoding.EncodeToString([]byte(password[:16]))
	case "2022-blake3-aes-256-gcm":
		return base64.StdEncoding.EncodeToString([]byte(password[:32]))
	default:
		return password
	}
}

func tuicUUIDs(users []panel.UserInfo) ([][16]byte, error) {
	userUUIDs := make([][16]byte, 0, len(users))
	for _, user := range users {
		parsedUUID, err := uuid.FromString(user.Uuid)
		if err != nil {
			return nil, fmt.Errorf("invalid uuid %q: %w", user.Uuid, err)
		}
		userUUIDs = append(userUUIDs, parsedUUID)
	}
	return userUUIDs, nil
}

func unsafeFieldValue(target any, fieldName string) (reflect.Value, error) {
	targetValue := reflect.ValueOf(target)
	if targetValue.Kind() != reflect.Pointer || targetValue.IsNil() {
		return reflect.Value{}, fmt.Errorf("invalid target for field %s", fieldName)
	}
	fieldValue := targetValue.Elem().FieldByName(fieldName)
	if !fieldValue.IsValid() {
		return reflect.Value{}, fmt.Errorf("field %s not found", fieldName)
	}
	return reflect.NewAt(fieldValue.Type(), unsafe.Pointer(fieldValue.UnsafeAddr())).Elem(), nil
}

func callUnsafeFieldMethod(target any, fieldName, methodName string, args ...any) error {
	fieldValue, err := unsafeFieldValue(target, fieldName)
	if err != nil {
		return err
	}
	method := fieldValue.MethodByName(methodName)
	if !method.IsValid() {
		return fmt.Errorf("method %s not found on field %s", methodName, fieldName)
	}
	callArgs := make([]reflect.Value, len(args))
	for i, arg := range args {
		callArgs[i] = reflect.ValueOf(arg)
	}
	results := method.Call(callArgs)
	if len(results) == 1 && !results[0].IsNil() {
		err, ok := results[0].Interface().(error)
		if ok {
			return err
		}
	}
	return nil
}

func setUnsafeField(target any, fieldName string, value any) error {
	fieldValue, err := unsafeFieldValue(target, fieldName)
	if err != nil {
		return err
	}
	valueRef := reflect.ValueOf(value)
	if !valueRef.Type().AssignableTo(fieldValue.Type()) {
		return fmt.Errorf("value type %s is not assignable to field %s", valueRef.Type(), fieldName)
	}
	fieldValue.Set(valueRef)
	return nil
}

func (b *Sing) refreshInboundUsers(tag string, nodeInfo *panel.NodeInfo, users []panel.UserInfo) error {
	in, found := b.box.Inbound().Get(tag)
	if !found {
		return errors.New("the inbound not found")
	}

	switch nodeInfo.Type {
	case "vless":
		userList := make([]option.VLESSUser, len(users))
		uuidList := make([]string, len(users))
		flowList := make([]string, len(users))
		for i, user := range users {
			userList[i] = option.VLESSUser{
				Name: user.Uuid,
				Flow: nodeInfo.VAllss.Flow,
				UUID: user.Uuid,
			}
			uuidList[i] = user.Uuid
			flowList[i] = nodeInfo.VAllss.Flow
		}
		inbound := in.(*vless.Inbound)
		if err := callUnsafeFieldMethod(inbound, "service", "UpdateUsers", userIndexes(len(users)), uuidList, flowList); err != nil {
			return err
		}
		return setUnsafeField(inbound, "users", userList)
	case "vmess":
		userList := make([]option.VMessUser, len(users))
		uuidList := make([]string, len(users))
		alterIDList := make([]int, len(users))
		for i, user := range users {
			userList[i] = option.VMessUser{
				Name: user.Uuid,
				UUID: user.Uuid,
			}
			uuidList[i] = user.Uuid
		}
		inbound := in.(*vmess.Inbound)
		if err := callUnsafeFieldMethod(inbound, "service", "UpdateUsers", userIndexes(len(users)), uuidList, alterIDList); err != nil {
			return err
		}
		return setUnsafeField(inbound, "users", userList)
	case "shadowsocks":
		userList := make([]string, len(users))
		passwordList := make([]string, len(users))
		for i, user := range users {
			userList[i] = user.Uuid
			passwordList[i] = shadowsocksPassword(nodeInfo.Shadowsocks.Cipher, user.Uuid)
		}
		return in.(*shadowsocks.MultiInbound).UpdateUsers(userList, passwordList)
	case "trojan":
		userList := make([]option.TrojanUser, len(users))
		passwordList := make([]string, len(users))
		for i, user := range users {
			userList[i] = option.TrojanUser{
				Name:     user.Uuid,
				Password: user.Uuid,
			}
			passwordList[i] = user.Uuid
		}
		inbound := in.(*trojan.Inbound)
		if err := callUnsafeFieldMethod(inbound, "service", "UpdateUsers", userIndexes(len(users)), passwordList); err != nil {
			return err
		}
		return setUnsafeField(inbound, "users", userList)
	case "tuic":
		userNameList := make([]string, len(users))
		passwordList := make([]string, len(users))
		uuidList, err := tuicUUIDs(users)
		if err != nil {
			return err
		}
		for i, user := range users {
			userNameList[i] = user.Uuid
			passwordList[i] = user.Uuid
		}
		inbound := in.(*tuic.Inbound)
		if err := callUnsafeFieldMethod(inbound, "server", "UpdateUsers", userIndexes(len(users)), uuidList, passwordList); err != nil {
			return err
		}
		return setUnsafeField(inbound, "userNameList", userNameList)
	case "hysteria":
		userNameList := make([]string, len(users))
		passwordList := make([]string, len(users))
		for i, user := range users {
			userNameList[i] = user.Uuid
			passwordList[i] = user.Uuid
		}
		inbound := in.(*hysteria.Inbound)
		if err := callUnsafeFieldMethod(inbound, "service", "UpdateUsers", userIndexes(len(users)), passwordList); err != nil {
			return err
		}
		return setUnsafeField(inbound, "userNameList", userNameList)
	case "hysteria2":
		userNameList := make([]string, len(users))
		passwordList := make([]string, len(users))
		for i, user := range users {
			userNameList[i] = user.Uuid
			passwordList[i] = user.Uuid
		}
		inbound := in.(*hysteria2.Inbound)
		if err := callUnsafeFieldMethod(inbound, "service", "UpdateUsers", userIndexes(len(users)), passwordList); err != nil {
			return err
		}
		return setUnsafeField(inbound, "userNameList", userNameList)
	case "anytls":
		userList := make([]anytlsservice.User, len(users))
		for i, user := range users {
			userList[i] = anytlsservice.User{
				Name:     user.Uuid,
				Password: user.Uuid,
			}
		}
		return callUnsafeFieldMethod(in.(*sbanytls.Inbound), "service", "UpdateUsers", userList)
	case "socks":
		return setUnsafeField(in.(*socks.Inbound), "authenticator", auth.NewAuthenticator(panelUsers(users)))
	case "http":
		return setUnsafeField(in.(*http.Inbound), "authenticator", auth.NewAuthenticator(panelUsers(users)))
	case "naive":
		return setUnsafeField(in.(*naive.Inbound), "authenticator", auth.NewAuthenticator(panelUsers(users)))
	default:
		return fmt.Errorf("unsupported sing node type: %s", nodeInfo.Type)
	}
}

func (b *Sing) replaceTagUsers(tag string, oldUsers map[string]panel.UserInfo, newUsers []panel.UserInfo) {
	if len(newUsers) == 0 {
		delete(b.users.tagUsers, tag)
	} else {
		nextUsers := make(map[string]panel.UserInfo, len(newUsers))
		for _, user := range newUsers {
			nextUsers[user.Uuid] = user
		}
		b.users.tagUsers[tag] = nextUsers
	}
	for uuid := range oldUsers {
		delete(b.users.uidMap, singUIDKey(tag, uuid))
	}
	for _, user := range newUsers {
		b.users.uidMap[singUIDKey(tag, user.Uuid)] = user.Id
	}
}

func (b *Sing) AddUsers(p *core.AddUsersParams) (added int, err error) {
	b.users.mapLock.Lock()
	defer b.users.mapLock.Unlock()

	oldUsers := cloneTagUsers(b.users.tagUsers[p.Tag])
	nextUsers := cloneTagUsers(oldUsers)
	for _, user := range p.Users {
		nextUsers[user.Uuid] = user
	}
	userList := sortedTagUsers(nextUsers)
	if err := b.refreshInboundUsers(p.Tag, p.NodeInfo, userList); err != nil {
		return 0, err
	}
	b.replaceTagUsers(p.Tag, oldUsers, userList)
	return len(p.Users), nil
}

func (b *Sing) GetUserTraffic(tag, uuid string, reset bool) (up int64, down int64) {
	if v, ok := b.hookServer.counter.Load(tag); ok {
		c := v.(*counter.TrafficCounter)
		up = c.GetUpCount(uuid)
		down = c.GetDownCount(uuid)
		if reset {
			c.Reset(uuid)
		}
		return
	}
	return 0, 0
}

func (b *Sing) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	trafficSlice := make([]panel.UserTraffic, 0)
	hook := b.hookServer
	b.users.mapLock.RLock()
	defer b.users.mapLock.RUnlock()
	if v, ok := hook.counter.Load(tag); ok {
		c := v.(*counter.TrafficCounter)
		c.Counters.Range(func(key, value interface{}) bool {
			uuid := key.(string)
			traffic := value.(*counter.TrafficStorage)
			up := traffic.UpCounter.Load()
			down := traffic.DownCounter.Load()
			if up+down > b.nodeReportMinTrafficBytes[tag] {
				if reset {
					traffic.UpCounter.Store(0)
					traffic.DownCounter.Store(0)
				}
				uidKey := singUIDKey(tag, uuid)
				if b.users.uidMap[uidKey] == 0 {
					c.Delete(uuid)
					return true
				}
				trafficSlice = append(trafficSlice, panel.UserTraffic{
					UID:      b.users.uidMap[uidKey],
					Upload:   up,
					Download: down,
				})
			}
			return true
		})
		if len(trafficSlice) == 0 {
			return nil, nil
		}
		return trafficSlice, nil
	}
	return nil, nil
}

func (b *Sing) DelUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) error {
	b.users.mapLock.Lock()
	defer b.users.mapLock.Unlock()

	oldUsers := cloneTagUsers(b.users.tagUsers[tag])
	nextUsers := cloneTagUsers(oldUsers)
	for _, user := range users {
		delete(nextUsers, user.Uuid)
	}
	userList := sortedTagUsers(nextUsers)
	if err := b.refreshInboundUsers(tag, info, userList); err != nil {
		return err
	}
	b.replaceTagUsers(tag, oldUsers, userList)
	if v, ok := b.hookServer.counter.Load(tag); ok {
		c := v.(*counter.TrafficCounter)
		for _, user := range users {
			c.Delete(user.Uuid)
		}
	}
	return nil
}
