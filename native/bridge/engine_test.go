package bridge

import (
	"errors"
	"github.com/sagernet/sing/common/control"
	"testing"
)

type testProtector struct{ called bool }

func (p *testProtector) PhysicalInterfaces() (string, error) { return "", nil }

func (p *testProtector) Protect(fd int32) error                   { p.called = true; return errors.New("rejected") }
func (p *testProtector) ExchangeDNS(query []byte) ([]byte, error) { return nil, errors.New("rejected") }
func TestRejectsInvalidContextBeforeOpeningDescriptors(t *testing.T) {
	if _, err := NewRuntime("{}", -1, &testProtector{}, "test", 1); err == nil {
		t.Fatal("negative FD accepted")
	}
	if _, err := NewRuntime("{}", 0, nil, "test", 1); err == nil {
		t.Fatal("missing protector accepted")
	}
	if _, err := NewRuntime("not-json", 0, &testProtector{}, "test", 1); err == nil {
		t.Fatal("invalid config accepted")
	}
}
func TestSocketProtectionFailsClosed(t *testing.T) {
	protector := &testProtector{}
	p := &platform{protector: protector}
	if p.AutoDetectInterfaceControl(7) == nil || !protector.called {
		t.Fatal("protection failure ignored")
	}
}
func TestMonitorUsesImmutableSnapshotsAndUnregisters(t *testing.T) {
	m := &monitor{iface: control.Interface{Name: "first", Index: 1}}
	before := m.DefaultInterface()
	calls := 0
	callback := m.RegisterCallback(func(i *control.Interface, flags int) {
		calls++
		if i.Name != "second" {
			t.Error("wrong network")
		}
	})
	m.update(control.Interface{Name: "second", Index: 2})
	if calls != 1 || before.Name != "first" || m.DefaultInterface().Index != 2 {
		t.Fatal("monitor snapshot/callback failure")
	}
	m.UnregisterCallback(callback)
	m.update(control.Interface{Name: "third", Index: 3})
	if calls != 1 {
		t.Fatal("removed callback executed")
	}
}
