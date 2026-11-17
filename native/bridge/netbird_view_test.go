package bridge

import "testing"

func TestNetBirdViewBridgeRejectsInactiveRuntimeWithoutStartingOwner(t *testing.T) {
	request := `{"kind":"overlay-view","section":"peers","page":0,"request":"view-test"}`
	for _, runtime := range []*Runtime{nil, {}, {platform: &platform{}}} {
		if runtime.NetBirdView(request) {
			t.Fatal("view gained authority without an active runtime")
		}
	}
}

func TestNetBirdViewBridgeRetainsLeaseExpiryAndNoOwnerRecovery(t *testing.T) {
	var now int64 = 10
	guard := &leaseGuard{clock: func() int64 { return now }}
	if err := guard.set(20); err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{platform: &platform{lease: guard}}
	request := `{"kind":"overlay-view","section":"diagnostics","page":63,"request":"view-test"}`
	if runtime.NetBirdView(request) {
		t.Fatal("view created an absent overlay owner")
	}
	now = 20
	if runtime.NetBirdView(request) || guard.allowed() {
		t.Fatal("expired lease gained view authority")
	}
	if err := guard.set(30); err == nil {
		t.Fatal("view revived expired owner")
	}
}
