package main

import "testing"

// With no authentication, the listen address is the first line of defence: a
// non-loopback bind must be an explicit decision.
func TestCheckListenAddr(t *testing.T) {
	cases := []struct {
		addr   string
		remote bool
		ok     bool
	}{
		{"127.0.0.1:8080", false, true},
		{"localhost:8080", false, true},
		{"[::1]:8080", false, true},
		{"127.0.0.2:8080", false, true}, // the whole 127/8 block is loopback
		{":8080", false, false},         // every interface
		{"0.0.0.0:8080", false, false},
		{"[::]:8080", false, false},
		{"192.168.1.5:8080", false, false},
		{"myhost.example.com:8080", false, false},
		{":8080", true, true}, // opted in (the container case)
		{"0.0.0.0:8080", true, true},
		{"8080", false, false}, // malformed
		{"", false, false},
	}
	for _, c := range cases {
		err := checkListenAddr(c.addr, c.remote)
		if (err == nil) != c.ok {
			t.Errorf("checkListenAddr(%q, remote=%v) = %v, want ok=%v", c.addr, c.remote, err, c.ok)
		}
	}
}
