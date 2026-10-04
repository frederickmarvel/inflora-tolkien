package app

import (
	"testing"
	"time"
)

func TestTokenCacheExpiresAndClears(t *testing.T) {
	c := NewTokenCache(10 * time.Millisecond)
	p := Principal{StreamerID: "streamer", SessionID: "session", ExpiresAt: time.Now().Add(time.Hour)}
	c.Put("token", p)
	if got, ok := c.Get("token"); !ok || got.StreamerID != p.StreamerID {
		t.Fatalf("cache miss: %#v %v", got, ok)
	}
	time.Sleep(15 * time.Millisecond)
	if _, ok := c.Get("token"); ok {
		t.Fatal("expired cache entry returned")
	}
	c.Put("token", p)
	c.Clear()
	if _, ok := c.Get("token"); ok {
		t.Fatal("cleared cache entry returned")
	}
}

func TestLast4UsesOpaqueTokenSuffix(t *testing.T) {
	if got := last4("ok_abcXYZ"); got != "cXYZ" {
		t.Fatalf("got %q", got)
	}
	if got := last4("abc"); got != "abc" {
		t.Fatalf("got %q", got)
	}
}
