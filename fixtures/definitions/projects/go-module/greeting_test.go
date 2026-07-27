package greeting

import "testing"

func TestMessage(t *testing.T) {
	if got := Message(); got != "hello from go" {
		t.Fatalf("Message() = %q", got)
	}
}
