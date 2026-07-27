package embedded

import "testing"

func TestEmbeddedMessage(t *testing.T) {
	if message := Message(); message != "hello from embed\n" {
		t.Fatalf("Message() = %q", message)
	}
}
