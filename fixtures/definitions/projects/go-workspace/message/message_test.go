package message

import "testing"

func TestText(t *testing.T) {
	if got := Text(); got != "hello" {
		t.Fatalf("Text() = %q", got)
	}
}
