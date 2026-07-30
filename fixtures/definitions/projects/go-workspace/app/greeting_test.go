package greeting

import "testing"

func TestGreeting(t *testing.T) {
	if got := Greeting(); got != "hello from workspace" {
		t.Fatalf("Greeting() = %q", got)
	}
}
