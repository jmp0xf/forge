package alpha

import "testing"

func TestName(t *testing.T) {
	if got := Name(); got != "alpha" {
		t.Fatalf("Name() = %q", got)
	}
}
