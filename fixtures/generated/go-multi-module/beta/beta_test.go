package beta

import "testing"

func TestName(t *testing.T) {
	if got := Name(); got != "beta" {
		t.Fatalf("Name() = %q", got)
	}
}
