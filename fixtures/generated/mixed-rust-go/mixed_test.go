package mixed

import "testing"

func TestGoLanguage(t *testing.T) {
	if got := GoLanguage(); got != "go" {
		t.Fatalf("GoLanguage() = %q", got)
	}
}
