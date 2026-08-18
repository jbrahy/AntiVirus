package notify

import "testing"

func TestEscapeQuotesAndBackslashes(t *testing.T) {
	got := escape(`say "hi" \ bye`)
	want := `say \"hi\" \\ bye`
	if got != want {
		t.Fatalf("escape() = %q, want %q", got, want)
	}
}
