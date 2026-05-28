package term

import (
	"os"
	"testing"
)

func TestReadLineTrimsCRLF(t *testing.T) {
	// Drive stdin from a pipe so the test is hermetic.
	orig := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Stdin = orig })
	os.Stdin = r
	go func() {
		_, _ = w.WriteString("47281930\r\n")
		_ = w.Close()
	}()

	got, err := ReadLine("Enter code: ")
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	if got != "47281930" {
		t.Fatalf("got %q want %q", got, "47281930")
	}
}
