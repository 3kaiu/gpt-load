package embedded

import (
	"encoding/json"
	"testing"
)

func TestKiroToolInputFragment(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []byte
	}{
		{"null placeholder", `null`, nil},
		{"empty quoted", `""`, []byte{}},
		{"quoted content", `"{\"command"`, []byte(`{\"command`)},
		{"trailing quote stripped", `"d\": \"echo "`, []byte(`d\": \"echo `)},
		{"bare token ignored", `nope`, nil},
		{"empty raw", ``, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := kiroToolInputFragment(json.RawMessage(c.raw))
			if string(got) != string(c.want) {
				t.Fatalf("kiroToolInputFragment(%q) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

func TestKiroDecodeToolInputReconstructsArguments(t *testing.T) {
	// Fragments captured from a live Kiro stream for `{"command": "echo hello"}`.
	fragments := [][]byte{
		[]byte(`null`),
		[]byte{0x22, 0x22},
		[]byte{0x22, 0x7b, 0x5c, 0x22, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x22},
		[]byte{0x22, 0x64, 0x5c, 0x22, 0x3a, 0x20, 0x5c, 0x22, 0x65, 0x63, 0x68, 0x6f, 0x20, 0x22},
		[]byte{0x22, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x5c, 0x22, 0x7d, 0x22},
		[]byte(`null`),
	}

	acc := &kiroToolUseAccumulator{}
	var emitted []byte
	for _, frag := range fragments {
		payload := map[string]json.RawMessage{
			"toolUseId": json.RawMessage(`"tid1"`),
			"name":      json.RawMessage(`"bash"`),
			"input":     json.RawMessage(frag),
		}
		event, ok := acc.update(payload)
		if ok {
			emitted = []byte(event.ToolInput)
		}
	}
	// The stop frame never arrived in this fragment set; decode the accumulator
	// directly in the way flush would.
	if event, ok := acc.flush(); ok {
		emitted = []byte(event.ToolInput)
	}

	var got map[string]any
	if err := json.Unmarshal(emitted, &got); err != nil {
		t.Fatalf("decoded tool input is not valid JSON: %q (err=%v)", string(emitted), err)
	}
	if got["command"] != "echo hello" {
		t.Fatalf("reconstructed command = %q, want %q", got["command"], "echo hello")
	}
}
