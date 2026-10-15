package collatio

// Host conformance (ABI.md §Hosts) and the genesis vectors through the Go host.
// The real module is ../out/collatio.wasm (../build.sh), or COLLATIO_WASM.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func realModule(t *testing.T) []byte {
	t.Helper()
	if p := os.Getenv("COLLATIO_WASM"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return readFile(t, "out/collatio.wasm")
}

func decode(t *testing.T, b []byte, v any) {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		t.Fatal(err)
	}
}

// canonical is enough for comparing answers: json.Marshal sorts keys and keeps json.Number text.
func canonical(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func assertAnswer(t *testing.T, got Answer, want map[string]any, where string) {
	t.Helper()
	for k, v := range want {
		if g, ok := got[k]; !ok || canonical(g) != canonical(v) {
			t.Errorf("%s: %s = %s (want %s)", where, k, canonical(got[k]), canonical(v))
			return
		}
	}
}

type scenario struct {
	Name           string                          `json:"name"`
	Modules        []struct{ File, Digest string } `json:"modules"`
	MaxMemory      uint32                          `json:"max_memory"`
	LoadError      string                          `json:"load_error"`
	Instantiations *int                            `json:"instantiations"`
	Calls          []struct {
		Raw    *string         `json:"raw"`
		Input  json.RawMessage `json:"input"`
		Answer map[string]any  `json:"answer"`
		Absent []string        `json:"absent"`
	} `json:"calls"`
}

func TestHostConformance(t *testing.T) {
	ctx := context.Background()
	real := realModule(t)
	var file struct {
		Scenarios []scenario `json:"scenarios"`
	}
	decode(t, readFile(t, "conformance/hosts-1.json"), &file)
	for _, sc := range file.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			mods := make([]declaredModule, 0, len(sc.Modules))
			for _, m := range sc.Modules {
				if m.File == "collatio" {
					mods = append(mods, declaredModule{digest: m.Digest, bytes: real})
				} else {
					mods = append(mods, declaredModule{digest: "stub:" + m.File, bytes: readFile(t, "conformance/modules/"+m.File)})
				}
			}
			h, err := newHost(ctx, mods, Options{MaxMemory: sc.MaxMemory})
			if sc.LoadError != "" {
				var e *Error
				if !errors.As(err, &e) || e.Reason != sc.LoadError {
					t.Fatalf("load: %v (want %s)", err, sc.LoadError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close(ctx)
			for i, c := range sc.Calls {
				input := []byte(c.Input)
				if c.Raw != nil {
					input = []byte(*c.Raw)
				}
				got, err := h.Call(ctx, input)
				if err != nil {
					t.Fatalf("call %d: %v", i, err)
				}
				assertAnswer(t, got, c.Answer, "call")
				for _, k := range c.Absent {
					if _, ok := got[k]; ok {
						t.Errorf("call %d: %s should be absent", i, k)
					}
				}
			}
			if sc.Instantiations != nil && h.Instantiations() != *sc.Instantiations {
				t.Errorf("instantiations = %d (want %d)", h.Instantiations(), *sc.Instantiations)
			}
		})
	}
}

func TestGenesisVectors(t *testing.T) {
	ctx := context.Background()
	var hosts struct {
		Scenarios []scenario `json:"scenarios"`
	}
	decode(t, readFile(t, "conformance/hosts-1.json"), &hosts)
	var verifier string
	for _, sc := range hosts.Scenarios {
		if sc.Name == "a receipt on the module it names" {
			verifier = sc.Modules[0].Digest
		}
	}
	h, err := newHost(ctx, []declaredModule{{digest: verifier, bytes: realModule(t)}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(ctx)
	var file struct {
		Cases []struct {
			Name   string          `json:"name"`
			Input  json.RawMessage `json:"input"`
			Answer map[string]any  `json:"answer"`
		} `json:"cases"`
	}
	decode(t, readFile(t, "vectors/genesis/ops-1.json"), &file)
	if len(file.Cases) < 100 {
		t.Fatalf("%d cases", len(file.Cases))
	}
	for _, c := range file.Cases {
		got, err := h.Call(ctx, c.Input)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		assertAnswer(t, got, c.Answer, c.Name)
	}
}

func TestNewChecksDigests(t *testing.T) {
	ctx := context.Background()
	stub := readFile(t, "conformance/modules/stub.wasm")
	h, err := New(ctx, []Module{{Bytes: stub}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(ctx)
	if got := h.Digests()[0]; got != Digest(stub) {
		t.Fatalf("digest %s", got)
	}
	var e *Error
	if _, err := New(ctx, []Module{{Bytes: stub, Digest: "sha256:x"}}, Options{}); !errors.As(err, &e) || e.Reason != "digest_mismatch" {
		t.Fatalf("declared digest: %v", err)
	}
}
