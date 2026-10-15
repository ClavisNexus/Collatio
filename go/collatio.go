// Package collatio is the Go host for collatio.wasm (ABI.md): it runs the module on wazero,
// replaces instances after a trap or a memory overrun, picks the module the catalog allows,
// follows revoked verifiers to their successor and marks a stale catalog.
//
// Evidence goes in as the strings received; results come from the answer.
package collatio

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const (
	abiVersion       = 1
	defaultMaxMemory = 64 * 1024 * 1024
	staleAfter       = 7 * 86400
	trustCacheSize   = 16
)

// Error is a refusal before any answer: the module cannot be used.
type Error struct{ Reason string }

func (e *Error) Error() string { return e.Reason }

// Answer is the module's answer: "ok" and what it established, or "ok" false and "reason".
// Numbers are json.Number.
type Answer map[string]any

// OK reports whether the answer is ok.
func (a Answer) OK() bool { ok, _ := a["ok"].(bool); return ok }

// Reason is the refusal's reason, or "".
func (a Answer) Reason() string { r, _ := a["reason"].(string); return r }

func refused(reason string) Answer { return Answer{"ok": false, "reason": reason} }

// Module is a module's bytes. Digest, when set, must be the digest of the bytes.
type Module struct {
	Bytes  []byte
	Digest string
}

// Options tune a Host.
type Options struct {
	// MaxMemory replaces an instance whose memory grows above this many bytes (default 64 MiB).
	MaxMemory uint32
}

// Digest is "sha256:" + Base64URL of the module bytes.
func Digest(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

type slot struct {
	digest   string
	compiled wazero.CompiledModule
	instance api.Module
}

type trustAnswer struct {
	answer   Answer
	issuedAt int64
	revoked  map[string]string
	runnable []*slot
}

// Host runs Collatio modules. It is safe for concurrent use; calls run one at a time.
type Host struct {
	mu             sync.Mutex
	runtime        wazero.Runtime
	slots          []*slot
	maxMemory      uint32
	trustCache     map[string]*trustAnswer
	trustOrder     []string
	instantiations int
}

// New compiles and loads modules; the first is the default.
func New(ctx context.Context, modules []Module, opts Options) (*Host, error) {
	declared := make([]declaredModule, 0, len(modules))
	for _, m := range modules {
		d := Digest(m.Bytes)
		if m.Digest != "" && m.Digest != d {
			return nil, &Error{Reason: "digest_mismatch"}
		}
		declared = append(declared, declaredModule{digest: d, bytes: m.Bytes})
	}
	return newHost(ctx, declared, opts)
}

type declaredModule struct {
	digest string
	bytes  []byte
}

func newHost(ctx context.Context, modules []declaredModule, opts Options) (*Host, error) {
	h := &Host{
		runtime:    wazero.NewRuntime(ctx),
		maxMemory:  opts.MaxMemory,
		trustCache: map[string]*trustAnswer{},
	}
	if h.maxMemory == 0 {
		h.maxMemory = defaultMaxMemory
	}
	for _, m := range modules {
		compiled, err := h.runtime.CompileModule(ctx, m.bytes)
		if err != nil {
			_ = h.Close(ctx)
			return nil, err
		}
		s := &slot{digest: m.digest, compiled: compiled}
		if err := h.instantiate(ctx, s); err != nil {
			_ = h.Close(ctx)
			return nil, err
		}
		h.slots = append(h.slots, s)
	}
	return h, nil
}

// Close releases the runtime and every instance.
func (h *Host) Close(ctx context.Context) error { return h.runtime.Close(ctx) }

// Instantiations is how many instances were made.
func (h *Host) Instantiations() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.instantiations
}

// Digests are the loaded modules' digests, default first.
func (h *Host) Digests() []string {
	out := make([]string, len(h.slots))
	for i, s := range h.slots {
		out[i] = s.digest
	}
	return out
}

func (h *Host) instantiate(ctx context.Context, s *slot) error {
	mod, err := h.runtime.InstantiateModule(ctx, s.compiled, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		return err
	}
	h.instantiations++
	for _, name := range []string{"alloc", "free", "verify", "abi_version"} {
		if mod.ExportedFunction(name) == nil {
			_ = mod.Close(ctx)
			return &Error{Reason: "unsupported_abi"}
		}
	}
	v, err := mod.ExportedFunction("abi_version").Call(ctx)
	if mod.Memory() == nil || err != nil || len(v) != 1 || uint32(v[0]) != abiVersion {
		_ = mod.Close(ctx)
		return &Error{Reason: "unsupported_abi"}
	}
	s.instance = mod
	return nil
}

func (h *Host) discard(ctx context.Context, s *slot) {
	if s.instance != nil {
		_ = s.instance.Close(ctx)
		s.instance = nil
	}
}

// invoke runs one call on a slot. A trap answers verifier_trap; other failures are errors.
func (h *Host) invoke(ctx context.Context, s *slot, input []byte) (Answer, error) {
	if s.instance == nil {
		if err := h.instantiate(ctx, s); err != nil {
			return nil, err
		}
	}
	mod := s.instance
	mem := mod.Memory()
	text, trapped := func() ([]byte, bool) {
		n := uint64(len(input))
		p, err := mod.ExportedFunction("alloc").Call(ctx, n)
		if err != nil || len(p) != 1 || uint32(p[0]) == 0 || !mem.Write(uint32(p[0]), input) {
			return nil, true
		}
		out, err := mod.ExportedFunction("verify").Call(ctx, p[0], n)
		if err != nil || len(out) != 1 {
			return nil, true
		}
		if _, err := mod.ExportedFunction("free").Call(ctx, p[0], n); err != nil {
			return nil, true
		}
		at := uint32(out[0])
		size, ok := mem.ReadUint32Le(at)
		if !ok {
			return nil, true
		}
		view, ok := mem.Read(at+4, size)
		if !ok {
			return nil, true
		}
		text := append([]byte(nil), view...)
		if _, err := mod.ExportedFunction("free").Call(ctx, uint64(at), uint64(size)+4); err != nil {
			return nil, true
		}
		return text, false
	}()
	if trapped {
		h.discard(ctx, s)
		return refused("verifier_trap"), nil
	}
	if mem.Size() > h.maxMemory {
		h.discard(ctx, s)
	}
	return parseAnswer(text)
}

func parseAnswer(text []byte) (Answer, error) {
	var a Answer
	d := json.NewDecoder(bytes.NewReader(text))
	d.UseNumber()
	if err := d.Decode(&a); err != nil {
		return nil, err
	}
	return a, nil
}

// Run runs one call on the module with digest, with no routing.
func (h *Host) Run(ctx context.Context, digest string, input []byte) (Answer, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.slots {
		if s.digest == digest {
			return h.invoke(ctx, s, input)
		}
	}
	return refused("verifier_unavailable"), nil
}

type outer struct {
	Op    string          `json:"op"`
	Trust json.RawMessage `json:"trust"`
	Now   *json.Number    `json:"now"`
}

// Call runs one call (ABI.md §Hosts). input is the outer input as JSON; evidence inside it stays
// as strings.
func (h *Host) Call(ctx context.Context, input []byte) (Answer, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var o outer
	if err := json.Unmarshal(input, &o); err != nil || len(o.Trust) == 0 {
		return h.invoke(ctx, h.slots[0], input)
	}
	now := time.Now().Unix()
	if o.Now != nil {
		if n, err := o.Now.Int64(); err == nil {
			now = n
		}
	}
	t, err := h.trust(ctx, o.Trust)
	if err != nil {
		return nil, err
	}
	if !t.answer.OK() {
		return refused(t.answer.Reason()), nil
	}
	if len(t.runnable) == 0 {
		return refused("verifier_unavailable"), nil
	}
	first := t.runnable[0]
	answer, err := h.invoke(ctx, first, input)
	if err != nil {
		return nil, err
	}
	if answer.OK() && (o.Op == "receipt" || o.Op == "app_receipt") {
		dim, _ := answer["dimension"].(map[string]any)
		named, _ := dim["verifier"].(string)
		target, ok := successor(named, t.revoked)
		if !ok {
			return refused("verifier_unavailable"), nil
		}
		if target != first.digest {
			var next *slot
			for _, s := range t.runnable {
				if s.digest == target {
					next = s
				}
			}
			if next == nil {
				return refused("verifier_unavailable"), nil
			}
			if answer, err = h.invoke(ctx, next, input); err != nil {
				return nil, err
			}
		}
		if answer.OK() {
			answer["verifier"] = target
		}
	}
	if answer.OK() && now-t.issuedAt > staleAfter {
		answer["catalog_stale"] = true
	}
	return answer, nil
}

// successor follows revoked verifiers to their successor; false on a cycle.
func successor(digest string, revoked map[string]string) (string, bool) {
	d := digest
	for i := 0; i <= len(revoked); i++ {
		next, ok := revoked[d]
		if !ok {
			return d, true
		}
		d = next
	}
	return "", false
}

type trustFacts struct {
	IssuedAt  json.Number `json:"issued_at"`
	Verifiers []struct {
		Digest string `json:"digest"`
	} `json:"verifiers"`
	Revoked []struct {
		Verifier  string `json:"verifier"`
		Successor string `json:"successor"`
	} `json:"revoked"`
}

func (h *Host) trust(ctx context.Context, trust json.RawMessage) (*trustAnswer, error) {
	key := string(trust)
	if hit, ok := h.trustCache[key]; ok {
		return hit, nil
	}
	call, err := json.Marshal(map[string]any{"op": "trust", "trust": trust})
	if err != nil {
		return nil, err
	}
	answer, err := h.invoke(ctx, h.slots[0], call)
	if err != nil {
		return nil, err
	}
	t := &trustAnswer{answer: answer}
	if answer.OK() {
		if err := h.readTrust(t); err != nil {
			return nil, err
		}
		if len(t.runnable) > 0 && t.runnable[0] != h.slots[0] {
			if t.answer, err = h.invoke(ctx, t.runnable[0], call); err != nil {
				return nil, err
			}
			if t.answer.OK() {
				if err := h.readTrust(t); err != nil {
					return nil, err
				}
			}
		}
	}
	if len(h.trustOrder) >= trustCacheSize {
		delete(h.trustCache, h.trustOrder[0])
		h.trustOrder = h.trustOrder[1:]
	}
	h.trustCache[key] = t
	h.trustOrder = append(h.trustOrder, key)
	return t, nil
}

func (h *Host) readTrust(t *trustAnswer) error {
	raw, err := json.Marshal(t.answer)
	if err != nil {
		return err
	}
	var f trustFacts
	if err := json.Unmarshal(raw, &f); err != nil {
		return err
	}
	issued, err := f.IssuedAt.Int64()
	if err != nil {
		return errors.New("collatio: trust answer without issued_at")
	}
	t.issuedAt = issued
	listed := map[string]bool{}
	for _, v := range f.Verifiers {
		listed[v.Digest] = true
	}
	t.revoked = map[string]string{}
	for _, r := range f.Revoked {
		t.revoked[r.Verifier] = r.Successor
	}
	t.runnable = nil
	for _, s := range h.slots {
		if _, gone := t.revoked[s.digest]; listed[s.digest] && !gone {
			t.runnable = append(t.runnable, s)
		}
	}
	return nil
}
