// Replays vectors/answers.jsonl through wazero and compares answer bytes (item 5 of spike/README.md).
// The runtime is limited to WebAssembly 1.0 core features, which also checks that the
// module stays inside what `wasm32v1-none` promises.
//
//	go run . ../out/collatio_spike.wasm ../vectors/answers.jsonl
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type line struct {
	Call   string `json:"call"`
	Answer string `json:"answer"`
}

type host struct {
	mod                     api.Module
	alloc, free, verify, av api.Function
}

func newHost(ctx context.Context, rt wazero.Runtime, compiled wazero.CompiledModule) (*host, error) {
	mod, err := rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		return nil, err
	}
	h := &host{mod: mod, alloc: mod.ExportedFunction("alloc"), free: mod.ExportedFunction("free"), verify: mod.ExportedFunction("verify"), av: mod.ExportedFunction("abi_version")}
	v, err := h.av.Call(ctx)
	if err != nil || v[0] != 1 {
		return nil, fmt.Errorf("abi_version %v %v", v, err)
	}
	return h, nil
}

func (h *host) call(ctx context.Context, in []byte) (string, error) {
	r, err := h.alloc.Call(ctx, uint64(len(in)))
	if err != nil {
		return "", err
	}
	p := uint32(r[0])
	if !h.mod.Memory().Write(p, in) {
		return "", fmt.Errorf("write")
	}
	r, err = h.verify.Call(ctx, uint64(p), uint64(len(in)))
	if err != nil {
		return "", err
	}
	_, _ = h.free.Call(ctx, uint64(p), uint64(len(in)))
	out := uint32(r[0])
	lb, ok := h.mod.Memory().Read(out, 4)
	if !ok {
		return "", fmt.Errorf("read len")
	}
	n := binary.LittleEndian.Uint32(lb)
	body, ok := h.mod.Memory().Read(out+4, n)
	if !ok {
		return "", fmt.Errorf("read body")
	}
	s := string(body)
	_, _ = h.free.Call(ctx, uint64(out), uint64(4+n))
	return s, nil
}

func main() {
	ctx := context.Background()
	wasm, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCoreFeatures(api.CoreFeaturesV1))
	defer rt.Close(ctx)
	t0 := time.Now()
	compiled, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		fmt.Println("compile (CoreFeaturesV1):", err)
		os.Exit(1)
	}
	compileDur := time.Since(t0)
	if n := len(compiled.ImportedFunctions()); n != 0 {
		fmt.Println("imports:", n)
		os.Exit(1)
	}
	h, err := newHost(ctx, rt, compiled)
	if err != nil {
		panic(err)
	}

	f, err := os.Open(os.Args[2])
	if err != nil {
		panic(err)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<20), 64<<20)
	total, same := 0, 0
	t1 := time.Now()
	for sc.Scan() {
		var l line
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			panic(err)
		}
		got, err := h.call(ctx, []byte(l.Call))
		if err != nil {
			panic(err)
		}
		total++
		if got == l.Answer {
			same++
		} else if total-same <= 5 {
			fmt.Printf("differs: call=%.120s\n  js=%s\n  go=%s\n", l.Call, l.Answer, got)
		}
	}
	replayDur := time.Since(t1)

	// Trap, then a fresh instance must answer again (item 3).
	_, trapErr := h.call(ctx, []byte(`{"op":"trap","input":{}}`))
	_ = h.mod.Close(ctx)
	h2, err := newHost(ctx, rt, compiled)
	if err != nil {
		panic(err)
	}
	after, err := h2.call(ctx, []byte(`{"op":"nope","input":{}}`))

	fmt.Printf("{\"compile_ms\":%.1f,\"replayed\":%d,\"identical\":%d,\"replay_ms\":%d,\"trap_error\":%q,\"after_trap\":%q,\"after_trap_err\":%v}\n",
		float64(compileDur.Microseconds())/1000, total, same, replayDur.Milliseconds(), fmt.Sprint(trapErr != nil), after, err)
	if same != total {
		os.Exit(1)
	}
}
