// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

package pwru

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"iter"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

type Funcs map[string]int

// getAvailableFilterFunctions return list of functions to which it is possible
// to attach kprobes.
func getAvailableFilterFunctions() (map[string]struct{}, error) {
	availableFuncs := make(map[string]struct{})
	f, err := os.Open("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		return nil, fmt.Errorf("failed to open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		availableFuncs[scanner.Text()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return availableFuncs, nil
}

func sortCompact[S ~[]E, E cmp.Ordered](x S) S {
	slices.Sort(x)
	return slices.Compact(x)
}

func fileExists(filepath string) bool {
	stat, err := os.Stat(filepath)
	return err == nil && !stat.IsDir()
}

func LoadKmodBtfs(kmods []string, kmodBTFDir string) (map[string]*btf.Spec, error) {
	if kmodBTFDir == "" {
		return nil, nil
	}

	btfs := map[string]*btf.Spec{}
	if len(kmods) != 0 {
		kmods = sortCompact(kmods)
		if idx := slices.Index(kmods, "vmlinux"); idx != -1 {
			kmods = slices.Delete(kmods, idx, idx+1)
		}

		btfs = make(map[string]*btf.Spec, len(kmods))
		for _, kmod := range kmods {
			btfPath := filepath.Join(kmodBTFDir, kmod+".btf")
			if !fileExists(btfPath) {
				return nil, fmt.Errorf("split BTF file %s does not exist", btfPath)
			}

			kmodBtf, err := btf.LoadSpec(btfPath)
			if err != nil {
				if errors.Is(err, btf.ErrNotFound) {
					log.Printf("split BTF not found for %s", btfPath)
					continue
				}
				return nil, fmt.Errorf("failed to load %s: %w", btfPath, err)
			}

			btfs[kmod] = kmodBtf
		}
	} else {
		files, err := os.ReadDir(kmodBTFDir)
		if err != nil {
			return nil, fmt.Errorf("failed to read /sys/kernel/btf: %w", err)
		}

		fileNames := make([]string, 0, len(files))
		for _, file := range files {
			if file.IsDir() || file.Name() == "vmlinux" {
				continue // skip directories and vmlinux
			}
			if !strings.HasSuffix(file.Name(), ".btf") {
				continue
			}
			fileNames = append(fileNames, file.Name())
		}

		btfs = make(map[string]*btf.Spec, len(fileNames))
		for _, fileName := range fileNames {
			btfPath := filepath.Join(kmodBTFDir, fileName)

			kmodBtf, err := btf.LoadSpec(btfPath)
			if err != nil {
				if errors.Is(err, btf.ErrNotFound) {
					log.Printf("BTF not found for %s", btfPath)
					continue
				}
				return nil, fmt.Errorf("failed to load %s BTF: %w", btfPath, err)
			}

			btfs[strings.TrimSuffix(fileName, ".btf")] = kmodBtf
		}
	}

	return btfs, nil
}

func GetFuncs(pattern string, spec *btf.Spec, kmods []string, kmodBTFDir string, kprobeMulti bool) (Funcs, error) {
	funcs := Funcs{}

	type iterator struct {
		kmod string
		iter iter.Seq2[btf.Type, error]
	}

	reg, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regular expression %v", err)
	}

	var availableFuncs map[string]struct{}
	availableFuncs, err = getAvailableFilterFunctions()
	if err != nil {
		log.Printf("Failed to retrieve available ftrace functions (is /sys/kernel/debug/tracing mounted?): %s", err)
	}

	iters := []iterator{{"", spec.All()}}
	for _, module := range kmods {
		path := filepath.Join("/sys/kernel/btf", module)
		f, err := os.Open(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && kmodBTFDir != "" {
				continue
			}
			return nil, fmt.Errorf("failed to open %s: %v", path, err)
		}
		defer f.Close()

		modSpec, err := btf.LoadSplitSpecFromReader(f, spec)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s btf: %v", module, err)
		}
		iters = append(iters, iterator{module, modSpec.All()})
	}

	kmodBtfs, err := LoadKmodBtfs(kmods, kmodBTFDir)
	if err != nil {
		return nil, err
	}
	for kmod, kmodBtf := range kmodBtfs {
		iters = append(iters, iterator{kmod, kmodBtf.All()})
	}

	for _, it := range iters {
		for typ, err := range it.iter {
			if err != nil {
				return nil, fmt.Errorf("failed to iterate through btf types: %v", err)
			}

			fn, ok := typ.(*btf.Func)
			if !ok {
				continue
			}

			fnName := string(fn.Name)

			if pattern != "" && reg.FindString(fnName) != fnName {
				continue
			}

			availableFnName := fnName
			if it.kmod != "" {
				availableFnName = fmt.Sprintf("%s [%s]", fnName, it.kmod)
			}
			if _, ok := availableFuncs[availableFnName]; !ok {
				continue
			}

			fnProto := fn.Type.(*btf.FuncProto)
			i := 1
			for _, p := range fnProto.Params {
				if ptr, ok := p.Type.(*btf.Pointer); ok {
					if strct, ok := ptr.Target.(*btf.Struct); ok {
						if strct.Name == "sk_buff" && i <= 5 {
							name := fnName
							if kprobeMulti && it.kmod != "" {
								name = fmt.Sprintf("%s[%s]", fnName, it.kmod)
							}
							funcs[name] = i
							continue
						}
					}
				}
				i += 1
			}
		}
	}

	return funcs, nil
}

func GetFuncsByPos(funcs Funcs) map[int][]string {
	ret := make(map[int][]string, len(funcs))
	for fn, pos := range funcs {
		ret[pos] = append(ret[pos], fn)
	}
	return ret
}

// Very hacky way to check whether multi-link kprobe is supported.
func HaveBPFLinkKprobeMulti() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "probe_kpm_link",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceKprobeMulti,
		License:    "MIT",
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	opts := link.KprobeMultiOptions{Symbols: []string{"vprintk"}}
	link, err := link.KretprobeMulti(prog, opts)
	if err != nil {
		return false
	}
	defer link.Close()

	return true
}

// Very hacky way to check whether tracing link is supported.
func HaveBPFLinkTracing() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "fexit_skb_clone",
		Type: ebpf.Tracing,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceFExit,
		AttachTo:   "skb_clone",
		License:    "MIT",
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		return false
	}
	defer link.Close()

	return true
}

func HaveAvailableFilterFunctions() bool {
	_, err := getAvailableFilterFunctions()
	return err == nil
}

func HaveSnprintfBtf(kernelBtf *btf.Spec) bool {
	types, err := kernelBtf.AnyTypesByName("bpf_func_id")
	if err != nil {
		return false
	}

	for _, t := range types {
		if enum, ok := t.(*btf.Enum); ok {
			for _, v := range enum.Values {
				if v.Name == "BPF_FUNC_snprintf_btf" {
					return true
				}
			}
		}
	}

	return false
}
