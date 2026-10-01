// Package scanner defines the plugin contract every SAST engine implements and
// a registry for looking them up. Adding an engine means implementing Scanner
// and registering it — no changes to the orchestrator.
package scanner

import (
	"context"
	"fmt"
	"sort"
)

// Target is the code under analysis.
type Target struct {
	// Path is the absolute path to the checked-out source tree.
	Path string
	// Languages detected in the tree (lowercase, e.g. "python", "go"). Empty
	// means "unknown / let the tool decide".
	Languages []string
}

// RawResult is a tool's native output plus metadata, before normalization.
type RawResult struct {
	Tool     string
	Format   string // "sarif" in Phase 0
	Data     []byte
	ExitCode int
	Stderr   string
}

// ScannerMeta describes an engine, including the license facts the policy layer
// gates on.
type ScannerMeta struct {
	ID             string
	License        string
	CommercialSafe bool
	Languages      []string
	Image          string
}

// Scanner wraps one underlying SAST engine.
type Scanner interface {
	ID() string
	Meta() ScannerMeta
	// Applicable reports whether this engine handles anything in the target.
	Applicable(t Target) bool
	// Run executes the engine and returns its native (raw) output.
	Run(ctx context.Context, t Target) (RawResult, error)
}

// Registry holds the available scanners.
type Registry struct {
	scanners map[string]Scanner
}

func NewRegistry() *Registry {
	return &Registry{scanners: map[string]Scanner{}}
}

func (r *Registry) Register(s Scanner) error {
	id := s.ID()
	if _, exists := r.scanners[id]; exists {
		return fmt.Errorf("scanner %q already registered", id)
	}
	r.scanners[id] = s
	return nil
}

func (r *Registry) Get(id string) (Scanner, bool) {
	s, ok := r.scanners[id]
	return s, ok
}

// All returns the registered scanners sorted by ID for deterministic ordering.
func (r *Registry) All() []Scanner {
	out := make([]Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}
