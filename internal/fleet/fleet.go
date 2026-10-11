// Package fleet is the fleet-scan control plane (DESIGN §10/§11). It
// dispatches scans across many tenants' targets, each writing to that tenant's
// isolated Evidence Vault, so the shared vault becomes the fleet's central store
// (Option B — build on the vault we already have, not a separate bundle store).
//
// It is deliberately a SEPARATE package/binary (cmd/achilles-fleet) from the OSS
// core: the multi-tenant control plane is the natural commercial/OSS boundary, so
// keeping it separable (and routing everything through the injected Runner +
// vault.Store interface, never a cloud SDK directly) keeps that split drawable.
package fleet

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config is a fleet definition: tenants and the targets to scan for each.
type Config struct {
	Tenants []TenantSpec `yaml:"tenants"`
}

// TenantSpec is one tenant's targets + per-tenant scan defaults.
type TenantSpec struct {
	ID      string   `yaml:"id"`
	Mode    string   `yaml:"mode"`    // license mode; default "oss"
	Profile string   `yaml:"profile"` // scan profile; default "default"
	Targets []Target `yaml:"targets"` // a path string, or a git source mapping (see Target)
}

// Job is a single scan of one target for one tenant.
//
// Target is the path to scan, or — for a git source — the credential-free repo
// URL (+ "#ref") used for display and ordering. For a git source, Source is set
// and FetchingRunner swaps Target for the checkout path (and fills Commit) on
// the copy it hands to the inner runner.
type Job struct {
	Tenant  string
	Target  string
	Mode    string
	Profile string
	Source  *GitSource // nil for plain path targets
	Commit  string     // resolved sha of the checkout (set by FetchingRunner)
}

var tenantRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// LoadConfig reads and validates a fleet YAML file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fleet config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse fleet config %s: %w", path, err)
	}
	if len(c.Tenants) == 0 {
		return nil, fmt.Errorf("fleet config has no tenants")
	}
	for _, t := range c.Tenants {
		if !tenantRE.MatchString(t.ID) {
			return nil, fmt.Errorf("invalid tenant id %q (must match %s)", t.ID, tenantRE)
		}
		for i, tgt := range t.Targets {
			if err := tgt.Validate(); err != nil {
				return nil, fmt.Errorf("tenant %q target #%d: %w", t.ID, i+1, err)
			}
		}
	}
	return &c, nil
}

// Plan expands the config into the flat list of scan jobs, applying per-tenant
// defaults (mode=oss, profile=default). Order is stable (tenant, then target).
func (c *Config) Plan() []Job {
	var jobs []Job
	for _, t := range c.Tenants {
		mode, profile := t.Mode, t.Profile
		if mode == "" {
			mode = "oss"
		}
		if profile == "" {
			profile = "default"
		}
		for _, tgt := range t.Targets {
			jobs = append(jobs, Job{Tenant: t.ID, Target: tgt.Label(), Mode: mode, Profile: profile, Source: tgt.Git})
		}
	}
	return jobs
}

// Result is the outcome of one job.
type Result struct {
	Job    Job
	Err    error  // non-nil if the scan failed to run
	Detail string // stderr tail / message
}

// Runner scans one job, writing findings to the job's tenant vault. Injected so
// the dispatcher is testable and the transport (subprocess CLI, in-process, …)
// stays swappable.
type Runner interface {
	Scan(ctx context.Context, j Job) Result
}

// Summary tallies a fleet dispatch.
type Summary struct {
	Total     int
	Succeeded int
	Failed    int
	Results   []Result // sorted by tenant, then target
}

// Dispatch runs all jobs over a bounded worker pool (default min(numCPU, N)) and
// returns a summary. Each job is independent; one failing never aborts the fleet.
func Dispatch(ctx context.Context, jobs []Job, r Runner, concurrency int) Summary {
	sum := Summary{Total: len(jobs)}
	if len(jobs) == 0 {
		return sum
	}
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}
	if concurrency > len(jobs) {
		concurrency = len(jobs)
	}

	in := make(chan Job)
	out := make(chan Result)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range in {
				out <- r.Scan(ctx, j)
			}
		}()
	}
	go func() {
		for _, j := range jobs {
			in <- j
		}
		close(in)
		wg.Wait()
		close(out)
	}()

	for res := range out {
		sum.Results = append(sum.Results, res)
		if res.Err != nil {
			sum.Failed++
		} else {
			sum.Succeeded++
		}
	}
	sort.Slice(sum.Results, func(i, j int) bool {
		a, b := sum.Results[i].Job, sum.Results[j].Job
		if a.Tenant != b.Tenant {
			return a.Tenant < b.Tenant
		}
		return a.Target < b.Target
	})
	return sum
}
