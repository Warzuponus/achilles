package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ModelRouting is a per-task LLM model-routing config (--model-config). It lets
// an operator route each pipeline step to a different model/endpoint — e.g. a
// cheap model for triage, a stronger one for the judge and remediation.
//
// Task keys match the router task names used by the pipeline ("triage",
// "judge", "remediation"); unknown keys are accepted so steps added later
// (e.g. "review", "sca") can be pre-configured without a code change.
type ModelRouting struct {
	Tasks map[string]TaskModel `yaml:"tasks"`
}

// TaskModel overrides the model (and optionally the endpoint) for one task.
type TaskModel struct {
	Model   string `yaml:"model"`
	BaseURL string `yaml:"baseURL,omitempty"`
}

// LoadModelRouting reads a model-routing YAML file.
func LoadModelRouting(path string) (ModelRouting, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ModelRouting{}, fmt.Errorf("read model-config: %w", err)
	}
	var m ModelRouting
	if err := yaml.Unmarshal(data, &m); err != nil {
		return ModelRouting{}, fmt.Errorf("parse model-config %s: %w", path, err)
	}
	return m, nil
}
