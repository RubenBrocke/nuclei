package shell

import (
	"os/exec"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline"`

	ID string `yaml:"id"`

	// The command to execute
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`

	CompiledOperators *operators.Operators

	// cache any variables that may be needed for operation.
	options *protocols.ExecuterOptions
}

// GetID returns the unique ID of the request if any.
func (r *Request) GetID() string {
	return r.ID
}

// Compile compiles the protocol request for further execution.
func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	// Compile matchers and extractors
	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		r.CompiledOperators = compiled
	}

	r.options = options

	// Check if the given command exists
	if _, err := exec.LookPath(r.Command); err != nil {
		return errors.Wrap(err, "Given command not found")
	}

	// Replace template variables
	for i, arg := range r.Args {
		r.Args[i] = strings.ReplaceAll(arg, "{{BaseUrl}}", options.Options.Target)
	}

	return nil
}

// Requests returns the total number of requests the YAML rule will perform
func (r *Request) Requests() int {
	return 1
}
