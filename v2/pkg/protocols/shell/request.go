package shell

import (
	"os/exec"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/tostring"
)

var _ protocols.Request = &Request{}

func (r *Request) ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {

	cmd := exec.Command(r.Command, r.Args...)
	//TODO: stdin option
	// Run command
	gologger.Verbose().Msgf("[%s] Executing SHELL command %s", r.options.TemplateID, cmd.Path+" "+strings.Join(cmd.Args[1:], " "))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrap(err, "Could not execute command")
	}
	gologger.Verbose().Msgf("[%s] SHELL command output: %s", r.options.TemplateID, out)
	cmdStr := tostring.UnsafeToString(out)
	outputEvent := r.responseToDSLMap(cmd, cmdStr, input, input)
	for k, v := range previous {
		outputEvent[k] = v
	}

	event := &output.InternalWrappedEvent{InternalEvent: outputEvent}
	if r.CompiledOperators != nil {
		result, ok := r.CompiledOperators.Execute(outputEvent, r.Match, r.Extract)
		if ok && result != nil {
			event.OperatorsResult = result
			event.Results = r.MakeResultEvent(event)
		}
	}
	callback(event)

	return nil
}
