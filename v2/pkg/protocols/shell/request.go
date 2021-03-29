package shell

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

var _ protocols.Request = &Request{}

func (r *Request) ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {

	cmd := exec.Command(r.Command, r.Args...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	//TODO: stdin option
	// Run command
	gologger.Verbose().Msgf("[%s] Executing SHELL command %s", r.options.TemplateID, cmd.Path+" "+strings.Join(cmd.Args[1:], " "))
	if err := cmd.Start(); err != nil {
		return errors.Wrap(err, "Command execution failed")
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(stdout)
	buf.ReadFrom(stderr)
	if err := cmd.Wait(); err != nil {
		return errors.Wrap(err, "Error while waiting for command to exit")
	}
	cmdStr := buf.String()
	gologger.Verbose().Msgf("[%s] SHELL command output: %s", r.options.TemplateID, cmdStr)
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
