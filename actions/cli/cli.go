package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

const (
	configDirectoryEnvironment = "RANCHER_CLI_CONFIG_DIR"
	credentialStoreEnvironment = "RANCHER_CLI_CREDENTIAL_STORE"
	fileCredentialStore        = "file"
	rancherBinary              = "rancher"
)

// Result contains the output and exit status from a Rancher CLI command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// RunOptions contains per-command input and environment variables.
type RunOptions struct {
	Stdin       string
	Environment map[string]string
}

// ExitError reports a non-zero Rancher CLI exit code without exposing command arguments.
type ExitError struct {
	ExitCode int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("rancher command exited with code %d", e.ExitCode)
}

// Runner executes an installed Rancher CLI with isolated configuration and credentials.
type Runner struct {
	binaryPath      string
	configDirectory string
}

// NewRunner resolves the installed Rancher CLI and returns an isolated command runner.
func NewRunner(configDirectory string) (*Runner, error) {
	binaryPath, err := exec.LookPath(rancherBinary)
	if err != nil {
		return nil, fmt.Errorf("Rancher CLI binary %q was not found in PATH: %w", rancherBinary, err)
	}

	return newRunner(binaryPath, configDirectory)
}

func newRunner(binaryPath, configDirectory string) (*Runner, error) {
	if strings.TrimSpace(binaryPath) == "" {
		return nil, errors.New("Rancher CLI binary path is required")
	}
	if strings.TrimSpace(configDirectory) == "" {
		return nil, errors.New("Rancher CLI config directory is required")
	}

	return &Runner{
		binaryPath:      binaryPath,
		configDirectory: configDirectory,
	}, nil
}

// Run executes a Rancher CLI command and captures stdout, stderr, and its exit code.
func (r *Runner) Run(ctx context.Context, options RunOptions, args ...string) (Result, error) {
	command := exec.CommandContext(ctx, r.binaryPath, args...)
	command.Stdin = strings.NewReader(options.Stdin)
	command.Env = commandEnvironment(options.Environment, r.configDirectory)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Run()
	result := Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: 0,
	}
	if err == nil {
		return result, nil
	}

	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, &ExitError{ExitCode: result.ExitCode}
	}

	return result, fmt.Errorf("failed to execute Rancher CLI: %w", err)
}

func commandEnvironment(overrides map[string]string, configDirectory string) []string {
	environment := make(map[string]string, len(os.Environ())+len(overrides)+2)
	for _, variable := range os.Environ() {
		key, value, found := strings.Cut(variable, "=")
		if found {
			environment[key] = value
		}
	}
	for key, value := range overrides {
		environment[key] = value
	}

	environment[configDirectoryEnvironment] = configDirectory
	environment[credentialStoreEnvironment] = fileCredentialStore

	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	variables := make([]string, 0, len(keys))
	for _, key := range keys {
		variables = append(variables, key+"="+environment[key])
	}

	return variables
}
