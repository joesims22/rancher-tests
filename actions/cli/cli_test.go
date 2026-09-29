package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunnerRun(t *testing.T) {
	testCases := []struct {
		name             string
		args             []string
		options          RunOptions
		expectedStdout   []string
		expectedStderr   string
		expectedExitCode int
	}{
		{
			name: "captures input arguments and isolated environment",
			args: []string{"get", "project", "project-a"},
			options: RunOptions{
				Stdin: "token-value",
				Environment: map[string]string{
					"CUSTOM_VALUE":             "custom",
					configDirectoryEnvironment: "ignored-config",
					credentialStoreEnvironment: "ignored-store",
				},
			},
			expectedStdout: []string{
				"args=get project project-a",
				"stdin=token-value",
				"custom=custom",
				"store=file",
			},
		},
		{
			name:             "preserves non-zero exit status and stderr",
			args:             []string{"fail"},
			expectedStderr:   "command failed\n",
			expectedExitCode: 12,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			configDirectory := t.TempDir()
			binaryPath := writeFakeRancher(t)
			runner, err := newRunner(binaryPath, configDirectory)
			require.NoError(t, err)

			result, runErr := runner.Run(context.Background(), testCase.options, testCase.args...)

			assert.Equal(t, testCase.expectedExitCode, result.ExitCode)
			assert.Equal(t, testCase.expectedStderr, result.Stderr)
			for _, expectedOutput := range testCase.expectedStdout {
				assert.Contains(t, result.Stdout, expectedOutput)
			}
			assert.Contains(t, result.Stdout, "config="+configDirectory)

			if testCase.expectedExitCode == 0 {
				require.NoError(t, runErr)
				return
			}

			var exitError *ExitError
			require.ErrorAs(t, runErr, &exitError)
			assert.Equal(t, testCase.expectedExitCode, exitError.ExitCode)
			assert.NotContains(t, runErr.Error(), strings.Join(testCase.args, " "))
		})
	}
}

func TestNewRunnerValidation(t *testing.T) {
	_, err := newRunner("", t.TempDir())
	require.EqualError(t, err, "Rancher CLI binary path is required")

	_, err = newRunner("rancher", "")
	require.EqualError(t, err, "Rancher CLI config directory is required")
}

func TestExitErrorDoesNotExposeCommandInput(t *testing.T) {
	binaryPath := writeFakeRancher(t)
	runner, err := newRunner(binaryPath, t.TempDir())
	require.NoError(t, err)

	secret := "secret-token-value"
	_, err = runner.Run(context.Background(), RunOptions{Stdin: secret}, "fail", secret)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secret)

	var exitError *ExitError
	assert.True(t, errors.As(err, &exitError))
}

func writeFakeRancher(t *testing.T) string {
	t.Helper()

	binaryPath := filepath.Join(t.TempDir(), "rancher")
	script := `#!/bin/sh
printf 'args=%s\n' "$*"
IFS= read -r input || true
printf 'stdin=%s\n' "$input"
printf 'custom=%s\n' "$CUSTOM_VALUE"
printf 'config=%s\n' "$RANCHER_CLI_CONFIG_DIR"
printf 'store=%s\n' "$RANCHER_CLI_CREDENTIAL_STORE"
if [ "$1" = "fail" ]; then
  printf 'command failed\n' >&2
  exit 12
fi
`
	require.NoError(t, os.WriteFile(binaryPath, []byte(script), 0o700))

	return binaryPath
}
