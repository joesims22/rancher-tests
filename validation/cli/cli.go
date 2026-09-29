//go:build validation

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/extensions/defaults"
	extnamespaceapi "github.com/rancher/shepherd/extensions/kubeapi/namespaces"
	extprojectapi "github.com/rancher/shepherd/extensions/kubeapi/projects"
	"github.com/rancher/shepherd/pkg/session"
	actioncli "github.com/rancher/tests/actions/cli"
	namespaceapi "github.com/rancher/tests/actions/kubeapi/namespaces"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kwait "k8s.io/apimachinery/pkg/util/wait"
)

const (
	jsonOutput              = "json"
	localClusterID          = "local"
	rancherCLIAPIVersion    = "cli.rancher.io/v1"
	notFoundExitCode        = 4
	rbacFailureExitCode     = 6
	tlsTrustFailureExitCode = 10
	accessDeniedExitCode    = 12
)

type commandEnvelope struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Data       json.RawMessage `json:"data"`
	Warnings   []interface{}   `json:"warnings"`
}

type cliIdentity struct {
	name            string
	configDirectory string
	runner          *actioncli.Runner
}

func newCLIIdentity(rancherConfig *rancher.Config, name, token string) (*cliIdentity, error) {
	configDirectory, err := os.MkdirTemp("", "rancher-cli-test-"+name+"-")
	if err != nil {
		return nil, fmt.Errorf("failed to create isolated Rancher CLI config directory: %w", err)
	}

	identity := &cliIdentity{
		name:            name,
		configDirectory: configDirectory,
	}

	runner, err := actioncli.NewRunner(configDirectory)
	if err != nil {
		identity.Close()
		return nil, err
	}
	identity.runner = runner

	loginArgs := []string{"auth", "login", name, "--url", rancherServerURL(rancherConfig.Host), "--token-stdin", "-o", jsonOutput}
	caFile, err := writeCACert(configDirectory, rancherConfig)
	if err != nil {
		identity.Close()
		return nil, err
	}
	if caFile != "" {
		loginArgs = append(loginArgs, "--cacert", caFile)
	}

	_, err = runner.Run(context.Background(), actioncli.RunOptions{Stdin: token + "\n"}, loginArgs...)
	if err != nil {
		identity.Close()
		var exitError *actioncli.ExitError
		if errors.As(err, &exitError) && exitError.ExitCode == tlsTrustFailureExitCode {
			return nil, fmt.Errorf("Rancher CLI could not verify the server certificate; configure rancher.caCerts: %w", err)
		}
		return nil, fmt.Errorf("failed to log in Rancher CLI identity %q: %w", name, err)
	}

	return identity, nil
}

func (c *cliIdentity) Close() error {
	if c == nil || c.configDirectory == "" {
		return nil
	}
	return os.RemoveAll(c.configDirectory)
}

func (c *cliIdentity) run(ctx context.Context, args ...string) (actioncli.Result, error) {
	return c.runner.Run(ctx, actioncli.RunOptions{}, args...)
}

func (c *cliIdentity) runJSON(ctx context.Context, args ...string) (commandEnvelope, actioncli.Result, error) {
	args = append(args, "-o", jsonOutput)
	result, err := c.run(ctx, args...)
	if err != nil {
		return commandEnvelope{}, result, err
	}

	var envelope commandEnvelope
	if err := json.Unmarshal([]byte(result.Stdout), &envelope); err != nil {
		return commandEnvelope{}, result, fmt.Errorf("failed to decode Rancher CLI JSON output: %w", err)
	}
	if envelope.APIVersion != rancherCLIAPIVersion {
		return commandEnvelope{}, result, fmt.Errorf("unexpected Rancher CLI API version %q", envelope.APIVersion)
	}

	return envelope, result, nil
}

func rancherServerURL(host string) string {
	if strings.HasPrefix(host, "https://") || strings.HasPrefix(host, "http://") {
		return host
	}
	return "https://" + host
}

func writeCACert(configDirectory string, rancherConfig *rancher.Config) (string, error) {
	if rancherConfig.CAFile != "" {
		return rancherConfig.CAFile, nil
	}
	if strings.TrimSpace(rancherConfig.CACerts) == "" {
		return "", nil
	}

	caFile := filepath.Join(configDirectory, "ca.pem")
	if err := os.WriteFile(caFile, []byte(rancherConfig.CACerts), 0o600); err != nil {
		return "", fmt.Errorf("failed to write Rancher CA certificate: %w", err)
	}
	return caFile, nil
}

func waitForProject(client *rancher.Client, projectName string) (*v3.Project, error) {
	var project *v3.Project
	err := kwait.PollUntilContextTimeout(context.Background(), defaults.FiveSecondTimeout, defaults.OneMinuteTimeout, true, func(ctx context.Context) (bool, error) {
		var getErr error
		project, getErr = extprojectapi.GetProjectByName(client, localClusterID, projectName)
		if k8serrors.IsNotFound(getErr) {
			return false, nil
		}
		return getErr == nil, getErr
	})
	return project, err
}

func waitForProjectDeletion(client *rancher.Client, projectName string) error {
	return kwait.PollUntilContextTimeout(context.Background(), defaults.FiveSecondTimeout, defaults.OneMinuteTimeout, true, func(ctx context.Context) (bool, error) {
		_, err := extprojectapi.GetProjectByName(client, localClusterID, projectName)
		if k8serrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
}

func waitForNamespace(client *rancher.Client, namespaceName string) (*corev1.Namespace, error) {
	var namespace *corev1.Namespace
	err := kwait.PollUntilContextTimeout(context.Background(), defaults.FiveSecondTimeout, defaults.OneMinuteTimeout, true, func(ctx context.Context) (bool, error) {
		var getErr error
		namespace, getErr = extnamespaceapi.GetNamespaceByName(client, localClusterID, namespaceName)
		if k8serrors.IsNotFound(getErr) {
			return false, nil
		}
		return getErr == nil, getErr
	})
	return namespace, err
}

func waitForNamespaceDeletion(client *rancher.Client, namespaceName string) error {
	return kwait.PollUntilContextTimeout(context.Background(), defaults.FiveSecondTimeout, defaults.OneMinuteTimeout, true, func(ctx context.Context) (bool, error) {
		_, err := extnamespaceapi.GetNamespaceByName(client, localClusterID, namespaceName)
		if k8serrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
}

func waitForNamespaceProject(client *rancher.Client, namespaceName, projectName string) error {
	expectedProjectID := ""
	if projectName != "" {
		expectedProjectID = localClusterID + ":" + projectName
	}

	return kwait.PollUntilContextTimeout(context.Background(), defaults.FiveSecondTimeout, defaults.OneMinuteTimeout, true, func(ctx context.Context) (bool, error) {
		namespace, err := extnamespaceapi.GetNamespaceByName(client, localClusterID, namespaceName)
		if err != nil {
			return false, err
		}
		return namespace.Annotations[namespaceapi.ProjectIDAnnotation] == expectedProjectID, nil
	})
}

func registerProjectCleanup(testSession *session.Session, client *rancher.Client, projectName string) {
	testSession.RegisterCleanupFunc(func() error {
		_, err := extprojectapi.GetProjectByName(client, localClusterID, projectName)
		if k8serrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return extprojectapi.DeleteProject(client, localClusterID, projectName, true)
	})
}

func registerNamespaceCleanup(testSession *session.Session, client *rancher.Client, namespaceName string) {
	testSession.RegisterCleanupFunc(func() error {
		_, err := extnamespaceapi.GetNamespaceByName(client, localClusterID, namespaceName)
		if k8serrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return extnamespaceapi.DeleteNamespace(client, localClusterID, namespaceName, true)
	})
}

func getProject(client *rancher.Client, projectName string) (*v3.Project, error) {
	return client.WranglerContext.Mgmt.Project().Get(localClusterID, projectName, metav1.GetOptions{})
}
