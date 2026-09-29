//go:build validation

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/clients/rancher/auth"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/extensions/users"
	shepherdconfig "github.com/rancher/shepherd/pkg/config"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	"github.com/rancher/shepherd/pkg/session"
	actioncli "github.com/rancher/tests/actions/cli"
	projectapi "github.com/rancher/tests/actions/kubeapi/projects"
	rbacapi "github.com/rancher/tests/actions/kubeapi/rbac"
	"github.com/rancher/tests/actions/rbac"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type CLITestSuite struct {
	suite.Suite
	client          *rancher.Client
	session         *session.Session
	adminCLI        *cliIdentity
	standardUserCLI *cliIdentity
	standardUser    *management.User
}

func (c *CLITestSuite) TearDownSuite() {
	if c.adminCLI != nil {
		if err := c.adminCLI.Close(); err != nil {
			c.T().Error(err)
		}
	}
	if c.standardUserCLI != nil {
		if err := c.standardUserCLI.Close(); err != nil {
			c.T().Error(err)
		}
	}
	if c.session != nil {
		c.session.Cleanup()
	}
}

func (c *CLITestSuite) SetupSuite() {
	c.session = session.NewSession()

	rancherConfig := new(rancher.Config)
	shepherdconfig.LoadConfig(rancher.ConfigurationFileKey, rancherConfig)
	rancherConfig.RancherCLI = false

	client, err := rancher.NewClientForConfig("", rancherConfig, c.session)
	require.NoError(c.T(), err)
	c.client = client

	adminToken, err := c.client.Management.Token.Create(&management.Token{
		Description: "new Rancher CLI admin test token",
		UserID:      c.client.UserID,
	})
	require.NoError(c.T(), err)
	require.NotEmpty(c.T(), adminToken.Token)
	c.adminCLI, err = newCLIIdentity(rancherConfig, "admin-test", adminToken.Token)
	require.NoError(c.T(), err)

	userConfig := users.UserConfig()
	standardUser, err := users.CreateUserWithRole(c.client, userConfig, rbac.StandardUser.String())
	require.NoError(c.T(), err)
	c.standardUser = standardUser

	_, err = rbacapi.CreateClusterRoleTemplateBinding(c.client, localClusterID, standardUser.ID, rbac.ClusterMember.String())
	require.NoError(c.T(), err)

	standardUserClient, err := c.client.AsAuthUser(standardUser, auth.LocalAuth)
	require.NoError(c.T(), err)
	standardUserClient, err = standardUserClient.ReLoginForConfig(rancherConfig)
	require.NoError(c.T(), err)

	standardUserToken, err := standardUserClient.Management.Token.Create(&management.Token{
		Description: "new Rancher CLI standard-user test token",
		UserID:      standardUserClient.UserID,
	})
	require.NoError(c.T(), err)
	require.NotEmpty(c.T(), standardUserToken.Token)
	c.standardUserCLI, err = newCLIIdentity(rancherConfig, "standard-user-test", standardUserToken.Token)
	require.NoError(c.T(), err)
}

func (c *CLITestSuite) TestSchemaAndConfiguration() {
	schema, _, err := c.adminCLI.runJSON(context.Background(), "schema")
	require.NoError(c.T(), err)
	require.Equal(c.T(), "SchemaManifest", schema.Kind)
	require.Contains(c.T(), string(schema.Data), "access can")
	require.Contains(c.T(), string(schema.Data), "config status")
	require.Contains(c.T(), string(schema.Data), "create project")

	pathResult, err := c.adminCLI.run(context.Background(), "config", "path")
	require.NoError(c.T(), err)
	require.Contains(c.T(), pathResult.Stdout, c.adminCLI.configDirectory)

	servers, _, err := c.adminCLI.runJSON(context.Background(), "config", "list-servers")
	require.NoError(c.T(), err)
	require.NotEmpty(c.T(), servers.Data)
	require.Contains(c.T(), string(servers.Data), c.adminCLI.name)

	status, _, err := c.adminCLI.runJSON(context.Background(), "config", "status")
	require.NoError(c.T(), err)
	require.NotEmpty(c.T(), status.Data)
}

func (c *CLITestSuite) TestAuthentication() {
	testCases := []struct {
		name             string
		identity         *cliIdentity
		expectedUsername string
	}{
		{name: "admin", identity: c.adminCLI, expectedUsername: "admin"},
		{name: "standard user", identity: c.standardUserCLI, expectedUsername: c.standardUser.Username},
	}

	for _, testCase := range testCases {
		c.Run(testCase.name, func() {
			status, _, err := testCase.identity.runJSON(context.Background(), "auth", "status")
			require.NoError(c.T(), err)
			require.Equal(c.T(), "AuthCheck", status.Kind)
			require.Contains(c.T(), string(status.Data), testCase.expectedUsername)
		})
	}
}

func (c *CLITestSuite) TestReadCommands() {
	testCases := [][]string{
		{"get", "cluster", localClusterID},
		{"get", "user", c.standardUser.Username},
		{"get", "setting", "server-version"},
		{"inspect", "cluster", localClusterID},
		{"inspect", "user", c.standardUser.Username},
	}

	for _, args := range testCases {
		c.Run(args[0]+" "+args[1], func() {
			envelope, _, err := c.adminCLI.runJSON(context.Background(), args...)
			require.NoError(c.T(), err)
			require.NotEmpty(c.T(), envelope.Kind)
			require.NotEmpty(c.T(), envelope.Data)
		})
	}

	kubeconfig, err := c.adminCLI.run(context.Background(), "kubeconfig", "--cluster", localClusterID)
	require.NoError(c.T(), err)
	require.Contains(c.T(), kubeconfig.Stdout, "apiVersion:")
	require.Contains(c.T(), kubeconfig.Stdout, "clusters:")
}

func (c *CLITestSuite) TestAccessCommands() {
	allowed, _, err := c.standardUserCLI.runJSON(context.Background(), "access", "can", "get", "namespaces", "--cluster", localClusterID)
	require.NoError(c.T(), err)
	require.Contains(c.T(), string(allowed.Data), "allowed")

	deniedResult, err := c.standardUserCLI.run(context.Background(), "access", "can", "delete", "nodes", "--cluster", localClusterID, "-o", jsonOutput)
	require.Error(c.T(), err)
	var exitError *actioncli.ExitError
	require.True(c.T(), errors.As(err, &exitError))
	require.Equal(c.T(), accessDeniedExitCode, exitError.ExitCode)

	var denied commandEnvelope
	require.NoError(c.T(), json.Unmarshal([]byte(deniedResult.Stdout), &denied))
	require.Contains(c.T(), string(denied.Data), "denied")

	readOnlyCommands := [][]string{
		{"access", "list", "--cluster", localClusterID, "--namespace", "default"},
		{"access", "clusters"},
		{"access", "projects", "--cluster", localClusterID},
		{"access", "who-can", "get", "namespaces", "--cluster", localClusterID},
		{"access", "explain", "get", "namespaces", "--cluster", localClusterID},
	}
	for _, args := range readOnlyCommands {
		c.Run(args[1], func() {
			envelope, _, err := c.standardUserCLI.runJSON(context.Background(), args...)
			require.NoError(c.T(), err)
			require.NotEmpty(c.T(), envelope.Data)
		})
	}
}

func (c *CLITestSuite) TestAdminProjectAndNamespaceCRUD() {
	testSession := c.session.NewSession()
	defer testSession.Cleanup()

	projectName := namegen.AppendRandomString("cli-project-")
	namespaceName := namegen.AppendRandomString("cli-namespace-")
	updatedDescription := "updated by Rancher CLI validation"

	c.T().Log("Creating and validating a project with the Rancher CLI")
	createdProject, _, err := c.adminCLI.runJSON(context.Background(), "create", "project", projectName, "--cluster", localClusterID, "--apply")
	require.NoError(c.T(), err)
	require.Equal(c.T(), "Project", createdProject.Kind)
	registerProjectCleanup(testSession, c.client, projectName)

	project, err := waitForProject(c.client, projectName)
	require.NoError(c.T(), err)
	require.Equal(c.T(), projectName, project.Spec.DisplayName)

	projectResult, _, err := c.adminCLI.runJSON(context.Background(), "get", "project", projectName, "--cluster", localClusterID)
	require.NoError(c.T(), err)
	require.Contains(c.T(), string(projectResult.Data), projectName)

	patch := fmt.Sprintf(`[{"op":"replace","path":"/spec/description","value":%q}]`, updatedDescription)
	patchedProject, _, err := c.adminCLI.runJSON(context.Background(), "patch", "project", projectName, "--cluster", localClusterID, "--patch", patch, "--apply")
	require.NoError(c.T(), err)
	require.Equal(c.T(), "Project", patchedProject.Kind)

	project, err = getProject(c.client, project.Name)
	require.NoError(c.T(), err)
	require.Equal(c.T(), updatedDescription, project.Spec.Description)

	c.T().Log("Creating a namespace and changing its project membership with the Rancher CLI")
	createdNamespace, _, err := c.adminCLI.runJSON(context.Background(), "create", "namespace", namespaceName, "--cluster", localClusterID, "--project", projectName, "--apply")
	require.NoError(c.T(), err)
	require.Equal(c.T(), "Namespace", createdNamespace.Kind)
	registerNamespaceCleanup(testSession, c.client, namespaceName)

	namespace, err := waitForNamespace(c.client, namespaceName)
	require.NoError(c.T(), err)
	require.Equal(c.T(), localClusterID+":"+project.Name, namespace.Annotations["field.cattle.io/projectId"])

	namespaceResult, _, err := c.adminCLI.runJSON(context.Background(), "get", "namespace", namespaceName, "--cluster", localClusterID)
	require.NoError(c.T(), err)
	require.Contains(c.T(), string(namespaceResult.Data), namespaceName)

	_, _, err = c.adminCLI.runJSON(context.Background(), "project", "remove-namespace", namespaceName, "--project", projectName, "--cluster", localClusterID, "--apply")
	require.NoError(c.T(), err)
	require.NoError(c.T(), waitForNamespaceProject(c.client, namespaceName, ""))

	_, _, err = c.adminCLI.runJSON(context.Background(), "project", "add-namespace", namespaceName, "--project", projectName, "--cluster", localClusterID, "--apply")
	require.NoError(c.T(), err)
	require.NoError(c.T(), waitForNamespaceProject(c.client, namespaceName, project.Name))

	c.T().Log("Deleting the namespace and project with the Rancher CLI")
	_, _, err = c.adminCLI.runJSON(context.Background(), "delete", "namespace", namespaceName, "--cluster", localClusterID, "--apply", "--yes")
	require.NoError(c.T(), err)
	require.NoError(c.T(), waitForNamespaceDeletion(c.client, namespaceName))

	_, _, err = c.adminCLI.runJSON(context.Background(), "delete", "project", projectName, "--cluster", localClusterID, "--apply", "--yes")
	require.NoError(c.T(), err)
	require.NoError(c.T(), waitForProjectDeletion(c.client, project.Name))
}

func (c *CLITestSuite) TestStandardUserNamespaceCRUD() {
	testSession := c.session.NewSession()
	defer testSession.Cleanup()

	project, err := projectapi.CreateProject(c.client, localClusterID)
	require.NoError(c.T(), err)
	_, err = rbacapi.CreateProjectRoleTemplateBinding(c.client, c.standardUser.ID, project, rbac.ProjectOwner.String())
	require.NoError(c.T(), err)

	c.T().Log("Creating and deleting a namespace as a standard project owner")
	namespaceName := namegen.AppendRandomString("standard-cli-namespace-")
	createdNamespace, _, err := c.standardUserCLI.runJSON(context.Background(), "create", "namespace", namespaceName, "--cluster", localClusterID, "--project", project.Name, "--apply")
	require.NoError(c.T(), err)
	require.Equal(c.T(), "Namespace", createdNamespace.Kind)
	registerNamespaceCleanup(testSession, c.client, namespaceName)

	_, err = waitForNamespace(c.client, namespaceName)
	require.NoError(c.T(), err)
	getNamespace, _, err := c.standardUserCLI.runJSON(context.Background(), "get", "namespace", namespaceName, "--cluster", localClusterID)
	require.NoError(c.T(), err)
	require.Contains(c.T(), string(getNamespace.Data), namespaceName)

	_, _, err = c.standardUserCLI.runJSON(context.Background(), "delete", "namespace", namespaceName, "--cluster", localClusterID, "--apply", "--yes")
	require.NoError(c.T(), err)
	require.NoError(c.T(), waitForNamespaceDeletion(c.client, namespaceName))

	c.T().Log("Verifying the standard user cannot mutate a project outside its scope")
	outOfScopeProject, err := projectapi.CreateProject(c.client, localClusterID)
	require.NoError(c.T(), err)
	deniedNamespaceName := namegen.AppendRandomString("denied-cli-namespace-")
	deniedResult, deniedErr := c.standardUserCLI.run(context.Background(), "create", "namespace", deniedNamespaceName, "--cluster", localClusterID, "--project", outOfScopeProject.Name, "--apply", "-o", jsonOutput)
	require.Error(c.T(), deniedErr)
	var exitError *actioncli.ExitError
	require.True(c.T(), errors.As(deniedErr, &exitError))
	require.Contains(c.T(), []int{notFoundExitCode, rbacFailureExitCode}, exitError.ExitCode)
	require.Contains(c.T(), deniedResult.Stdout, `"kind":"Error"`)
}

func TestCLITestSuite(t *testing.T) {
	suite.Run(t, new(CLITestSuite))
}
