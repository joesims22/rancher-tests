package keycloak

import (
	"fmt"
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	v3 "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/extensions/clusters"
	"github.com/rancher/shepherd/pkg/config"
	"github.com/rancher/shepherd/pkg/session"
	authactions "github.com/rancher/tests/actions/auth"
	rbacapi "github.com/rancher/tests/actions/kubeapi/rbac"
	projectsapi "github.com/rancher/tests/actions/kubeapi/projects"
	"github.com/rancher/shepherd/clients/rancher/auth/keycloak"
	"github.com/rancher/tests/actions/rbac"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type KeycloakAuthProviderSuite struct {
	suite.Suite
	session *session.Session
	client  *rancher.Client
	cluster *v3.Cluster
	adminUser  *v3.User
	authConfig *authactions.AuthConfig
	// keycloakConfig *v3.KeycloakConfig
}

func (k *KeycloakAuthProviderSuite) SetupSuite() {
	k.session = session.NewSession()

	client, err := rancher.NewClient("", k.session)
	require.NoError(k.T(), err, "Failed to create Rancher client")
	k.client = client

	logrus.Info("Loading auth configuration from config file")
	k.authConfig = new(authactions.AuthConfig)
	config.LoadConfig(authactions.KeycloakAuthInput, k.authConfig)
	require.NotNil(k.T(), k.authConfig, "Auth configuration is not provided")

	logrus.Info("Getting cluster name from the config file")
	clusterName := client.RancherConfig.ClusterName
	require.NotEmpty(k.T(), clusterName, "Cluster name should be set")

	clusterID, err := clusters.GetClusterIDByName(k.client, clusterName)
	require.NoError(k.T(), err, "Error getting cluster ID for cluster: %s", clusterName)

	k.cluster, err = k.client.Management.Cluster.ByID(clusterID)
	require.NoError(k.T(), err, "Failed to retrieve cluster by ID: %s", clusterID)

	logrus.Info("Setting up admin user credentials for Keycloak authentication")
	k.adminUser = &v3.User{
		Username: k.client.Auth.Keycloak.Config.Users.Admin.Username,
		Password: k.client.Auth.Keycloak.Config.Users.Admin.Password,
	}
}

func (k *KeycloakAuthProviderSuite) TearDownSuite() {
	if k.client != nil {
		keycloakConfig, err := k.client.Management.AuthConfig.ByID(authactions.Keycloak)
		if err == nil && keycloakConfig.Enabled {
			logrus.Info("Disabling Keycloak authentication after test suite")
			err := k.client.Auth.Keycloak.Disable()
			if err != nil {
				logrus.WithError(err).Warn("Failed to disable Keycloak in teardown")
			}
		}
	}
	k.session.Cleanup()
}

func (k *KeycloakAuthProviderSuite) TestKeycloakEnableProvider() {
	subSession := k.session.NewSession()
	defer subSession.Cleanup()

	provider, err := keycloak.NewKeycloak(k.client.Management, k.session)
	require.NoError(k.T(), err, "Failed to initialize Keycloak Shepherd client")

	err = provider.Enable()
	require.NoError(k.T(), err, "Failed to enable Keycloak")

	keycloakConfig, err := k.client.Management.AuthConfig.ByID(authactions.Keycloak)
	require.NoError(k.T(), err, "Failed to retrieve Keycloak config")
	require.True(k.T(), keycloakConfig.Enabled, "Keycloak should be enabled")
	require.Equal(k.T(), "keyCloakConfig", keycloakConfig.Type, "AuthConfig type should be keyCloakConfig")

	log.Info("Keycloak config is successfully enabled!")

	log.Info("Attempt to login as keycloak admin user")
	token, err := provider.Login(k.client.Auth.Keycloak.Config.Users.Admin.Username, k.client.Auth.Keycloak.Config.Users.Admin.Password)
	require.NoError(k.T(), err)
	assert.NotEmpty(k.T(), token, "Login failed")
}

func (k *KeycloakAuthProviderSuite) TestKeycloakAllowClusterAndProjectMembersAccessMode() {
	subSession := k.session.NewSession()
	defer subSession.Cleanup()

	provider, err := keycloak.NewKeycloak(k.client.Management, k.session)
	require.NoError(k.T(), err, "Failed to initialize Keycloak Shepherd client")

	err = provider.Enable()
	require.NoError(k.T(), err, "Failed to enable Keycloak")

	projectResp, _, err := projectsapi.CreateProjectAndNamespace(k.client, k.cluster.ID)
	require.NoError(k.T(), err, "Failed to create project")

	prtbNamespace := projectResp.Name
	if projectResp.Status.BackingNamespace != "" {
		prtbNamespace = projectResp.Status.BackingNamespace
	}
	projectName := fmt.Sprintf("%s:%s", projectResp.Namespace, projectResp.Name)

	groupPRTBResp, err := rbacapi.CreateGroupProjectRoleTemplateBinding(k.client, projectName, prtbNamespace, "keycloak_group://testgroup1", rbac.ProjectOwner.String())
	require.NoError(k.T(), err, "Failed to create PRTB")
	require.NotNil(k.T(), groupPRTBResp, "PRTB should be created")

	provider.Config.AccessMode = authactions.AccessModeRestricted
	allowedPrincipalIDs := provider.Config.AllowedPrincipalIDs
	allowedPrincipalIDs = append(allowedPrincipalIDs, "keycloak_user://admin-test")


    _ = provider.UpdateAccessMode(authactions.AccessModeRestricted, allowedPrincipalIDs)
    require.NoError(k.T(), err, "Failed to update Keycloak access mode safely")
   

	allowedUsers := []authactions.User{
        {Username: k.adminUser.Username, Password: k.adminUser.Password},
        {Username: "testuser1", Password: "password"}, 
    }

	for _, user := range allowedUsers {
		logrus.Info("Testing restricted access mode: Logging in as Keycloak user: ", user.Username)
		token, err := provider.Login(user.Username, user.Password)
		require.NoError(k.T(), err, "Allowed user %s should be able to login in restricted access mode", user.Username)
		require.NotEmpty(k.T(), token, "Expected a valid R_SESS token for user %s", user.Username)
	}
	
	deniedUser := authactions.User{
		Username: "testuser6",
		Password: "password",
	}

	logrus.Info("Testing restricted access mode: Logging in as Keycloak user that is not allowed: ", deniedUser.Username)
	token, err := provider.Login(deniedUser.Username, deniedUser.Password)
	require.Error(k.T(), err, "User %s should not be able to login in restricted access mode", deniedUser.Username)
	require.Empty(k.T(), token, "Token should be empty for denied user %s", deniedUser.Username)
}

func (k *KeycloakAuthProviderSuite) TestKeycloakRequiredAccessMode() {
	subSession := k.session.NewSession()
	defer subSession.Cleanup()

	provider, err := keycloak.NewKeycloak(k.client.Management, k.session)
	require.NoError(k.T(), err, "Failed to initialize Keycloak Shepherd client")

	err = provider.Enable()
	require.NoError(k.T(), err, "Failed to enable Keycloak")

	provider.Config.AccessMode = authactions.AccessModeRequired
	allowedPrincipalIDs := provider.Config.AllowedPrincipalIDs
	allowedPrincipalIDs = append(allowedPrincipalIDs, "keycloak_user://admin-test", "keycloak_group://testgroup1")
	newAuthConfig, err := authactions.UpdateAccessMode(k.client, authactions.Keycloak, authactions.AccessModeRequired, allowedPrincipalIDs)
	require.NoError(k.T(), err, "Failed to update access mode")
	require.Equal(k.T(), authactions.AccessModeRequired, newAuthConfig.AccessMode, "Access mode should be required")

	adminUser := authactions.User{
		Username: k.client.Auth.Keycloak.Config.Users.Admin.Username,
		Password: k.client.Auth.Keycloak.Config.Users.Admin.Password,
	}

	allowedUsers := []authactions.User{
        {Username: adminUser.Username, Password: adminUser.Password},
        {Username: "testuser1", Password: "password"}, 
    }

	for _, user := range allowedUsers {
		logrus.Info("Testing required access mode: Logging in as an allowed Keycloak user:", user.Username)
		token, err := provider.Login(user.Username, user.Password)
		require.NoError(k.T(), err, "User %s should be able to login in required access mode", user.Username)
		require.NotEmpty(k.T(), token, "Expected a valid R_SESS token for user %s", user.Username)
	}
	
	deniedUser := authactions.User{
		Username: "testuser6",
		Password: "password",
	}

	logrus.Info("Testing required access mode: Logging in as Keycloak user that is not allowed: ", deniedUser.Username)
	token, err := provider.Login(deniedUser.Username, deniedUser.Password)
	require.Error(k.T(), err, "User %s should not be able to login in required access mode", deniedUser.Username)
	require.Empty(k.T(), token, "Token should be empty for denied user %s", deniedUser.Username)
}

func (k *KeycloakAuthProviderSuite) TestKeycloakDisableAndEnableProvider() {
	subSession := k.session.NewSession()
	defer subSession.Cleanup()

	provider, err := keycloak.NewKeycloak(k.client.Management, k.session)
	require.NoError(k.T(), err, "Failed to initialize Keycloak Shepherd client")

	err = provider.Enable()
	require.NoError(k.T(), err, "Failed to enable Keycloak")

	log.Info("Attempt to login as keycloak admin user")
	token, err := provider.Login(k.client.Auth.Keycloak.Config.Users.Admin.Username, k.client.Auth.Keycloak.Config.Users.Admin.Password)
	require.NoError(k.T(), err)
	assert.NotEmpty(k.T(), token, "Login failed")
	log.Info(token)

	keycloakSecret, err := k.client.WranglerContext.Core.Secret().Get("cattle-global-data", authactions.KeycloakPasswordSecretID, metav1.GetOptions{})
	require.NoError(k.T(), err, "Expected secret created for Keycloak")
	require.NotEmpty(k.T(), keycloakSecret.Data, "Expected secret data to be populated for Keycloak")

	err = provider.Disable()
	require.NoError(k.T(), err, "Failed to disable Keycloak")

	keycloakConfig, err := k.client.Management.AuthConfig.ByID(authactions.Keycloak)
	require.NoError(k.T(), err, "Failed to retrieve Keycloak config")
	require.False(k.T(), keycloakConfig.Enabled, "Keycloak should be disabled")
	_, err = k.client.WranglerContext.Core.Secret().Get("cattle-global-data", authactions.KeycloakPasswordSecretID, metav1.GetOptions{})
	require.Error(k.T(), err, "Expected secret created for Keycloak to be deleted upon disabling Keycloak")

	log.Info("Keycloak config is successfully disabled!")

	err = provider.Enable()
	require.NoError(k.T(), err, "Failed to re-enable Keycloak")

	keycloakConfig, err = k.client.Management.AuthConfig.ByID(authactions.Keycloak)
	require.NoError(k.T(), err, "Failed to retrieve Keycloak config after re-enabling")
	require.True(k.T(), keycloakConfig.Enabled, "Keycloak should be enabled after re-enabling")
}

func TestKeycloakAuthProviderSuite(t *testing.T) {
	suite.Run(t, new(KeycloakAuthProviderSuite))
}
