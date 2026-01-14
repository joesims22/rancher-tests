package keycloak

import (
	// "fmt"
	// "slices"
	"testing"

	// managementv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/shepherd/clients/rancher"
	v3 "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/extensions/clusters"
	// "github.com/rancher/shepherd/extensions/users"
	"github.com/rancher/shepherd/pkg/config"
	"github.com/rancher/shepherd/pkg/session"
	authactions "github.com/rancher/tests/actions/auth"
	// projectsapi "github.com/rancher/tests/actions/kubeapi/projects"
	// krbac "github.com/rancher/tests/actions/kubeapi/rbac"
	// "github.com/rancher/tests/actions/projects"
	"github.com/rancher/shepherd/clients/rancher/auth/keycloak"
	"github.com/rancher/tests/actions/rbac"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type KeycloakAuthProviderSuite struct {
	suite.Suite
	session    *session.Session
	client     *rancher.Client
	cluster    *v3.Cluster
	adminUser  *v3.User
	authConfig *authactions.AuthConfig
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
		Username: client.Auth.OLDAP.Config.Users.Admin.Username,
		Password: client.Auth.OLDAP.Config.Users.Admin.Password,
	}

	logrus.Info("Enabling Keycloak authentication for test suite")
	err = k.client.Auth.OLDAP.Enable()
	require.NoError(k.T(), err, "Failed to enable Keycloak authentication")
}

func (k *KeycloakAuthProviderSuite) TearDownSuite() {
	if k.client != nil {
		ldapConfig, err := k.client.Management.AuthConfig.ByID(authactions.Keycloak)
		if err == nil && ldapConfig.Enabled {
			logrus.Info("Disabling Keycloak authentication after test suite")
			err := k.client.Auth.OLDAP.Disable()
			if err != nil {
				logrus.WithError(err).Warn("Failed to disable Keycloak in teardown")
			}
		}
	}
	k.session.Cleanup()
}

func (a *KeycloakAuthProviderSuite) TestKeycloakEnableProvider() {
	subSession := a.session.NewSession()
	defer subSession.Cleanup()

	err := a.client.Auth.OLDAP.Enable()
	require.NoError(a.T(), err, "Failed to enable Keycloak")

	ldapConfig, err := a.client.Management.AuthConfig.ByID(authactions.Keycloak)
	require.NoError(a.T(), err, "Failed to retrieve Keycloak config")

	require.True(a.T(), ldapConfig.Enabled, "Keycloak should be enabled")
	require.Equal(a.T(), authactions.AuthProvCleanupAnnotationValUnlocked, ldapConfig.Annotations[authactions.AuthProvCleanupAnnotationKey], "Annotation should be unlocked")

	secret, err := a.client.WranglerContext.Core.Secret().Get(
		rbac.GlobalDataNS,
		authactions.KeycloakPasswordSecretID,
		metav1.GetOptions{},
	)
	require.NoError(a.T(), err, "Failed to retrieve password secret")

	require.Equal(a.T(), a.client.Auth.OLDAP.Config.ServiceAccount.Password, string(secret.Data["serviceaccountpassword"]), "Password mismatch")
}

// func (k *KeycloakAuthProviderSuite) TestKeycloakUserLogin() {
// 	subSession, authClient, err := authactions.SetupAuthenticatedSession(k.client, k.session, k.adminUser, authactions.Keycloak)
// 	require.NoError(k.T(), err, "Failed to setup authenticated session for admin user")
// 	defer subSession.Cleanup()

// 	adminUserDetails, err := authactions.GetUserAfterLogin(authClient, authClient.AuthenticatedUser)
// 	require.NoError(k.T(), err, "Failed to get admin user details after login")

// 	require.Equal(k.T(), k.adminUser.Username, adminUserDetails.Username, "Admin username mismatch after login")

// 	for _, user := range k.authConfig.Users {
// 		logrus.Infof("Testing login for Keycloak user: %s", user.Username)
// 		testUser := &v3.User{
// 			Username: user.Username,
// 			Password: user.Password,
// 		}

// 		userSession, userClient, err := authactions.SetupAuthenticatedSession(k.client, k.session, testUser, authactions.Keycloak)
// 		require.NoError(k.T(), err, "Failed to setup authenticated session for user: %s", user.Username)
// 		defer userSession.Cleanup()

// 		userDetails, err := authactions.GetUserAfterLogin(userClient, userClient.AuthenticatedUser)
// 		require.NoError(k.T(), err, "Failed to get user details after login for user: %s", user.Username)

// 		require.Equal(k.T(), user.Username, userDetails.Username, "Username mismatch after login for user: %s", user.Username)
// 	}
// }




func TestKeycloakAuthProviderSuite(t *testing.T) {
	suite.Run(t, new(KeycloakAuthProviderSuite))
}
