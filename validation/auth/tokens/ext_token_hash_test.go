//go:build (validation || infra.any || cluster.any || extended) && !sanity && !stress && !2.8 && !2.9 && !2.10 && !2.11 && !2.12

package tokens

import (
	exttokenapi "github.com/rancher/shepherd/extensions/kubeapi/tokens"
	tokenapi "github.com/rancher/tests/actions/kubeapi/tokens/exttokens"
	"github.com/rancher/tests/actions/rbac"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (ext *ExtTokenTestSuite) TestExtTokenHashAbsentFromReadResponse() {
	subSession := ext.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Create ext token as the admin user")
	adminUserExtToken, err := tokenapi.CreateExtToken(ext.client, ext.defaultExtTokenTTL)
	require.NoError(ext.T(), err)

	log.Info("Create ext token as standard user")
	standardUser, standardUserClient, err := rbac.SetupUser(ext.client, rbac.StandardUser.String())
	require.NoError(ext.T(), err)
	ownedExtToken, err := tokenapi.CreateExtToken(standardUserClient, ext.defaultExtTokenTTL)
	require.NoError(ext.T(), err)

	log.Info("Verifying hash is absent from GET request as standard user")
	standardUserGetToken, err := exttokenapi.GetExtTokenByName(standardUserClient, ownedExtToken.Name)
	require.NoError(ext.T(), err)
	require.NoError(ext.T(), tokenapi.VerifyStatusHashEmptyInToken(standardUserGetToken, "standard user get"))

	log.Info("Verifying hash is absent from LIST request as standard user")
	standardUserSelector := tokenapi.UserIDLabel + "=" + standardUser.ID
	standardUserList, err := exttokenapi.ListExtTokens(standardUserClient, metav1.ListOptions{LabelSelector: standardUserSelector})
	require.NoError(ext.T(), err)
	require.NotEmpty(ext.T(), standardUserList.Items, "standardUser list should return at least one token")
	require.NoError(ext.T(), tokenapi.VerifyStatusHashEmptyInList(standardUserList.Items, "standardUser list"))

	log.Info("Verifying hash is absent from WATCH request as standard user")
	require.NoError(ext.T(), tokenapi.VerifyWatchEventHasRedactedHash(standardUserClient, ownedExtToken.Name, "standardUser watch"))

	log.Info("Verifying hash is absent from UPDATE response as standard user")
	standardUserTokenToUpdate := standardUserGetToken.DeepCopy()
	standardUserTokenToUpdate.Labels["hash-redaction-standardUser"] = "true"
	standardUserUpdatedToken, err := exttokenapi.UpdateExtToken(standardUserClient, standardUserTokenToUpdate)
	require.NoError(ext.T(), err)
	require.NoError(ext.T(), tokenapi.VerifyStatusHashEmptyInToken(standardUserUpdatedToken, "standardUser update"))

	log.Info("Verifying hash is absent from GET request as admin")
	adminGetToken, err := exttokenapi.GetExtTokenByName(ext.client, adminUserExtToken.Name)
	require.NoError(ext.T(), err)
	require.NoError(ext.T(), tokenapi.VerifyStatusHashEmptyInToken(adminGetToken, "admin get"))

	log.Info("Verifying hash is absent from LIST request as admin")
	adminExtTokenList, err := exttokenapi.ListExtTokens(ext.client, metav1.ListOptions{LabelSelector: standardUserSelector})
	require.NoError(ext.T(), err)
	require.NotEmpty(ext.T(), adminExtTokenList.Items, "Admin list should return the standardUser's token")
	require.NoError(ext.T(), tokenapi.VerifyStatusHashEmptyInList(adminExtTokenList.Items, "admin list"))

	log.Info("Verifying hash is absent from WATCH request as admin")
	require.NoError(ext.T(), tokenapi.VerifyWatchEventHasRedactedHash(ext.client, adminUserExtToken.Name, "admin watch"))

	log.Info("Verifying hash is absent from UPDATE response as admin")
	adminTokenToUpdate := adminGetToken.DeepCopy()
	adminTokenToUpdate.Labels["hash-redaction-admin"] = "true"
	adminUpdatedToken, err := exttokenapi.UpdateExtToken(ext.client, adminTokenToUpdate)
	require.NoError(ext.T(), err)
	require.NoError(ext.T(), tokenapi.VerifyStatusHashEmptyInToken(adminUpdatedToken, "admin update"))
}
