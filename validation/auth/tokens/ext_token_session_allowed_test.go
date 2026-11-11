//go:build (validation || infra.any || cluster.any || extended) && !sanity && !stress && !2.8 && !2.9 && !2.10 && !2.11 && !2.16

package tokens

import (
	tokenapi "github.com/rancher/tests/actions/kubeapi/tokens/exttokens"
	"github.com/rancher/tests/actions/rbac"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func (ext *ExtTokenTestSuite) TestCreateExtSessionTokenAllowedAsAdmin() {
	subSession := ext.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Verify admin user can create ext token of kind session")
	sessionToken, err := tokenapi.CreateExtSessionToken(ext.client)
	require.NoError(ext.T(), err)
	require.NotEmpty(ext.T(), sessionToken.Name)
}

func (ext *ExtTokenTestSuite) TestCreateExtSessionTokenAllowedAsNonAdmin() {
	subSession := ext.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Verify standard user can create ext token of kind session")
	_, standardUserClient, err := rbac.SetupUser(ext.client, rbac.StandardUser.String())
	require.NoError(ext.T(), err)
	sessionToken, err := tokenapi.CreateExtSessionToken(standardUserClient)
	require.NoError(ext.T(), err)
	require.NotEmpty(ext.T(), sessionToken.Name)
}
