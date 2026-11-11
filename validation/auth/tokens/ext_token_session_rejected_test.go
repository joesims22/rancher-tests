//go:build (validation || infra.any || cluster.any || extended) && !sanity && !stress && !2.8 && !2.9 && !2.10 && !2.11 && !2.12 && !2.13 && !2.14 && !2.15

package tokens

import (
	tokenapi "github.com/rancher/tests/actions/kubeapi/tokens/exttokens"
	"github.com/rancher/tests/actions/rbac"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func (ext *ExtTokenTestSuite) TestCreateExtSessionTokenRejectedAsAdmin() {
	subSession := ext.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Verify admin user cannot create ext token of kind session, with or without dry-run")
	err := tokenapi.VerifySessionTokenCreateRejected(ext.client)
	require.NoError(ext.T(), err)
}

func (ext *ExtTokenTestSuite) TestCreateExtSessionTokenRejectedAsNonAdmin() {
	subSession := ext.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Verify standard user cannot create ext token of kind session, with or without dry-run")
	_, standardUserClient, err := rbac.SetupUser(ext.client, rbac.StandardUser.String())
	require.NoError(ext.T(), err)
	err = tokenapi.VerifySessionTokenCreateRejected(standardUserClient)
	require.NoError(ext.T(), err)
}
