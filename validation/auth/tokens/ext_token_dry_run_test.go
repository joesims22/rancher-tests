//go:build (validation || infra.any || cluster.any || extended) && !sanity && !stress && !2.8 && !2.9 && !2.10 && !2.11 && !2.12 && !2.13 && !2.14 && !2.15

package tokens

import (
	extsettingsapi "github.com/rancher/shepherd/extensions/kubeapi/settings"
	exttokenapi "github.com/rancher/shepherd/extensions/kubeapi/tokens"
	tokenapi "github.com/rancher/tests/actions/kubeapi/tokens/exttokens"
	"github.com/rancher/tests/actions/rbac"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

func (ext *ExtTokenTestSuite) TestDryRunCreateExtTokenHasNoHash() {
	subSession := ext.session.NewSession()
	defer subSession.Cleanup()

	_, standardUserClient, err := rbac.SetupUser(ext.client, rbac.StandardUser.String())
	require.NoError(ext.T(), err)

	log.Info("Dry-run create ext token and verify no status.hash is returned")
	dryRunToken, err := tokenapi.CreateExtTokenDryRun(standardUserClient, tokenapi.NewExtTokenObject("", 0))
	require.NoError(ext.T(), err)
	require.NoError(ext.T(), tokenapi.VerifyStatusHashEmptyInToken(dryRunToken, "dry-run create"))
}

func (ext *ExtTokenTestSuite) TestDryRunCreateExtTokenReturnsResolvedTTL() {
	subSession := ext.session.NewSession()
	defer subSession.Cleanup()

	_, standardUserClient, err := rbac.SetupUser(ext.client, rbac.StandardUser.String())
	require.NoError(ext.T(), err)

	log.Info("Reset auth-token-max-ttl-minutes to its default so the resolved TTL matches the default")
	err = extsettingsapi.ResetGlobalSettingToDefaultValue(ext.client, extsettingsapi.AuthTokenMaxTTLMinutesSetting)
	require.NoError(ext.T(), err)

	log.Info("Dry-run create ext token with TTL set to 0")
	dryRunToken, err := tokenapi.CreateExtTokenDryRun(standardUserClient, tokenapi.NewExtTokenObject("", 0))
	require.NoError(ext.T(), err)

	log.Info("Verify dry-run response has the resolved default TTL and no token value")
	require.Equal(ext.T(), ext.defaultExtTokenTTL, dryRunToken.Spec.TTL, "Expected dry-run TTL to equal the default TTL")
	require.Empty(ext.T(), dryRunToken.Status.Value, "dry-run create should not return a token value")

	log.Info("Verify dry-run did not persist the ext token")
	_, err = exttokenapi.GetExtTokenByName(standardUserClient, dryRunToken.Name)
	require.Error(ext.T(), err)
	require.True(ext.T(), k8serrors.IsNotFound(err))
}

func (ext *ExtTokenTestSuite) TestDryRunCreateExtTokenCapsTTLAtMax() {
	subSession := ext.session.NewSession()
	defer subSession.Cleanup()

	_, standardUserClient, err := rbac.SetupUser(ext.client, rbac.StandardUser.String())
	require.NoError(ext.T(), err)

	log.Info("Reset auth-token-max-ttl-minutes to its default so the cap matches the default max")
	err = extsettingsapi.ResetGlobalSettingToDefaultValue(ext.client, extsettingsapi.AuthTokenMaxTTLMinutesSetting)
	require.NoError(ext.T(), err)

	log.Info("Dry-run create ext token with TTL value > max TTL value")
	dryRunToken, err := tokenapi.CreateExtTokenDryRun(standardUserClient, tokenapi.NewExtTokenObject("", int64(9999999999)))
	require.NoError(ext.T(), err)

	log.Info("Verify dry-run response has the max TTL value instead of the requested value")
	require.Equal(ext.T(), ext.defaultExtTokenTTL, dryRunToken.Spec.TTL, "Expected dry-run TTL to be capped at the max TTL")
}
