package openldap

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/rancher/shepherd/clients/rancher"
	v3 "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	//"github.com/rancher/shepherd/extensions/cloudcredentials"
	extClusters "github.com/rancher/shepherd/extensions/clusters"
	extDefaults "github.com/rancher/shepherd/extensions/defaults"
	"github.com/rancher/shepherd/pkg/config"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/rancher/tests/actions/clusters"

	"github.com/rancher/tests/actions/config/defaults"
	// "github.com/rancher/tests/actions/machinepools"
	// "github.com/rancher/tests/actions/provisioning"
	// "github.com/rancher/tests/actions/provisioninginput"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kwait "k8s.io/apimachinery/pkg/util/wait"
)

const (
	rancherLabel       = "app=rancher"
	rancherNamespace   = "cattle-system"
	rancherDeployment  = "rancher"
	rancherContainer   = "rancher"
)

type OpenLDAPAuthUpgradeChecksSuite struct {
	suite.Suite
	session       *session.Session
	client        *rancher.Client
	cluster       *v3.Cluster
	authConfig    *AuthConfig
	clusterConfig *clusters.ClusterConfig
	adminUser     *v3.User
}

// UpgradeRancher executes the helm upgrade command using a provided kubeconfig file.
func UpgradeRancher(kubeconfigPath string, timeout time.Duration, version, rancherHostname, imageTag string, additionalSets map[string]string) error {
	args := []string{
		"upgrade",
		"rancher",
		"rancher-latest/rancher",
		"--namespace", "cattle-system",
		"--kubeconfig", kubeconfigPath,
		"--timeout", timeout.String(),
		"--version", version,
		"--set", "hostname=" + rancherHostname,
		"--set", "rancherImageTag=" + imageTag,
	}

	for key, value := range additionalSets {
		args = append(args, "--set", fmt.Sprintf("%s=%s", key, value))
	}

	cmd := exec.Command("helm", args...)
	log.Infof("Running helm command: %s", strings.ReplaceAll(cmd.String(), " --", "\n  --"))

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("helm upgrade failed: %w\nOutput:\n%s", err, out.String())
	}

	log.Infof("Helm upgrade successful:\n%s", out.String())
	return nil
}

func WaitForRancherUpgrade(client *rancher.Client) error {
	// Step 1: Wait for the Deployment to complete its rolling update.
	log.Infof("Waiting up to ten minutes for the '%s' deployment to stabilize...", rancherDeployment)
	
	err := kwait.PollUntilContextTimeout(context.Background(), extDefaults.FiveMinuteTimeout, extDefaults.TenSecondTimeout, true, func(ctx context.Context) (bool, error) {
		// Get the latest version of the Deployment
		deployment, err := client.WranglerContext.Apps.Deployment().Get(rancherNamespace, rancherDeployment, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		// Check if the controller has processed the update
		if deployment.Status.ObservedGeneration < deployment.Generation {
			log.Infof("Waiting for deployment generation %d to be observed...", deployment.Generation)
			return false, nil
		}

		// Check if all replicas have been updated
		if deployment.Status.UpdatedReplicas < *deployment.Spec.Replicas {
			log.Infof("Waiting for all %d replicas to be updated. Currently at %d...", *deployment.Spec.Replicas, deployment.Status.UpdatedReplicas)
			return false, nil
		}
		
		// Check if all replicas are available and ready
		if deployment.Status.ReadyReplicas < *deployment.Spec.Replicas {
			log.Infof("Waiting for all %d replicas to be ready. Currently at %d...", *deployment.Spec.Replicas, deployment.Status.ReadyReplicas)
			return false, nil
		}
		
		log.Infof("Deployment '%s' is stable and fully rolled out.", rancherDeployment)
		return true, nil // Success, stop polling.
	})

	if err != nil {
		return fmt.Errorf("timed out waiting for Rancher deployment to upgrade: %w", err)
	}
	return nil

	// // Step 2: Verify the image tag on the new pods.
	// log.Infof("Verifying pod image tag contains '%s'", expectedImageTag)

	// pods, err := client.WranglerContext.Core.Pod().List(rancherNamespace, metav1.ListOptions{LabelSelector: rancherLabel})
	// if err != nil {
	// 	return fmt.Errorf("failed to list Rancher pods: %w", err)
	// }
	// if len(pods.Items) == 0 {
	// 	return fmt.Errorf("no Rancher pods found to verify")
	// }

	// // Check the image of the first pod in the list.
	// pod := pods.Items[0]
	// var actualImage string
	// for _, container := range pod.Spec.Containers {
	// 	if container.Name == rancherContainer {
	// 		actualImage = container.Image
	// 		log.Info(actualImage)
	// 		break
	// 	}
	// }

	// if actualImage == "" {
	// 	return fmt.Errorf("could not find container '%s' in pod '%s'", rancherContainer, pod.Name)
	// }
	
	// if !strings.Contains(actualImage, expectedImageTag) {
	// 	return fmt.Errorf("image tag mismatch: expected to find '%s' in image '%s'", expectedImageTag, actualImage)
	// }
	
	// log.Infof("✅ Successfully verified Rancher pod image: %s", actualImage)
	// return nil
}

func (a *OpenLDAPAuthUpgradeChecksSuite) TearDownSuite() {
	if a.client != nil {
		ldapConfig, err := a.client.Management.AuthConfig.ByID("openLdap")
		if err == nil && ldapConfig.Enabled {
			log.Info("Disabling OpenLDAP authentication after test suite")
			err := a.client.Auth.OLDAP.Disable()
			if err != nil {
				log.WithError(err).Warn("Failed to disable OpenLDAP in teardown")
			}
		}
	}
	a.session.Cleanup()
}

func (a *OpenLDAPAuthUpgradeChecksSuite) SetupSuite() {
	a.session = session.NewSession()

	client, err := rancher.NewClient("", a.session)
	require.NoError(a.T(), err, "Failed to create Rancher client")
	a.client = client

	a.clusterConfig = new(clusters.ClusterConfig)
	config.LoadConfig(defaults.ClusterConfigKey, a.clusterConfig)

	log.Info("Loading auth configuration from config file")
	a.authConfig = new(AuthConfig)
	config.LoadConfig("authInput", a.authConfig)
	require.NotNil(a.T(), a.authConfig, "Auth configuration is not provided")

	log.Info("Getting cluster name from the config file")
	clusterName := client.RancherConfig.ClusterName
	require.NotEmpty(a.T(), clusterName, "Cluster name should be set")

	clusterID, err := extClusters.GetClusterIDByName(a.client, clusterName)
	require.NoError(a.T(), err, "Error getting cluster ID for cluster: %s", clusterName)

	a.cluster, err = a.client.Management.Cluster.ByID(clusterID)
	require.NoError(a.T(), err, "Failed to retrieve cluster by ID: %s", clusterID)

	log.Info("Setting up admin user credentials for OpenLDAP authentication")
	a.adminUser = &v3.User{
		Username: client.Auth.OLDAP.Config.Users.Admin.Username,
		Password: client.Auth.OLDAP.Config.Users.Admin.Password,
	}

	log.Info("Enabling OpenLDAP authentication for test suite")
	err = a.client.Auth.OLDAP.Enable()
	require.NoError(a.T(), err, "Failed to enable OpenLDAP authentication")
}

func (a *OpenLDAPAuthUpgradeChecksSuite) TestOpenLDAPAuthUpgradeChecks() {
	subSession := a.session.NewSession()
	defer subSession.Cleanup()

	// log.Infof("Provisioning downstream cluster as openLDAP user %s", a.adminUser.Username)
	// nodeRolesAll := []provisioninginput.MachinePools{provisioninginput.AllRolesMachinePool}
	// a.clusterConfig.MachinePools = nodeRolesAll
	// provider := provisioning.CreateProvider(a.clusterConfig.Provider)
	// credentialSpec := cloudcredentials.LoadCloudCredential(string(provider.Name))
	// machineConfigSpec := machinepools.LoadMachineConfigs(string(provider.Name))

	// clusterObject, err := provisioning.CreateProvisioningCluster(a.client, provider, credentialSpec, a.clusterConfig, machineConfigSpec, nil)
	// require.NoError(a.T(), err)

	// provisioning.VerifyCluster(a.T(), a.client, clusterObject)
	// require.NoError(a.T(), err)

	log.Info("Getting the local kubeconfig file for helm cmd")
	localCluster, err := a.client.Management.Cluster.ByID("local")
	require.NoError(a.T(), err)
	kubeConfig, err := a.client.Management.Cluster.ActionGenerateKubeconfig(localCluster)
	require.NoError(a.T(), err)
	kubeconfigYAML := kubeConfig.Config

	tmpFile, err := os.CreateTemp("", "kubeconfig-*.yaml")
	require.NoError(a.T(), err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(kubeconfigYAML)
	require.NoError(a.T(), err)
	tmpFile.Close()
	kubeconfigPath := tmpFile.Name()

	rancherVersion := "2.12.2"
	rancherHostname := "jsims212test3.qa.rancher.space"
	rancherTag := "head"
	additionalSettings := map[string]string{
		"global.cattle.psp.enabled": "false",
		"ingress.tls.source":        "secret",
		"bootstrapPassword":         "admin",
		"agentTLSMode":              "system-store",
		"rancherImage":              "rancher/rancher",
	}

	upgradeTimeout := extDefaults.TenMinuteTimeout
	log.Info("Starting Rancher upgrade with a modified kubeconfig...")
	err = UpgradeRancher(kubeconfigPath, upgradeTimeout, rancherVersion, rancherHostname, rancherTag, additionalSettings)
	require.NoError(a.T(), err, "Rancher upgrade should complete successfully")
	
	log.Info("Waiting for Rancher pods to restart and become active upon upgrading Rancher")
	err = WaitForRancherUpgrade(a.client)
	require.NoError(a.T(), err)

}

func TestOpenLDAPAuthUpgradeChecks(t *testing.T) {
	suite.Run(t, new(OpenLDAPAuthUpgradeChecksSuite))
}