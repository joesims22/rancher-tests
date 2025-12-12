package defaults

import (
	"fmt"

	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/extensions/clusters/kubernetesversions"
	"github.com/rancher/shepherd/pkg/config/operations"
)

const (
    ClusterConfigKey     = "clusterConfig"
    AWSEC2Configs        = "awsEC2Configs"
    K8SVersionKey        = "kubernetesVersion"
    CNIKey               = "cni"
    ProviderKey          = "provider"
    ProvisioningInputKey = "provisioningInput"
    DataKey              = "data"
    RKE2VersionKey       = "rke2KubernetesVersion"
    K3SVersionKey        = "k3sKubernetesVersion"
)

//SetK8sDefault sets the k8s version based on the provided k8sType to the latest version in the cattleConfig
func SetK8sDefault(client *rancher.Client, k8sType string, cattleConfig map[string]any) (map[string]any, error) {
    var overrideKey string

    if k8sType == "rke2" { 
        overrideKey = RKE2VersionKey
    } else {
        overrideKey = K3SVersionKey
    }


    overridePath := []string{ProvisioningInputKey, DataKey, overrideKey}
    overrideValue, _ := operations.GetValue(overridePath, cattleConfig) // Ignore error (treat as missing)

    var versionToUse interface{}

    if overrideValue != nil {
        // Handle YAML lists (which load as []interface{}) vs simple strings
        switch v := overrideValue.(type) {
        case []interface{}:
            if len(v) > 0 {
                versionToUse = v[0]
            }
        case string:
            if v != "" {
                versionToUse = v
            }
        }
    }

    if versionToUse != nil {
        fmt.Printf("Using config override for %s: %v\n", k8sType, versionToUse)
    } else {
        // Fallback: No override found, fetch the latest default from Rancher
        fmt.Printf("No specific %s version found in config, fetching latest default...\n", k8sType)
        versions, err := kubernetesversions.Default(client, k8sType, nil)
        if err != nil {
            return nil, err
        }
        versionToUse = versions[0]
    }

    k8sKeyPath := []string{ClusterConfigKey, K8SVersionKey}
    
    // Note: If the key doesn't exist yet, ReplaceValue usually fails in some libraries.
    // If operations.ReplaceValue strictly requires existence, you might need operations.PutValue 
    // or similar if your framework supports it. 
    // Assuming standard Rancher testing framework behavior where ReplaceValue handles path creation or we know the struct exists:
    cattleConfig, err := operations.ReplaceValue(k8sKeyPath, versionToUse, cattleConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to set kubernetes version: %w", err)
    }

    return cattleConfig, nil
}
