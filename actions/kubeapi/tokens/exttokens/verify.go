package exttokens

import (
	"context"
	"fmt"

	extapi "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/extensions/defaults"
	exttokenapi "github.com/rancher/shepherd/extensions/kubeapi/tokens"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

// VerifyExtTokenData validates ext token data against expected values
func VerifyExtTokenData(client *rancher.Client, exttoken *extapi.Token, expectedUserID string, expectedDefaultTTL int64, onCreation bool) error {
	userID, ok := exttoken.Labels[UserIDLabel]
	if !ok {
		return fmt.Errorf("expected label cattle.io/user-id to exist on token")
	}
	if userID != expectedUserID {
		return fmt.Errorf("label mismatch for user ID: got '%s', want '%s'", userID, expectedUserID)
	}

	if exttoken.Spec.Enabled == nil {
		return fmt.Errorf("Spec.Enabled should not be nil")
	}
	if !*exttoken.Spec.Enabled {
		return fmt.Errorf("expected token to be enabled, but it was disabled")
	}
	if exttoken.Spec.TTL != expectedDefaultTTL {
		return fmt.Errorf("TTL mismatch: got %d, want %d", exttoken.Spec.TTL, expectedDefaultTTL)
	}

	if exttoken.Status.Expired != ExtTokenStatusCurrentValue {
		return fmt.Errorf("status.Current mismatch: got '%v', want '%v'", exttoken.Status.Current, FalseConditionStatus)
	}

	if exttoken.Status.Expired != ExtTokenStatusExpiredValue {
		return fmt.Errorf("status.Expired mismatch: got '%v', want '%v'", exttoken.Status.Expired, ExtTokenStatusExpiredValue)
	}

	if onCreation {
		if exttoken.Status.Value == "" {
			return fmt.Errorf("expected Status.Value to be populated, but it was empty")
		}
		if exttoken.Status.Hash != "" {
			return fmt.Errorf("expected Status.Hash to be empty on creation, but it was: '%s'", exttoken.Status.Hash)
		}
	} else {
		if exttoken.Status.Value != "" {
			return fmt.Errorf("expected Status.Value to be empty after creation, but it was populated")
		}
		if exttoken.Status.Hash == "" {
			return fmt.Errorf("expected Status.Hash to be populated after creation, but it was empty")
		}
	}
	return nil
}

// VerifyExtSessionTokenData validates that a session ext token has the expected properties
func VerifyExtSessionTokenData(exttoken *extapi.Token, expectedUserID string) error {
	userID, ok := exttoken.Labels[UserIDLabel]
	if !ok {
		return fmt.Errorf("expected label cattle.io/user-id to exist on token")
	}
	if userID != expectedUserID {
		return fmt.Errorf("label mismatch for user ID: got '%s', want '%s'", userID, expectedUserID)
	}
	if exttoken.Spec.Kind != "session" {
		return fmt.Errorf("expected Spec.Kind to be 'session', got '%s'", exttoken.Spec.Kind)
	}
	if exttoken.Spec.Enabled == nil {
		return fmt.Errorf("Spec.Enabled should not be nil")
	}
	if !*exttoken.Spec.Enabled {
		return fmt.Errorf("expected session token to be enabled, but it was disabled")
	}
	if exttoken.Status.Value == "" {
		return fmt.Errorf("expected Status.Value to be populated, but it was empty")
	}
	if exttoken.Status.Hash != "" {
		return fmt.Errorf("expected Status.Hash to be empty on creation, but it was: '%s'", exttoken.Status.Hash)
	}
	return nil
}

// VerifyExtTokenExistsInList returns true if a token with the given name exists in the provided list
func VerifyExtTokenExistsInList(tokens []extapi.Token, name string) bool {
	for _, token := range tokens {
		if token.Name == name {
			return true
		}
	}
	return false
}

// VerifySessionTokenCreateRejected returns an error unless both a real create and a dry-run create of an ext token of kind session are rejected with HTTP 400
func VerifySessionTokenCreateRejected(client *rancher.Client) error {
	_, err := exttokenapi.CreateExtToken(client, NewExtTokenObject("session", 0))
	if err == nil {
		return fmt.Errorf("creating an ext token of kind session should be rejected")
	}
	if !k8serrors.IsBadRequest(err) {
		return fmt.Errorf("expected HTTP 400 on create, got: %w", err)
	}

	_, err = CreateExtTokenDryRun(client, NewExtTokenObject("session", 0))
	if err == nil {
		return fmt.Errorf("dry-run create of an ext token of kind session should be rejected")
	}
	if !k8serrors.IsBadRequest(err) {
		return fmt.Errorf("expected HTTP 400 on dry-run, got: %w", err)
	}

	return nil
}

// VerifyStatusHashEmptyInToken returns an error if the token's status.hash is populated
func VerifyStatusHashEmptyInToken(token *extapi.Token, operation string) error {
	if token == nil {
		return fmt.Errorf("%s returned a nil token", operation)
	}
	if token.Status.Hash != "" {
		return fmt.Errorf("%s should not expose status.hash, got: '%s'", operation, token.Status.Hash)
	}
	return nil
}

// VerifyStatusHashEmptyInList returns an error if any listed token's status.hash is populated
func VerifyStatusHashEmptyInList(tokens []extapi.Token, operation string) error {
	for _, listedToken := range tokens {
		if listedToken.Status.Hash != "" {
			return fmt.Errorf("%s should not expose status.hash for token %s, got: '%s'", operation, listedToken.Name, listedToken.Status.Hash)
		}
	}
	return nil
}

// VerifyWatchEventHasRedactedHash watches the named token until its event arrives and returns an error if status.hash is populated
func VerifyWatchEventHasRedactedHash(client *rancher.Client, tokenName, operation string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaults.OneMinuteTimeout)
	defer cancel()
	sendInitial := true
	watcher, err := client.WranglerContext.Ext.Token().Watch(metav1.ListOptions{
		FieldSelector:        "metadata.name=" + tokenName,
		SendInitialEvents:    &sendInitial,
		AllowWatchBookmarks:  true,
		ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
	})
	if err != nil {
		return fmt.Errorf("%s failed to start watch: %w", operation, err)
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s did not observe a token event before timeout", operation)
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return fmt.Errorf("%s watch channel closed unexpectedly", operation)
			}
			if event.Type == watch.Bookmark {
				continue
			}

			watchedToken, ok := event.Object.(*extapi.Token)
			if !ok {
				return fmt.Errorf("%s expected ext token object from watch event", operation)
			}
			if watchedToken.Name != tokenName {
				continue
			}
			if watchedToken.Status.Hash != "" {
				return fmt.Errorf("%s should not expose status.hash, got: '%s'", operation, watchedToken.Status.Hash)
			}
			return nil
		}
	}
}
