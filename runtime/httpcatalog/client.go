package httpcatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/core"
)

// Sync 将当前完整 Manifest 单次提交给 IAM Core；重试由业务启动生命周期负责。
func (r *Registry) Sync(ctx context.Context) (result Result, resultErr error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return Result{}, errCatalogRegistration
	}
	started := time.Now()
	var snapshotVersion uint64
	var successfulCatalogHash, successfulManifestHash string
	defer func() {
		if !r.recordSync(snapshotVersion, successfulCatalogHash, successfulManifestHash, resultErr) {
			result = Result{}
			if resultErr == nil {
				resultErr = errCatalogRegistration
			}
		}
		outcome := "success"
		if resultErr != nil {
			outcome = "error"
		}
		r.observe(ctx, core.Event{Operation: registrationOperation, Outcome: outcome, CredentialSource: r.credentialSource(), Duration: time.Since(started)})
	}()
	manifest, version, err := r.manifestSnapshot()
	snapshotVersion = version
	if err != nil {
		return Result{}, errCatalogRegistration
	}
	manifestHash, err := manifest.ManifestDigest()
	if err != nil {
		return Result{}, errCatalogRegistration
	}
	r.mu.RLock()
	fenced := r.fenced
	previousManifestHash := r.manifestHash
	r.mu.RUnlock()
	if fenced {
		return Result{}, ErrGenerationConflict
	}
	if previousManifestHash != "" && previousManifestHash != manifestHash {
		return Result{}, ErrManifestChanged
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return Result{}, errCatalogRegistration
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, r.endpoint, bytes.NewReader(payload))
	if err != nil {
		return Result{}, errCatalogRegistration
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	if err := r.authenticateRequest(ctx, request); err != nil {
		return Result{}, err
	}
	response, err := r.client.Do(request)
	if err != nil {
		return Result{}, errCatalogRegistration
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusConflict {
		r.fence()
		return Result{}, ErrGenerationConflict
	}
	if response.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("%w: HTTP %d", errCatalogRegistration, response.StatusCode)
	}
	var envelope struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Application          string  `json:"application"`
			CatalogHash          string  `json:"catalog_hash"`
			DeploymentGeneration *uint64 `json:"deployment_generation"`
			ManifestHash         string  `json:"manifest_hash"`
			Changed              bool    `json:"changed"`
		} `json:"data"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(&envelope); err != nil || envelope.Code != 0 || envelope.Data.Application != manifest.Application || !validCatalogHash(envelope.Data.CatalogHash) || envelope.Data.DeploymentGeneration == nil || *envelope.Data.DeploymentGeneration != manifest.DeploymentGeneration || envelope.Data.ManifestHash != manifestHash {
		return Result{}, errCatalogRegistration
	}
	successfulCatalogHash = envelope.Data.CatalogHash
	successfulManifestHash = manifestHash
	return Result{Application: envelope.Data.Application, CatalogHash: envelope.Data.CatalogHash, DeploymentGeneration: *envelope.Data.DeploymentGeneration, ManifestHash: manifestHash, Changed: envelope.Data.Changed}, nil
}

// HeartbeatOnce 使用当前注册版本续约；部署代次冲突时停止续约。
func (r *Registry) HeartbeatOnce(ctx context.Context) (resultErr error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return errCatalogRegistration
	}
	started := time.Now()
	var catalogHash, manifestHash string
	var snapshotVersion uint64
	defer func() {
		if !r.recordHeartbeat(snapshotVersion, catalogHash, manifestHash, resultErr) && resultErr == nil {
			resultErr = errCatalogRegistration
		}
		outcome := "success"
		if resultErr != nil {
			outcome = "error"
		}
		r.observe(ctx, core.Event{Operation: "httpcatalog.heartbeat", Outcome: outcome, CredentialSource: r.credentialSource(), Duration: time.Since(started)})
	}()
	r.mu.RLock()
	catalogHash = r.catalogHash
	manifestHash = r.manifestHash
	fenced := r.fenced
	r.mu.RUnlock()
	if fenced {
		return ErrGenerationConflict
	}
	if !validCatalogHash(catalogHash) || !validCatalogHash(manifestHash) {
		return errCatalogRegistration
	}
	manifest, version, err := r.manifestSnapshot()
	snapshotVersion = version
	if err != nil {
		return errCatalogRegistration
	}
	currentHash, err := manifest.ManifestDigest()
	if err != nil {
		return errCatalogRegistration
	}
	if currentHash != manifestHash {
		return ErrManifestChanged
	}
	payload, err := json.Marshal(struct {
		CatalogHash          string `json:"catalog_hash"`
		DeploymentGeneration uint64 `json:"deployment_generation"`
		ManifestHash         string `json:"manifest_hash"`
	}{CatalogHash: catalogHash, DeploymentGeneration: manifest.DeploymentGeneration, ManifestHash: manifestHash})
	if err != nil {
		return errCatalogRegistration
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.config.BaseURL+heartbeatPath, bytes.NewReader(payload))
	if err != nil {
		return errCatalogRegistration
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	if err := r.authenticateRequest(ctx, request); err != nil {
		return err
	}
	response, err := r.client.Do(request)
	if err != nil {
		return errCatalogRegistration
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusConflict {
		r.fence()
		return ErrGenerationConflict
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d", errCatalogRegistration, response.StatusCode)
	}
	var envelope struct {
		Code int `json:"code"`
		Data struct {
			Application          string  `json:"application"`
			CatalogHash          string  `json:"catalog_hash"`
			DeploymentGeneration *uint64 `json:"deployment_generation"`
			ManifestHash         string  `json:"manifest_hash"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&envelope); err != nil || envelope.Code != 0 || envelope.Data.Application != r.config.Application || envelope.Data.CatalogHash != catalogHash || envelope.Data.DeploymentGeneration == nil || *envelope.Data.DeploymentGeneration != manifest.DeploymentGeneration || envelope.Data.ManifestHash != manifestHash {
		return errCatalogRegistration
	}
	return nil
}

func (r *Registry) observe(ctx context.Context, event core.Event) {
	if r.config.Observer == nil {
		return
	}
	defer func() { _ = recover() }()
	r.config.Observer.Observe(ctx, event)
}

// RunHeartbeat 在宿主 context 生命周期内按周期续约，失败时返回让宿主处理。
func (r *Registry) RunHeartbeat(ctx context.Context) error {
	if r == nil || ctx == nil {
		return errCatalogRegistration
	}
	r.mu.RLock()
	hasVersion := r.catalogHash != ""
	fenced := r.fenced
	r.mu.RUnlock()
	if fenced {
		return ErrGenerationConflict
	}
	if !hasVersion {
		return errCatalogRegistration
	}
	ticker := time.NewTicker(r.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			var err error
			for attempt := 0; attempt < 3; attempt++ {
				err = r.HeartbeatOnce(ctx)
				if err == nil {
					break
				}
				if errors.Is(err, ErrGenerationConflict) || errors.Is(err, ErrManifestChanged) {
					return err
				}
				if attempt == 2 {
					return err
				}
				wait := time.NewTimer(r.config.HeartbeatRetryDelay * time.Duration(1<<attempt))
				select {
				case <-ctx.Done():
					wait.Stop()
					return nil
				case <-wait.C:
				}
			}
		}
	}
}

func validCatalogHash(hash string) bool {
	if !strings.HasPrefix(hash, "sha256:") || len(hash) != len("sha256:")+64 {
		return false
	}
	for _, char := range hash[len("sha256:"):] {
		if char < '0' || char > '9' && char < 'a' || char > 'f' {
			return false
		}
	}
	return true
}

func validBearerToken(token string) bool {
	bodySeen := false
	paddingSeen := false
	for index := 0; index < len(token); index++ {
		character := token[index]
		if character == '=' {
			if !bodySeen {
				return false
			}
			paddingSeen = true
			continue
		}
		if paddingSeen || !validBearerBodyCharacter(character) {
			return false
		}
		bodySeen = true
	}
	return bodySeen
}

func validBearerBodyCharacter(character byte) bool {
	return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9') || character == '-' || character == '.' || character == '_' ||
		character == '~' || character == '+' || character == '/'
}
