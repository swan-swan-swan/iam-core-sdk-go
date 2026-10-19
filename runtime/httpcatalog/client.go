package httpcatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/core"
)

// Sync 将当前完整 Manifest 单次提交给 IAM Core；重试由业务启动生命周期负责。
func (r *Registry) Sync(ctx context.Context) (result Result, resultErr error) {
	started := time.Now()
	var snapshotVersion uint64
	var successfulHash string
	defer func() {
		if !r.recordSync(snapshotVersion, successfulHash, resultErr) {
			result = Result{}
			resultErr = errCatalogRegistration
		}
		observer := r.config.Observer
		if observer == nil {
			observer = core.NopObserver{}
		}
		outcome := "success"
		if resultErr != nil {
			outcome = "error"
		}
		observer.Observe(ctx, core.Event{Operation: registrationOperation, Outcome: outcome, CredentialSource: "bearer", Duration: time.Since(started)})
	}()
	manifest, version, err := r.manifestSnapshot()
	snapshotVersion = version
	if err != nil || ctx == nil || ctx.Err() != nil {
		return Result{}, errCatalogRegistration
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return Result{}, errCatalogRegistration
	}
	token, err := r.config.Tokens.AccessToken(ctx)
	if err != nil || !validBearerToken(token) {
		return Result{}, errCatalogRegistration
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, r.endpoint, bytes.NewReader(payload))
	if err != nil {
		return Result{}, errCatalogRegistration
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := r.client.Do(request)
	if err != nil {
		return Result{}, errCatalogRegistration
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Result{}, errCatalogRegistration
	}
	var envelope struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    Result `json:"data"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(&envelope); err != nil || envelope.Code != 0 || envelope.Data.Application != manifest.Application || envelope.Data.CatalogHash == "" {
		return Result{}, errCatalogRegistration
	}
	successfulHash = envelope.Data.CatalogHash
	return envelope.Data, nil
}

// HeartbeatOnce 使用当前注册版本续约；版本冲突时重新提交完整 Manifest。
func (r *Registry) HeartbeatOnce(ctx context.Context) (resultErr error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return errCatalogRegistration
	}
	started := time.Now()
	var hash string
	resynced := false
	defer func() {
		if !resynced && !r.recordHeartbeat(hash, resultErr) && resultErr == nil {
			resultErr = errCatalogRegistration
		}
		observer := r.config.Observer
		if observer == nil {
			observer = core.NopObserver{}
		}
		outcome := "success"
		if resultErr != nil {
			outcome = "error"
		}
		observer.Observe(ctx, core.Event{Operation: "httpcatalog.heartbeat", Outcome: outcome, CredentialSource: "bearer", Duration: time.Since(started)})
	}()
	r.mu.RLock()
	hash = r.catalogHash
	r.mu.RUnlock()
	if !validCatalogHash(hash) {
		return errCatalogRegistration
	}
	payload, err := json.Marshal(struct {
		CatalogHash string `json:"catalog_hash"`
	}{CatalogHash: hash})
	if err != nil {
		return errCatalogRegistration
	}
	token, err := r.config.Tokens.AccessToken(ctx)
	if err != nil || !validBearerToken(token) {
		return errCatalogRegistration
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.config.BaseURL+heartbeatPath, bytes.NewReader(payload))
	if err != nil {
		return errCatalogRegistration
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := r.client.Do(request)
	if err != nil {
		return errCatalogRegistration
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusConflict {
		_, err := r.Sync(ctx)
		resynced = err == nil
		return err
	}
	if response.StatusCode != http.StatusOK {
		return errCatalogRegistration
	}
	var envelope struct {
		Code int    `json:"code"`
		Data Result `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&envelope); err != nil || envelope.Code != 0 || envelope.Data.Application != r.config.Application || envelope.Data.CatalogHash != hash {
		return errCatalogRegistration
	}
	return nil
}

// RunHeartbeat 在宿主 context 生命周期内按周期续约，失败时返回让宿主处理。
func (r *Registry) RunHeartbeat(ctx context.Context) error {
	if r == nil || ctx == nil {
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
				r.mu.RLock()
				hasVersion := r.catalogHash != ""
				r.mu.RUnlock()
				if hasVersion {
					err = r.HeartbeatOnce(ctx)
				} else {
					_, err = r.Sync(ctx)
				}
				if err == nil {
					break
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
