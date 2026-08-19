package httpcatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

// Sync 将当前完整 Manifest 单次提交给 IAM Core；重试由业务启动生命周期负责。
func (r *Registry) Sync(ctx context.Context) (result Result, resultErr error) {
	started := time.Now()
	defer func() {
		r.recordSync(resultErr)
		observer := r.config.Observer
		if observer == nil {
			observer = core.NopObserver{}
		}
		outcome := "success"
		if resultErr != nil {
			outcome = "error"
		}
		observer.Observe(ctx, core.Event{Operation: registrationOperation, Outcome: outcome, CredentialSource: "client_secret_basic", Duration: time.Since(started)})
	}()
	manifest, err := r.manifestSnapshot()
	if err != nil || ctx == nil || ctx.Err() != nil {
		return Result{}, errCatalogRegistration
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
	request.SetBasicAuth(r.config.ClientID, r.config.ClientSecret)
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
	return envelope.Data, nil
}
