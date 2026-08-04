package bff

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

func (c *Client) MeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowOnlyMethod(w, request, http.MethodGet) {
			return
		}
		credential, present, err := c.ResolveSession(request)
		if err != nil {
			writeBFFError(w, err)
			return
		}
		if !present || strings.TrimSpace(credential.Auth.Subject) == "" {
			writeBFFError(w, bffError(core.KindUnauthenticated, "bff.me", 0, false))
			return
		}
		body, err := json.Marshal(credential.Auth)
		if err != nil {
			writeBFFError(w, bffError(core.KindProtocol, "bff.me", 0, false))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
}

func allowOnlyMethod(w http.ResponseWriter, request *http.Request, method string) bool {
	if w == nil {
		return false
	}
	if request == nil || request.Method != method {
		w.Header().Set("Allow", method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return false
	}
	return true
}
