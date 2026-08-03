package httpauthz

import (
	"net/http"
	"strings"
	"unicode"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

const decisionIDHeader = "X-IAM-Decision-ID"

func (s *Service) authenticateHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		credential, err := s.selectCredential(request)
		if err != nil {
			s.responder.Respond(w, request, err)
			return
		}
		request = requestWithCredential(request, credential)
		next.ServeHTTP(w, request)
	})
}

func (s *Service) requireHandler(route Route, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request == nil || request.Method != route.method {
			s.responder.Respond(w, request, core.NewError(core.KindProtocol, decideOperation, 0, false, nil))
			return
		}
		credential, err := s.selectCredential(request)
		if err != nil {
			s.responder.Respond(w, request, err)
			return
		}
		request = requestWithCredential(request, credential)
		decision, err := s.pdp.Decide(request.Context(), credential.Tokens, route)
		if err != nil {
			s.responder.Respond(w, request, err)
			return
		}
		request = requestWithDecision(request, decision)
		w.Header().Del(decisionIDHeader)
		if safeDecisionIDHeader(decision.ID) {
			w.Header().Set(decisionIDHeader, decision.ID)
		}
		if !decision.Allowed {
			s.responder.Respond(w, request, core.NewError(core.KindForbidden, decideOperation, http.StatusForbidden, false, nil))
			return
		}
		next.ServeHTTP(w, request)
	})
}

func safeDecisionIDHeader(value string) bool {
	return value != "" && safeEnvelopeString(value) &&
		!strings.ContainsFunc(value, func(r rune) bool { return !unicode.IsPrint(r) })
}

func requestWithCredential(request *http.Request, credential core.Credential) *http.Request {
	ctx := core.ContextWithAuthContext(request.Context(), credential.Auth)
	ctx = contextWithCredentialSource(ctx, credential.Source)
	return request.WithContext(ctx)
}

func requestWithDecision(request *http.Request, decision Decision) *http.Request {
	auth, _ := core.AuthContextFromContext(request.Context())
	auth.DecisionID = decision.ID
	auth.ReasonCode = decision.ReasonCode
	ctx := core.ContextWithAuthContext(request.Context(), auth)
	ctx = contextWithDecision(ctx, decision)
	return request.WithContext(ctx)
}
