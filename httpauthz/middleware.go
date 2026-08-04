package httpauthz

import (
	"context"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

const decisionIDHeader = "X-IAM-Decision-ID"

func (s *Service) authenticateHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		started := time.Now()
		ctx := serviceRequestContext(request)
		credential, err := s.selectCredential(request)
		if err != nil {
			s.record(ctx, serviceAuthenticateOperation, serviceOutcome(err), "", started)
			s.responder.Respond(w, request, err)
			return
		}
		request = requestWithCredential(request, credential)
		s.record(request.Context(), serviceAuthenticateOperation, "authenticated", credential.Source, started)
		next.ServeHTTP(w, request)
	})
}

func (s *Service) requireHandler(route Route, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		started := time.Now()
		ctx := serviceRequestContext(request)
		clearDecisionIDHeader(w.Header())
		if request == nil || request.Method != route.method {
			err := core.NewError(core.KindProtocol, decideOperation, 0, false, nil)
			s.record(ctx, serviceRequireOperation, serviceOutcome(err), "", started)
			s.responder.Respond(w, request, err)
			return
		}
		credential, err := s.selectCredential(request)
		if err != nil {
			s.record(ctx, serviceRequireOperation, serviceOutcome(err), "", started)
			s.responder.Respond(w, request, err)
			return
		}
		request = requestWithCredential(request, credential)
		decision, err := s.pdp.Decide(request.Context(), credential.Tokens, route)
		if err != nil {
			s.record(request.Context(), serviceRequireOperation, serviceOutcome(err), credential.Source, started)
			s.responder.Respond(w, request, err)
			return
		}
		if !validMiddlewareDecision(decision) {
			err := core.NewError(core.KindProtocol, decideOperation, 0, false, nil)
			s.record(request.Context(), serviceRequireOperation, serviceOutcome(err), credential.Source, started)
			s.responder.Respond(w, request, err)
			return
		}
		request = requestWithDecision(request, decision)
		if safeDecisionIDHeader(decision.ID) {
			w.Header().Set(decisionIDHeader, decision.ID)
		}
		if !decision.Allowed {
			err := core.NewError(core.KindForbidden, decideOperation, http.StatusForbidden, false, nil)
			s.record(request.Context(), serviceRequireOperation, "forbidden", credential.Source, started)
			s.responder.Respond(w, request, err)
			return
		}
		s.record(request.Context(), serviceRequireOperation, "allowed", credential.Source, started)
		next.ServeHTTP(w, request)
	})
}

func serviceRequestContext(request *http.Request) context.Context {
	if request == nil {
		return context.Background()
	}
	return request.Context()
}

func clearDecisionIDHeader(header http.Header) {
	for name := range header {
		if strings.EqualFold(name, decisionIDHeader) {
			delete(header, name)
		}
	}
}

func validMiddlewareDecision(decision Decision) bool {
	return safeDecisionMetadata(decision.ID, true) && safeDecisionMetadata(decision.ReasonCode, true) &&
		safeDecisionMetadata(decision.RequestID, false) && safeDecisionMetadata(decision.TraceID, false)
}

func safeDecisionIDHeader(value string) bool {
	return safeDecisionMetadata(value, true)
}

func safeDecisionMetadata(value string, required bool) bool {
	if value == "" {
		return !required
	}
	return safeEnvelopeString(value) && !strings.ContainsFunc(value, func(r rune) bool { return !unicode.IsPrint(r) })
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
