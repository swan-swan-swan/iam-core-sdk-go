// Package ginadapter bridges IAM Core net/http authorization middleware into Gin.
package ginadapter

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/httpauthz"
)

type admissionWriter struct {
	gin.ResponseWriter
	context *gin.Context
	reached bool
}

var _ gin.ResponseWriter = (*admissionWriter)(nil)

func (w *admissionWriter) Unwrap() http.ResponseWriter {
	if w == nil {
		return nil
	}
	return w.ResponseWriter
}

type terminalHandler struct{}

func (terminalHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request == nil {
		return
	}
	state, ok := writer.(*admissionWriter)
	if !ok || state == nil || state.context == nil {
		return
	}
	state.reached = true
	state.context.Request = request
	state.context.Next()
}

// Authenticate adapts the root authentication middleware to Gin.
func Authenticate(service *httpauthz.Service) (gin.HandlerFunc, error) {
	handler, err := service.Authenticate(terminalHandler{})
	if err != nil {
		return nil, err
	}
	return bridge(handler), nil
}

// Require adapts the root authorization middleware for a compiled route to Gin.
func Require(service *httpauthz.Service, route httpauthz.Route) (gin.HandlerFunc, error) {
	handler, err := service.Require(route, terminalHandler{})
	if err != nil {
		return nil, err
	}
	return bridge(handler), nil
}

func bridge(handler http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c == nil || c.Request == nil {
			if c != nil {
				c.Abort()
			}
			return
		}
		state := &admissionWriter{ResponseWriter: c.Writer, context: c}
		handler.ServeHTTP(state, c.Request)
		if !state.reached {
			c.Abort()
		}
	}
}

// AuthContext returns the authentication context attached by the root middleware.
func AuthContext(c *gin.Context) (core.AuthContext, bool) {
	if c == nil || c.Request == nil {
		return core.AuthContext{}, false
	}
	return core.AuthContextFromContext(c.Request.Context())
}

// Decision returns the authorization decision attached by the root middleware.
func Decision(c *gin.Context) (httpauthz.Decision, bool) {
	if c == nil || c.Request == nil {
		return httpauthz.Decision{}, false
	}
	return httpauthz.DecisionFromContext(c.Request.Context())
}
