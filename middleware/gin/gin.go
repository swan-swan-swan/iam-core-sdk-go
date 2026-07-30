// Package gin adapts IAM Core's net/http middleware to Gin.
package gin

import (
	"net/http"

	ginframework "github.com/gin-gonic/gin"
	iamcore "github.com/swan-swan-swan/iam-core-client-sdk-go"
)

const nilClientPanic = "iamcore/gin: nil Client"

// Authenticate verifies the request credential through the net/http core.
func Authenticate(client *iamcore.Client) ginframework.HandlerFunc {
	requireClient(client)
	return adapt(client.Authenticate)
}

// RequirePermission authenticates the request and asks IAM Core for a fresh
// permission decision through the net/http core.
func RequirePermission(
	client *iamcore.Client,
	resourceServer string,
	resource string,
) ginframework.HandlerFunc {
	requireClient(client)
	return adapt(client.RequirePermission(iamcore.Permission{
		ResourceServer: resourceServer,
		Resource:       resource,
	}))
}

// Identity returns the authenticated identity from the wrapped request
// Context.
func Identity(c *ginframework.Context) (iamcore.Identity, bool) {
	if c == nil || c.Request == nil {
		return iamcore.Identity{}, false
	}
	return iamcore.IdentityFromContext(c.Request.Context())
}

// Decision returns the authorization decision from the wrapped request
// Context.
func Decision(c *ginframework.Context) (iamcore.Decision, bool) {
	if c == nil || c.Request == nil {
		return iamcore.Decision{}, false
	}
	return iamcore.DecisionFromContext(c.Request.Context())
}

func requireClient(client *iamcore.Client) {
	if client == nil {
		panic(nilClientPanic)
	}
}

func adapt(wrap func(http.Handler) http.Handler) ginframework.HandlerFunc {
	return func(c *ginframework.Context) {
		reached := false
		terminal := http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			reached = true
			c.Request = request
		})
		wrap(terminal).ServeHTTP(c.Writer, c.Request)
		if !reached {
			c.Abort()
			return
		}
		c.Next()
	}
}
