// Command catalog 演示从同一声明编译PDP事实并离线导出v4完整清单。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/authzcontract"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/httpauthz"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/httpcatalog"
)

func main() {
	if err := run(); err != nil {
		_, _ = os.Stderr.WriteString("catalog export failed\n")
		os.Exit(1)
	}
}
func run() error {
	declared, err := httpauthz.NewClassifiedRouteSpec(http.MethodGet, "/api/v1/portal/apps/:applicationOpenId/open", "portal.app.jenkins.open", "opsgw:jenkins:access", authzcontract.PolicyClassCardAccess)
	if err != nil {
		return err
	}
	// 框架/PDP消费同一声明中的Spec；分类本身不会授予请求权限。
	pdpManifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{declared.Spec})
	if err != nil {
		return err
	}
	binder := pdpManifest.NewBinder()
	if _, err = binder.Bind(declared.Spec.Name); err != nil {
		return err
	}
	if err = binder.Validate(); err != nil {
		return err
	}
	registry, err := httpcatalog.NewClassifiedRegistry(httpcatalog.Config{
		BaseURL: "https://iam.example.invalid", Application: "opsgw", Service: "ops-gateway-server", Release: "offline-example", DeploymentGeneration: 101,
		// 导出不会调用凭据源；真实Sync/Heartbeat由宿主注入受控凭据。
		Credentials: httpcatalog.RegistrarCredentialSourceFunc(func(context.Context) (httpcatalog.RegistrarCredentials, error) {
			return httpcatalog.RegistrarCredentials{}, errors.New("offline export has no credentials")
		}),
	})
	if err != nil {
		return err
	}
	if err = registry.RegisterClassified(declared); err != nil {
		return err
	}
	manifest, err := registry.ExportClassifiedManifest()
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(manifest)
}
