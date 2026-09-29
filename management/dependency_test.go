package management

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestManagementExcludesForbiddenPublicPackages(t *testing.T) {
	forbidden := map[string]struct{}{
		"users": {}, "organizations": {}, "roles": {}, "globalroles": {}, "global-roles": {}, "global_roles": {},
		"cloudprovider": {}, "cloudproviders": {}, "cloud-provider": {}, "cloud-providers": {}, "cloud_provider": {}, "cloud_providers": {},
		"audits": {}, "rpc": {},
	}
	err := filepath.WalkDir(".", func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if _, disallowed := forbidden[strings.ToLower(entry.Name())]; disallowed {
				t.Errorf("forbidden Management package exists: %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("inspect Management packages: %v", err)
	}
}

func TestManagementProductionImportsStayLightweight(t *testing.T) {
	forbiddenFragments := []string{
		"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime",
		"github.com/gin-gonic/gin",
		"github.com/redis/",
		"github.com/go-redis/",
		"github.com/docker/",
		"github.com/testcontainers/",
		"dubbo",
		"triple",
		"google.golang.org/grpc",
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			for _, fragment := range forbiddenFragments {
				if strings.Contains(strings.ToLower(value), strings.ToLower(fragment)) {
					t.Errorf("%s imports forbidden heavy or RPC dependency %q", path, value)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("inspect Management imports: %v", err)
	}
}

func TestDirectoryClientsOnlyDependOnSharedManagementTransport(t *testing.T) {
	allowed := map[string]struct{}{
		"context": {}, "net/http": {}, "net/url": {}, "reflect": {}, "strconv": {},
		"strings": {}, "unicode/utf8": {},
		"github.com/swan-swan-swan/iam-core-sdk-go/v3/management/client": {},
	}
	for _, directory := range []string{"userdirectory", "notificationcontacts"} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatalf("read %s: %v", directory, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(directory, entry.Name())
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imported := range file.Imports {
				value, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := allowed[value]; !ok {
					t.Errorf("%s imports unapproved dependency %q", path, value)
				}
			}
		}
	}
}
