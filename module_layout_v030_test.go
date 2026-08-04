package iamcoresdk_test

import (
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestV030ModuleLayout(t *testing.T) {
	root := repositoryRoot(t)
	rootModule := readFile(t, "go.mod")
	if !strings.Contains(rootModule, "module github.com/swan-swan-swan/iam-core-sdk-go\n") {
		t.Fatalf("root module was not renamed: %s", rootModule)
	}

	required := []string{
		"runtime/core", "runtime/bff", "runtime/httpauthz", "runtime/testkit",
		"runtime/internal/nilcheck", "runtime/internal/random",
		"runtime/adapters/gin/go.mod", "runtime/adapters/redis/go.mod",
		"examples/runtime/bff", "examples/runtime/nethttp",
	}
	for _, path := range required {
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Errorf("required path %s: %v", path, err)
		}
	}

	forbidden := []string{
		"core", "bff", "httpauthz", "testkit", "rpc",
		"adapters/gin", "adapters/redis",
	}
	for _, path := range forbidden {
		if _, err := os.Stat(filepath.Join(root, path)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("legacy or forbidden path still exists: %s", path)
		}
	}

	if declaration := strings.SplitN(rootModule, "\n", 2)[0]; declaration != "module github.com/swan-swan-swan/iam-core-sdk-go" {
		t.Errorf("root module declaration = %q, want %q", declaration, "module github.com/swan-swan-swan/iam-core-sdk-go")
	}

	adapterModules := []struct {
		path        string
		declaration string
	}{
		{
			path:        "runtime/adapters/gin/go.mod",
			declaration: "module github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/gin",
		},
		{
			path:        "runtime/adapters/redis/go.mod",
			declaration: "module github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis",
		},
	}
	for _, adapterModule := range adapterModules {
		moduleFile := readFile(t, adapterModule.path)
		if declaration := strings.SplitN(moduleFile, "\n", 2)[0]; declaration != adapterModule.declaration {
			t.Errorf("%s module declaration = %q, want %q", adapterModule.path, declaration, adapterModule.declaration)
		}
	}

	integrationModule := readFile(t, "integration/go.mod")
	const integrationDeclaration = "module github.com/swan-swan-swan/iam-core-sdk-go/integration"
	if declaration := strings.SplitN(integrationModule, "\n", 2)[0]; declaration != integrationDeclaration {
		t.Errorf("integration/go.mod module declaration = %q, want %q", declaration, integrationDeclaration)
	}

	const legacyModule = "github.com/swan-swan-swan/iam-core-client-sdk-go"
	for _, path := range taskScopedGoSources(t, root) {
		for _, importPath := range legacyImportsInGoFile(t, filepath.Join(root, path), legacyModule) {
			t.Errorf("%s imports legacy module path %q", path, importPath)
		}
	}

	assertNoRPCPublicSurface(t, root)
}

func TestV030ModuleLayoutUnquotesLegacyImportLiterals(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "legacy_import_literals.go")
	contents := "package fixture\n\nimport (\n" +
		"\t_ `github.com/swan-swan-swan/iam-core-client-sdk-go/core`\n" +
		"\t_ \"github.com/swan-swan-swan/iam-core-client-sdk-go/\\x62ff\"\n" +
		")\n"
	if err := os.WriteFile(fixture, []byte(contents), 0o600); err != nil {
		t.Fatalf("write legacy import fixture: %v", err)
	}

	const legacyModule = "github.com/swan-swan-swan/iam-core-client-sdk-go"
	got := strings.Join(legacyImportsInGoFile(t, fixture, legacyModule), ",")
	const want = "github.com/swan-swan-swan/iam-core-client-sdk-go/core,github.com/swan-swan-swan/iam-core-client-sdk-go/bff"
	if got != want {
		t.Fatalf("legacy imports = %q, want %q", got, want)
	}
}

func legacyImportsInGoFile(t *testing.T, path, legacyModule string) []string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var legacyImports []string
	for _, imported := range parsed.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("unquote import path %q in %s: %v", imported.Path.Value, path, err)
		}
		if importPath == legacyModule || strings.HasPrefix(importPath, legacyModule+"/") {
			legacyImports = append(legacyImports, importPath)
		}
	}
	return legacyImports
}

func TestV030ModuleLayoutParsesCommentedRequireBlocks(t *testing.T) {
	moduleFile := filepath.Join(t.TempDir(), "go.mod")
	contents := `module example.com/fixture

go 1.24.0

require ( // direct dependencies
	example.com/dubbo v1.0.0 // indirectly required by policy
	google.golang.org/grpc v1.70.0 //indirect; transitive test dependency
) // end dependencies

require( // another direct dependency block
	example.com/triple v1.0.0
)
`
	if err := os.WriteFile(moduleFile, []byte(contents), 0o600); err != nil {
		t.Fatalf("write fixture go.mod: %v", err)
	}

	got := strings.Join(directGoModRequirements(t, moduleFile), ",")
	const want = "example.com/dubbo,example.com/triple"
	if got != want {
		t.Fatalf("direct requirements = %q, want %q", got, want)
	}
}

func TestV030ModuleLayoutUnquotesDirectRequirements(t *testing.T) {
	moduleFile := filepath.Join(t.TempDir(), "go.mod")
	contents := `module example.com/fixture

go 1.24.0

require "google.golang.org/grpc" v1.70.0

require (
	"example.com/\x64ubbo" v1.0.0
	"example.com/\x74riple" v1.0.0
)
`
	if err := os.WriteFile(moduleFile, []byte(contents), 0o600); err != nil {
		t.Fatalf("write fixture go.mod: %v", err)
	}

	got := strings.Join(directGoModRequirements(t, moduleFile), ",")
	const want = "google.golang.org/grpc,example.com/dubbo,example.com/triple"
	if got != want {
		t.Fatalf("direct requirements = %q, want %q", got, want)
	}
}

func assertNoRPCPublicSurface(t *testing.T, root string) {
	t.Helper()
	historicalDirectories := map[string]bool{
		".git":         true,
		".superpowers": true,
		".worktrees":   true,
		"docs":         true,
		"releases":     true,
		"vendor":       true,
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			relative, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			if path != root && !strings.Contains(relative, string(filepath.Separator)) && historicalDirectories[relative] {
				return filepath.SkipDir
			}
			if entry.Name() == "rpc" {
				t.Errorf("RPC package directory is forbidden: %s", relative)
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "go.mod" {
			return nil
		}

		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for _, modulePath := range directGoModRequirements(t, path) {
			lowerPath := strings.ToLower(modulePath)
			if strings.Contains(lowerPath, "dubbo") || strings.Contains(lowerPath, "triple") {
				t.Errorf("%s directly requires forbidden RPC module %q", relative, modulePath)
			}
			if relative == "go.mod" && modulePath == "google.golang.org/grpc" {
				t.Errorf("root go.mod directly requires forbidden gRPC module %q", modulePath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk no-RPC public surface: %v", err)
	}
}

func directGoModRequirements(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var requirements []string
	inRequireBlock := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		syntax := trimmed
		var commentFields []string
		if comment := strings.Index(syntax, "//"); comment >= 0 {
			commentFields = strings.Fields(strings.TrimSpace(syntax[comment+2:]))
			syntax = strings.TrimSpace(syntax[:comment])
		}
		fields := strings.Fields(syntax)
		switch {
		case syntax == "require(" || len(fields) == 2 && fields[0] == "require" && fields[1] == "(":
			inRequireBlock = true
			continue
		case inRequireBlock && len(fields) == 1 && fields[0] == ")":
			inRequireBlock = false
			continue
		}
		if len(commentFields) == 1 && commentFields[0] == "indirect" ||
			len(commentFields) > 1 && commentFields[0] == "indirect;" {
			continue
		}
		if inRequireBlock && len(fields) >= 2 {
			requirements = append(requirements, unquoteGoModString(t, path, fields[0]))
		}
		if !inRequireBlock && len(fields) >= 3 && fields[0] == "require" {
			requirements = append(requirements, unquoteGoModString(t, path, fields[1]))
		}
	}
	return requirements
}

func unquoteGoModString(t *testing.T, path, token string) string {
	t.Helper()
	if !strings.HasPrefix(token, `"`) {
		return token
	}
	value, err := strconv.Unquote(token)
	if err != nil {
		t.Fatalf("unquote module path %q in %s: %v", token, path, err)
	}
	return value
}

func taskScopedGoSources(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read repository root: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
			paths = append(paths, entry.Name())
		}
	}

	runtimeRoot := filepath.Join(root, "runtime")
	err = filepath.WalkDir(runtimeRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			paths = append(paths, relative)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
	return paths
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	path, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
			return path
		}
		parent := filepath.Dir(path)
		if parent == path {
			t.Fatal("could not find repository root")
		}
		path = parent
	}
}
