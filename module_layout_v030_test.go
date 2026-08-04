package iamcoresdk_test

import (
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
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
	}
	for _, path := range required {
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Errorf("required path %s: %v", path, err)
		}
	}

	forbidden := []string{"core", "bff", "httpauthz", "testkit", "rpc"}
	for _, path := range forbidden {
		if _, err := os.Stat(filepath.Join(root, path)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("legacy or forbidden path still exists: %s", path)
		}
	}

	if declaration := strings.SplitN(rootModule, "\n", 2)[0]; declaration != "module github.com/swan-swan-swan/iam-core-sdk-go" {
		t.Errorf("root module declaration = %q, want %q", declaration, "module github.com/swan-swan-swan/iam-core-sdk-go")
	}

	const legacyModule = "github.com/swan-swan-swan/iam-core-client-sdk-go"
	for _, path := range taskScopedGoSources(t, root) {
		parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, path), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imported := range parsed.Imports {
			importPath := strings.Trim(imported.Path.Value, "\"")
			if importPath == legacyModule || strings.HasPrefix(importPath, legacyModule+"/") {
				t.Errorf("%s imports legacy module path %q", path, importPath)
			}
		}
	}
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
