package management

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

const approvedManagementEndpointCount = 42

var approvedManagementDomains = map[string]struct{}{
	"applications":  {},
	"oidcclients":   {},
	"admission":     {},
	"groupmappings": {},
	"catalog":       {},
	"policies":      {},
}

var approvedManagementEndpointKeys = map[string]struct{}{
	"applications GET /api/v1/applications":                                                                                     {},
	"applications POST /api/v1/applications":                                                                                    {},
	"applications GET /api/v1/applications/{application_open_id}":                                                               {},
	"applications PUT /api/v1/applications/{application_open_id}":                                                               {},
	"applications PUT /api/v1/applications/{application_open_id}/status":                                                        {},
	"applications DELETE /api/v1/applications/{application_open_id}":                                                            {},
	"oidcclients GET /api/v1/applications/{application_open_id}/oidc-clients":                                                   {},
	"oidcclients POST /api/v1/applications/{application_open_id}/oidc-clients":                                                  {},
	"oidcclients GET /api/v1/oidc-clients/{client_id}":                                                                          {},
	"oidcclients GET /api/v1/oidc-clients/{client_id}/security":                                                                 {},
	"oidcclients PUT /api/v1/oidc-clients/{client_id}/security":                                                                 {},
	"oidcclients POST /api/v1/oidc-clients/{client_id}/credentials":                                                             {},
	"oidcclients DELETE /api/v1/oidc-clients/{client_id}/credentials/{credential_id}":                                           {},
	"admission GET /api/v1/applications/{application_open_id}/login-admission-rules":                                            {},
	"admission POST /api/v1/applications/{application_open_id}/login-admission-rules":                                           {},
	"admission PUT /api/v1/applications/{application_open_id}/login-admission-rules/{rule_open_id}":                             {},
	"admission DELETE /api/v1/applications/{application_open_id}/login-admission-rules/{rule_open_id}":                          {},
	"admission GET /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/login-admission-rules":                   {},
	"admission POST /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/login-admission-rules":                  {},
	"admission PUT /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/login-admission-rules/{rule_open_id}":    {},
	"admission DELETE /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/login-admission-rules/{rule_open_id}": {},
	"groupmappings GET /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/group-mappings":                      {},
	"groupmappings POST /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/group-mappings":                     {},
	"groupmappings PUT /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/group-mappings/{role_open_id}":       {},
	"groupmappings DELETE /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/group-mappings/{role_open_id}":    {},
	"catalog GET /api/v1/applications/{application_open_id}/http-resource-catalog":                                              {},
	"catalog POST /api/v1/applications/{application_open_id}/http-resource-servers":                                             {},
	"catalog PUT /api/v1/applications/{application_open_id}/http-resource-servers/{resource_server_open_id}":                    {},
	"catalog POST /api/v1/applications/{application_open_id}/http-resources":                                                    {},
	"catalog PUT /api/v1/applications/{application_open_id}/http-resources/{resource_open_id}":                                  {},
	"catalog POST /api/v1/applications/{application_open_id}/http-actions":                                                      {},
	"catalog PUT /api/v1/applications/{application_open_id}/http-actions/{action_open_id}":                                      {},
	"catalog PUT /api/v1/applications/{application_open_id}/http-method-mappings":                                               {},
	"catalog POST /api/v1/applications/{application_open_id}/http-resource-catalog/publish":                                     {},
	"catalog DELETE /api/v1/applications/{application_open_id}/http-resource-catalog/{entity_type}/{entity_open_id}":            {},
	"policies GET /api/v1/policy-documents":                                                                                     {},
	"policies GET /api/v1/policy-documents/{policy_document_open_id}":                                                           {},
	"policies POST /api/v1/policy-documents":                                                                                    {},
	"policies PUT /api/v1/policy-documents/{policy_document_open_id}":                                                           {},
	"policies POST /api/v1/policy-documents/preview":                                                                            {},
	"policies PUT /api/v1/policy-documents/{policy_document_open_id}/bindings":                                                  {},
	"policies GET /api/v1/policy-compiled-rules":                                                                                {},
}

type contractEndpoint struct {
	Domain string `json:"domain"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

type operationRegistration struct {
	Domain    string
	Method    string
	Path      string
	Operation string
}

var implementedManagementOperations = []operationRegistration{
	{"applications", "GET", "/api/v1/applications", "management.applications.list"},
	{"applications", "POST", "/api/v1/applications", "management.applications.create"},
	{"applications", "GET", "/api/v1/applications/{application_open_id}", "management.applications.get"},
	{"applications", "PUT", "/api/v1/applications/{application_open_id}", "management.applications.update"},
	{"applications", "PUT", "/api/v1/applications/{application_open_id}/status", "management.applications.set_enabled"},
	{"applications", "DELETE", "/api/v1/applications/{application_open_id}", "management.applications.hard_delete"},

	{"oidcclients", "GET", "/api/v1/applications/{application_open_id}/oidc-clients", "management.oidcclients.list"},
	{"oidcclients", "POST", "/api/v1/applications/{application_open_id}/oidc-clients", "management.oidcclients.create"},
	{"oidcclients", "GET", "/api/v1/oidc-clients/{client_id}", "management.oidcclients.get"},
	{"oidcclients", "GET", "/api/v1/oidc-clients/{client_id}/security", "management.oidcclients.get_security"},
	{"oidcclients", "PUT", "/api/v1/oidc-clients/{client_id}/security", "management.oidcclients.update_security"},
	{"oidcclients", "POST", "/api/v1/oidc-clients/{client_id}/credentials", "management.oidcclients.create_credential"},
	{"oidcclients", "DELETE", "/api/v1/oidc-clients/{client_id}/credentials/{credential_id}", "management.oidcclients.revoke_credential"},

	{"admission", "GET", "/api/v1/applications/{application_open_id}/login-admission-rules", "management.admission.list"},
	{"admission", "POST", "/api/v1/applications/{application_open_id}/login-admission-rules", "management.admission.create"},
	{"admission", "PUT", "/api/v1/applications/{application_open_id}/login-admission-rules/{rule_open_id}", "management.admission.update"},
	{"admission", "DELETE", "/api/v1/applications/{application_open_id}/login-admission-rules/{rule_open_id}", "management.admission.soft_delete"},
	{"admission", "GET", "/api/v1/applications/{application_open_id}/oidc-clients/{client_id}/login-admission-rules", "management.admission.list"},
	{"admission", "POST", "/api/v1/applications/{application_open_id}/oidc-clients/{client_id}/login-admission-rules", "management.admission.create"},
	{"admission", "PUT", "/api/v1/applications/{application_open_id}/oidc-clients/{client_id}/login-admission-rules/{rule_open_id}", "management.admission.update"},
	{"admission", "DELETE", "/api/v1/applications/{application_open_id}/oidc-clients/{client_id}/login-admission-rules/{rule_open_id}", "management.admission.soft_delete"},

	{"groupmappings", "GET", "/api/v1/applications/{application_open_id}/oidc-clients/{client_id}/group-mappings", "management.groupmappings.get"},
	{"groupmappings", "POST", "/api/v1/applications/{application_open_id}/oidc-clients/{client_id}/group-mappings", "management.groupmappings.create"},
	{"groupmappings", "PUT", "/api/v1/applications/{application_open_id}/oidc-clients/{client_id}/group-mappings/{role_open_id}", "management.groupmappings.update"},
	{"groupmappings", "DELETE", "/api/v1/applications/{application_open_id}/oidc-clients/{client_id}/group-mappings/{role_open_id}", "management.groupmappings.soft_delete"},

	{"catalog", "GET", "/api/v1/applications/{application_open_id}/http-resource-catalog", "management.catalog.get"},
	{"catalog", "POST", "/api/v1/applications/{application_open_id}/http-resource-servers", "management.catalog.create_resource_server"},
	{"catalog", "PUT", "/api/v1/applications/{application_open_id}/http-resource-servers/{resource_server_open_id}", "management.catalog.update_resource_server"},
	{"catalog", "POST", "/api/v1/applications/{application_open_id}/http-resources", "management.catalog.create_resource"},
	{"catalog", "PUT", "/api/v1/applications/{application_open_id}/http-resources/{resource_open_id}", "management.catalog.update_resource"},
	{"catalog", "POST", "/api/v1/applications/{application_open_id}/http-actions", "management.catalog.create_action"},
	{"catalog", "PUT", "/api/v1/applications/{application_open_id}/http-actions/{action_open_id}", "management.catalog.update_action"},
	{"catalog", "PUT", "/api/v1/applications/{application_open_id}/http-method-mappings", "management.catalog.put_method_mapping"},
	{"catalog", "POST", "/api/v1/applications/{application_open_id}/http-resource-catalog/publish", "management.catalog.publish"},
	{"catalog", "DELETE", "/api/v1/applications/{application_open_id}/http-resource-catalog/{entity_type}/{entity_open_id}", "management.catalog.deactivate"},

	{"policies", "GET", "/api/v1/policy-documents", "management.policies.list"},
	{"policies", "GET", "/api/v1/policy-documents/{policy_document_open_id}", "management.policies.get"},
	{"policies", "POST", "/api/v1/policy-documents", "management.policies.create"},
	{"policies", "PUT", "/api/v1/policy-documents/{policy_document_open_id}", "management.policies.update"},
	{"policies", "POST", "/api/v1/policy-documents/preview", "management.policies.preview"},
	{"policies", "PUT", "/api/v1/policy-documents/{policy_document_open_id}/bindings", "management.policies.set_bindings"},
	{"policies", "GET", "/api/v1/policy-compiled-rules", "management.policies.list_compiled_rules"},
}

func TestApprovedManagementContract(t *testing.T) {
	contents, err := os.ReadFile("testdata/contract-v1.8.1.json")
	if err != nil {
		t.Fatalf("read approved management contract: %v", err)
	}

	var endpoints []contractEndpoint
	if err := json.Unmarshal(contents, &endpoints); err != nil {
		t.Fatalf("decode approved management contract: %v", err)
	}

	if err := validateApprovedManagementContract(endpoints); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range endpoints {
		key := endpoint.Domain + " " + endpoint.Method + " " + endpoint.Path
		if _, ok := approvedManagementEndpointKeys[key]; !ok {
			t.Fatalf("unapproved endpoint %s", key)
		}
	}
}

func TestImplementedManagementOperationsExactlyMatchApprovedContract(t *testing.T) {
	contents, err := os.ReadFile("testdata/contract-v1.8.1.json")
	if err != nil {
		t.Fatalf("read approved management contract: %v", err)
	}
	var approved []contractEndpoint
	if err := json.Unmarshal(contents, &approved); err != nil {
		t.Fatalf("decode approved management contract: %v", err)
	}

	want := make(map[string]struct{}, len(approved))
	for _, endpoint := range approved {
		want[endpoint.Domain+" "+endpoint.Method+" "+endpoint.Path] = struct{}{}
	}
	got := make(map[string]string, len(implementedManagementOperations))
	for _, operation := range implementedManagementOperations {
		key := operation.Domain + " " + operation.Method + " " + operation.Path
		if previous, duplicate := got[key]; duplicate {
			t.Fatalf("endpoint %s registered more than once (%s and %s)", key, previous, operation.Operation)
		}
		if !strings.HasPrefix(operation.Operation, "management."+operation.Domain+".") {
			t.Fatalf("endpoint %s has invalid operation %q", key, operation.Operation)
		}
		got[key] = operation.Operation
	}
	if len(got) != approvedManagementEndpointCount {
		t.Fatalf("registered endpoint count = %d, want %d", len(got), approvedManagementEndpointCount)
	}
	for key := range want {
		if _, ok := got[key]; !ok {
			t.Errorf("approved endpoint is not registered: %s", key)
		}
	}
	for key := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("unapproved endpoint is registered: %s", key)
		}
	}
}

func TestValidateApprovedManagementContractRejectsInvalidFixture(t *testing.T) {
	valid := make([]contractEndpoint, approvedManagementEndpointCount)
	for i := range valid {
		valid[i] = contractEndpoint{
			Domain: "applications",
			Method: "GET",
			Path:   fmt.Sprintf("/api/v1/applications/%d", i),
		}
	}

	tests := []struct {
		name      string
		endpoints []contractEndpoint
		want      string
	}{
		{
			name:      "wrong entry count",
			endpoints: valid[:approvedManagementEndpointCount-1],
			want:      "expected 42 endpoints",
		},
		{
			name: "duplicate method path pair",
			endpoints: func() []contractEndpoint {
				endpoints := append([]contractEndpoint(nil), valid...)
				endpoints[1] = endpoints[0]
				return endpoints
			}(),
			want: "duplicate endpoint GET /api/v1/applications/0",
		},
		{
			name: "unknown domain",
			endpoints: func() []contractEndpoint {
				endpoints := append([]contractEndpoint(nil), valid...)
				endpoints[0].Domain = "users"
				return endpoints
			}(),
			want: "unknown domain \"users\"",
		},
		{
			name: "path outside api v1",
			endpoints: func() []contractEndpoint {
				endpoints := append([]contractEndpoint(nil), valid...)
				endpoints[0].Path = "/api/v2/applications"
				return endpoints
			}(),
			want: "outside /api/v1/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateApprovedManagementContract(tt.endpoints)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateApprovedManagementContract() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func validateApprovedManagementContract(endpoints []contractEndpoint) error {
	if len(endpoints) != approvedManagementEndpointCount {
		return fmt.Errorf("expected %d endpoints, got %d", approvedManagementEndpointCount, len(endpoints))
	}

	seen := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if _, ok := approvedManagementDomains[endpoint.Domain]; !ok {
			return fmt.Errorf("unknown domain %q", endpoint.Domain)
		}
		if !strings.HasPrefix(endpoint.Path, "/api/v1/") {
			return fmt.Errorf("endpoint path %q is outside /api/v1/", endpoint.Path)
		}

		pair := endpoint.Method + " " + endpoint.Path
		if _, ok := seen[pair]; ok {
			return fmt.Errorf("duplicate endpoint %s", pair)
		}
		seen[pair] = struct{}{}
	}

	return nil
}
