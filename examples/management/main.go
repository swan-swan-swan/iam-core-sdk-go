// Command management demonstrates explicitly invoked IAM Core administration.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"

	"github.com/swan-swan-swan/iam-core-sdk-go/management/admission"
	"github.com/swan-swan-swan/iam-core-sdk-go/management/applications"
	management "github.com/swan-swan-swan/iam-core-sdk-go/management/client"
)

type fixedTokenSource struct{ accessToken string }

func (source fixedTokenSource) AccessToken(context.Context) (string, error) {
	return source.accessToken, nil
}

func main() {
	if err := run(context.Background(), os.Getenv, os.Stdout); err != nil {
		// Deliberately omit the underlying error because it may originate outside the SDK.
		slog.Error("IAM Core management example failed", slog.String("reason", "configuration is invalid or IAM is unavailable"))
		os.Exit(1)
	}
}

func run(ctx context.Context, lookup func(string) string, output io.Writer) error {
	transport, err := management.New(management.Config{
		BaseURL: lookup("IAMCORE_MANAGEMENT_BASE_URL"),
		TokenSource: fixedTokenSource{
			accessToken: lookup("IAMCORE_MANAGEMENT_ACCESS_TOKEN"),
		},
	})
	if err != nil {
		return errors.New("management configuration is invalid")
	}

	applicationClient, err := applications.New(transport)
	if err != nil {
		return errors.New("application client configuration is invalid")
	}
	items, _, err := applicationClient.List(ctx)
	if err != nil {
		return errors.New("application list failed")
	}
	if _, err := fmt.Fprintf(output, "applications: %d\n", len(items)); err != nil {
		return errors.New("write result failed")
	}

	if lookup("IAMCORE_EXAMPLE_APPLY_ADMISSION_UPDATE") != "true" {
		return nil
	}
	revision, err := strconv.ParseUint(lookup("IAMCORE_ADMISSION_LOGIN_POLICY_REVISION"), 10, 64)
	if err != nil || revision == 0 {
		return errors.New("admission revision is invalid")
	}
	admissionClient, err := admission.New(transport)
	if err != nil {
		return errors.New("admission client configuration is invalid")
	}
	change, _, err := admissionClient.Update(
		ctx,
		admission.ApplicationScope(lookup("IAMCORE_APPLICATION_OPEN_ID")),
		lookup("IAMCORE_ADMISSION_RULE_OPEN_ID"),
		admission.Mutation{
			SubjectType:      lookup("IAMCORE_ADMISSION_SUBJECT_TYPE"),
			SubjectOpenID:    lookup("IAMCORE_ADMISSION_SUBJECT_OPEN_ID"),
			Effect:           lookup("IAMCORE_ADMISSION_EFFECT"),
			ExpectedRevision: revision,
		},
	)
	if err != nil {
		return errors.New("admission update failed")
	}
	if _, err := fmt.Fprintf(output, "admission revision: %d\n", change.Revision); err != nil {
		return errors.New("write result failed")
	}
	return nil
}
