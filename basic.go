package grpcauth

import (
	"context"
	"encoding/base64"
	"fmt"

	"google.golang.org/grpc/credentials"
)

// NewBasicCredentials returns a new PerRPCCredentials implementation configured
// with the plain-text username and password.
func NewBasicCredentials(u, p string) credentials.PerRPCCredentials {
	return &BasicCreds{
		user: u,
		pass: p,
	}
}

type BasicCreds struct {
	user, pass string
}

// GetRequestMetadata adds the HTTP Authorization Basic header to the request.
func (c *BasicCreds) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	ri, _ := credentials.RequestInfoFromContext(ctx)
	if err := credentials.CheckSecurityLevel(ri.AuthInfo, credentials.PrivacyAndIntegrity); err != nil {
		return nil, fmt.Errorf("unable to transfer Basic PerRPCCredentials: %w", err)
	}

	authString := base64.StdEncoding.EncodeToString([]byte(c.user + ":" + c.pass))

	return map[string]string{"Authorization": "Basic " + authString}, nil
}

// RequireTransportSecurity indicates whether the credentials requires
// transport security.
func (c *BasicCreds) RequireTransportSecurity() bool {
	return true
}
