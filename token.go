package grpcauth

import (
	"context"
	"fmt"

	"google.golang.org/grpc/credentials"
)

// NewTokenCredentials returns a new PerRPCCredentials implementation, configured
// using the raw token.
func NewTokenCredentials(token string) credentials.PerRPCCredentials {
	return &TokenCreds{
		token: token,
	}
}

type TokenCreds struct {
	token string
}

// GetRequestMetadata adds the HTTP Authorization Bearer header to the request.
func (c *TokenCreds) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	ri, _ := credentials.RequestInfoFromContext(ctx)
	if err := credentials.CheckSecurityLevel(ri.AuthInfo, credentials.PrivacyAndIntegrity); err != nil {
		return nil, fmt.Errorf("unable to transfer Token PerRPCCredentials: %w", err)
	}

	return map[string]string{"Authorization": "Bearer " + c.token}, nil
}

// RequireTransportSecurity indicates whether the credentials requires
// transport security.
func (c *TokenCreds) RequireTransportSecurity() bool {
	return true
}
