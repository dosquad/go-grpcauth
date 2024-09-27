package grpcauth_test

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type testContextValue string

const testTag testContextValue = "test"

//nolint:gochecknoglobals // test code
var (
	validAuth                     = basicAuth{[]byte("valid-user"), []byte("valid-pass")}
	validOnlineToken              = []byte("valid-online-token")
	validOnlineTokenWithCustomTag = []byte("valid-online-token-with-custom-tag")
	validOfflineToken             = []byte("valid-offline-token")
	basicAuthFunc                 = func(ctx context.Context, u string, p string) (context.Context, string, bool) {
		userValid := false
		passValid := false
		if subtle.ConstantTimeCompare([]byte(u), validAuth.U) == 1 {
			userValid = true
		}

		if subtle.ConstantTimeCompare([]byte(p), validAuth.P) == 1 {
			passValid = true
		}

		return ctx, u, (userValid && passValid)
	}
	bearerAuthFunc = func(ctx context.Context, token string) (context.Context, string, bool, bool) {
		if subtle.ConstantTimeCompare([]byte(token), validOnlineToken) == 1 {
			return ctx, "online-user", true, true
		}

		if subtle.ConstantTimeCompare([]byte(token), validOnlineTokenWithCustomTag) == 1 {
			ctx = context.WithValue(ctx, testTag, "test-tag-goes-here")

			return ctx, "online-user", true, true
		}

		if subtle.ConstantTimeCompare([]byte(token), validOfflineToken) == 1 {
			return ctx, "offline-user", false, true
		}

		return ctx, "", false, false
	}
)

func dialTLSVerification(t *testing.T) grpc.DialOption {
	t.Helper()

	pool := x509.NewCertPool()
	cadata, err := os.ReadFile("artifacts/certs/ca.pem")
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}

	capem, _ := pem.Decode(cadata)
	cacert, err := x509.ParseCertificate(capem.Bytes)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}

	pool.AddCert(cacert)
	creds := credentials.NewClientTLSFromCert(pool, "")

	return grpc.WithTransportCredentials(creds)
}
