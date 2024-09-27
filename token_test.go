package grpcauth_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/dosquad/go-grpcauth"
	"github.com/dosquad/go-grpcauth/test"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func TestToken_Fail_NonTLS(t *testing.T) {
	tests := []struct {
		name, token string
	}{
		{"Valid online token", "valid-online-token"},
		{"Valid offline token", "valid-offline-token"},
		{"Invalid token", "invalid-token"},
		{"Empty Token", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, gs := test.NewServer(basicAuthFunc, bearerAuthFunc)
			defer gs.Stop()

			tokenAuthCreds := grpcauth.NewTokenCredentials(tt.token)

			opts := []grpc.DialOption{
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithPerRPCCredentials(tokenAuthCreds),
			}

			_, err := grpc.NewClient(l.Addr().String(), opts...)
			if err == nil {
				t.Error("expected error to be returned, but error returned nil")
			}
			if err != nil && !strings.Contains(err.Error(), "credentials require transport level security") {
				t.Errorf("expected error to contain 'credentials require transport level security', but received '%s'", err.Error())
			}
		})
	}
}

func testTokenTLSVerify(t *testing.T, c test.TestClient, user string, online, expectedPass bool) {
	t.Helper()

	var (
		r       *test.Response
		testErr error
	)

	if online {
		r, testErr = c.TestOnline(context.Background(), &test.EmptyRequest{})
	} else {
		r, testErr = c.TestOffline(context.Background(), &test.EmptyRequest{})
	}

	if expectedPass {
		testTokenTLSVerifyExpectedPass(t, testErr, r, user, online)
	} else {
		testTokenTLSVerifyExpectedFail(t, testErr, r)
	}
}

func testTokenTLSVerifyExpectedPass(t *testing.T, testErr error, r *test.Response, user string, online bool) {
	t.Helper()

	if testErr != nil {
		t.Errorf("expected error to be nil, returned '%v'", testErr)
	}
	if r == nil {
		t.Error("result should not be nil when no error is returned")
	}
	if r.GetUser() != user {
		t.Errorf("expected r.User to be '%s', received '%s'", user, r.GetUser())
	}
	if r.GetOnline() != online {
		t.Errorf("expected r.Online to be '%t', received '%t'", online, r.GetOnline())
	}
}

func testTokenTLSVerifyExpectedFail(t *testing.T, testErr error, r *test.Response) {
	t.Helper()

	if testErr == nil {
		t.Error("expected error to be returned, but error returned nil")
	}

	if r != nil {
		t.Error("result should be nil when error returned")
	}
}

func TestToken_TLS(t *testing.T) {
	tests := []struct {
		name, token, user    string
		online, expectedPass bool
	}{
		{"will work with valid online token and online request", "valid-online-token", "online-user", true, true},
		{"will work with valid offline token and offline request", "valid-offline-token", "offline-user", false, true},
		{"will fail with valid offline token and online request", "valid-offline-token", "", true, false},
		{"will fail with valid online token and offline request", "valid-online-token", "", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gsCreds, err := credentials.NewServerTLSFromFile("artifacts/certs/server.pem", "artifacts/certs/server-key.pem")
			if err != nil {
				t.Errorf("expected error to be nil, returned '%v'", err)
			}

			l, gs := test.NewServer(
				basicAuthFunc,
				bearerAuthFunc,
				grpc.Creds(gsCreds),
			)
			defer gs.Stop()

			opts := []grpc.DialOption{
				dialTLSVerification(t),
				grpc.WithPerRPCCredentials(grpcauth.NewTokenCredentials(tt.token)),
			}

			cc, err := grpc.NewClient(l.Addr().String(), opts...)
			if err != nil {
				t.Errorf("expected error to be nil, returned '%v'", err)
			}
			defer cc.Close()

			c := test.NewTestClient(cc)

			testTokenTLSVerify(t, c, tt.user, tt.online, tt.expectedPass)
		})
	}
}

func TestToken_ExpectedFailures(t *testing.T) {
	tests := []struct {
		name, token string
	}{
		{"Invalid Token", "invalid-token"},
		{"Empty Token", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gsCreds, err := credentials.NewServerTLSFromFile("artifacts/certs/server.pem", "artifacts/certs/server-key.pem")
			if err != nil {
				t.Errorf("expected error to be nil, returned '%v'", err)
			}

			l, gs := test.NewServer(
				basicAuthFunc,
				bearerAuthFunc,
				grpc.Creds(gsCreds),
			)
			defer gs.Stop()

			opts := []grpc.DialOption{
				dialTLSVerification(t),
				grpc.WithPerRPCCredentials(grpcauth.NewTokenCredentials(tt.token)),
			}

			cc, err := grpc.NewClient(l.Addr().String(), opts...)
			if err != nil {
				t.Errorf("expected error to be nil, returned '%v'", err)
			}
			defer cc.Close()

			c := test.NewTestClient(cc)

			r, err := c.TestOnline(context.Background(), &test.EmptyRequest{})
			if err == nil {
				t.Error("expected error to be returned, but error returned nil")
			}

			if err != nil && !strings.Contains(err.Error(), "authentication failed with Bearer authorization scheme") {
				t.Errorf(
					"expected error to contain 'authentication failed with Bearer authorization scheme', but received '%s'",
					err.Error(),
				)
			}

			if r != nil {
				t.Error("result should be nil when error returned")
			}
		})
	}
}

func TestToken_Succeed_PassCustomContextTag(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{
		"authorization": []string{
			fmt.Sprintf("Bearer %s", validOnlineTokenWithCustomTag),
		},
	})

	authCtx, err := grpcauth.VerifyAuthorizationFunc(basicAuthFunc, bearerAuthFunc)(ctx)

	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}

	if v := authCtx.Value(grpcauth.Username); v != "online-user" {
		t.Errorf("expected context value grpcauth.Username to equal '%s', received '%s'", "online-user", v)
	}

	if v := authCtx.Value(grpcauth.Online); v != true {
		t.Errorf("expected context value grpcauth.Online to equal '%t', received '%t'", true, v)
	}

	if v := authCtx.Value(testTag); v != "test-tag-goes-here" {
		t.Errorf("expected context value testTag to equal '%s', received '%s'", "test-tag-goes-here", v)
	}
}

func TestToken_Fail_SecurityLevel(t *testing.T) {
	ctx := context.TODO()
	creds := grpcauth.NewTokenCredentials("new-token")
	r, err := creds.GetRequestMetadata(ctx)
	if err == nil {
		t.Error("expected error to be returned, but error returned nil")
	}

	if r != nil {
		t.Error("result should be nil when error returned")
	}
}
