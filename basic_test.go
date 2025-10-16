package grpcauth_test

import (
	"context"
	"strings"
	"testing"

	"github.com/dosquad/go-grpcauth"
	"github.com/dosquad/go-grpcauth/test"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func TestBasic_Fail_NonTLS(t *testing.T) {
	l, gs := test.NewServer(basicAuthFunc, bearerAuthFunc)
	defer gs.Stop()

	basicAuthCreds := grpcauth.NewBasicCredentials("valid-user", "valid-pass")

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(basicAuthCreds),
	}

	_, err := grpc.NewClient(l.Addr().String(), opts...)
	if err == nil {
		t.Error("expected error to be returned, but error returned nil")
	}
	if !strings.Contains(err.Error(), "credentials require transport level security") {
		t.Errorf(
			"expected error to contain 'credentials require transport level security' but returned '%s'",
			err.Error(),
		)
	}
}

func TestBasic_Success_TLS_ValidUserPass_Online(t *testing.T) {
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
		grpc.WithPerRPCCredentials(grpcauth.NewBasicCredentials("valid-user", "valid-pass")),
	}

	cc, err := grpc.NewClient(l.Addr().String(), opts...)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	defer cc.Close()

	c := test.NewTestClient(cc)

	r, err := c.TestOnline(context.Background(), &test.EmptyRequest{})
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	if r == nil {
		t.Error("expected result not to be nil")
	}
	if r.GetUser() != "valid-user" {
		t.Errorf("expected result.User to be 'valid-user', received '%s'", r.GetUser())
	}
	if r.GetOnline() != true {
		t.Errorf("expected result.Online to be 'true', received '%t'", r.GetOnline())
	}
}

func TestBasic_Fail_TLS_ValidUserPass_Offline(t *testing.T) {
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
		grpc.WithPerRPCCredentials(grpcauth.NewBasicCredentials("valid-user", "valid-pass")),
	}

	cc, err := grpc.NewClient(l.Addr().String(), opts...)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	defer cc.Close()

	c := test.NewTestClient(cc)

	r, err := c.TestOffline(context.Background(), &test.EmptyRequest{})
	if err == nil {
		t.Error("expected error to be returned, but error returned nil")
	}

	if r != nil {
		t.Error("result should be nil when error returned")
	}
}

func TestBasic_Fail_TLS_InvalidInput(t *testing.T) {
	tests := []struct {
		name, user, pass string
	}{
		{"Invalid Username and Password", "invalid-user", "invalid-pass"},
		{"Invalid Username and Valid Password", "invalid-user", "valid-pass"},
		{"Valid Username and Invalid Password", "valid-user", "invalid-pass"},
		{"Empty Username and Password", "", ""},
		{"Valid Online Token (but as a username)", "valid-online-token", ""},
		{"Valid Offline Token (but as a username)", "valid-offline-token", ""},
		{"Valid Online Token (but as a password)", "", "valid-online-token"},
		{"Valid Offline Token (but as a password)", "", "valid-offline-token"},
		{"Valid Online Token (but as a username and password)", "valid-online-token", "valid-online-token"},
		{"Valid Offline Token (but as a username and password)", "valid-offline-token", "valid-offline-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gsCreds, err := credentials.NewServerTLSFromFile(
				"artifacts/certs/server.pem",
				"artifacts/certs/server-key.pem",
			)
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
				grpc.WithPerRPCCredentials(grpcauth.NewBasicCredentials(tt.user, tt.pass)),
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

			if err != nil && !strings.Contains(err.Error(), "authentication failed with Basic authorization scheme") {
				t.Errorf(
					"expected error to contain 'authentication failed with Basic authorization scheme', but received '%s'",
					err.Error(),
				)
			}

			if r != nil {
				t.Error("result should be nil when error returned")
			}
		})
	}
}

func TestBasic_Fail_SecurityLevel(t *testing.T) {
	ctx := context.TODO()
	creds := grpcauth.NewBasicCredentials("user", "pass")
	r, err := creds.GetRequestMetadata(ctx)
	if err == nil {
		t.Error("expected error to be returned, but error returned nil")
	}

	if r != nil {
		t.Error("result should be nil when error returned")
	}
}
