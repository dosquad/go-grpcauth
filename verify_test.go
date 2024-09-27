package grpcauth_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/dosquad/go-grpcauth"
	"google.golang.org/grpc/metadata"
)

type basicAuth struct {
	U []byte
	P []byte
}

func TestVerify_Basic_ExpectedFailures(t *testing.T) {
	tests := []struct {
		name, user, pass string
	}{
		{"Invalid Username and Password", "invalid-user", "invalid-pass"},
		{"Invalid Username and Valid Password", "invalid-user", "valid-pass"},
		{"Valid Username and Invalid Password", "valid-user", "invalid-pass"},
		{"Empty Username and Password", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{
				"authorization": []string{
					"Basic " + base64.StdEncoding.EncodeToString([]byte(tt.user+":"+tt.pass)),
				},
			})
			authCtx, err := grpcauth.VerifyAuthorizationFunc(basicAuthFunc, bearerAuthFunc)(ctx)
			if err == nil {
				t.Error("expected error to be returned, but error returned nil")
			}

			if v := authCtx.Value(grpcauth.Username); v != nil {
				t.Errorf("expected context value grpcauth.Online to be nil, received '%s'", v)
			}

			if v := authCtx.Value(grpcauth.Online); v != nil {
				t.Errorf("expected context value grpcauth.Online to be nil, received '%t'", v)
			}
		})
	}
}

func TestVerify_Basic_Success_ValidUserPass(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{
		"authorization": []string{
			"Basic " + base64.StdEncoding.EncodeToString([]byte("valid-user:valid-pass")),
		},
	})
	authCtx, err := grpcauth.VerifyAuthorizationFunc(basicAuthFunc, bearerAuthFunc)(ctx)
	if err != nil {
		t.Errorf("expected error to be nil, returned '%v'", err)
	}
	if v := authCtx.Value(grpcauth.Username); v != "valid-user" {
		t.Errorf("expected context value grpcauth.Username to be '%s', received '%s'", "valid-user", v)
	}
	if v := authCtx.Value(grpcauth.Online); v != true {
		t.Errorf("expected context value grpcauth.Online to be '%t', received '%t'", true, v)
	}
}

func TestVerify_Basic_Fail_MalformedHeader(t *testing.T) {
	tests := []struct {
		name, header string
	}{
		{"Malformed Basic Header: Invalid Base64", "Basic ####"},
		{"Malformed Basic Header: Invalid Base64", "Basic =="},
		{"Malformed Basic Header: Invalid Format", "Basic aaaa"},
		{"Malformed Bearer Header: Empty Bearer", "Bearer "},
		{"Malformed Bearer Header: Just Bearer", "Bearer"},
		{"Malformed Header: Empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{
				"authorization": []string{tt.header},
			})

			authCtx, err := grpcauth.VerifyAuthorizationFunc(basicAuthFunc, bearerAuthFunc)(ctx)
			if err == nil {
				t.Error("expected error to be returned, but error returned nil")
			}

			if authCtx == nil {
				t.Error("returned context should never be nil")
			}

			if authCtx != nil {
				if v := authCtx.Value(grpcauth.Username); v != nil {
					t.Errorf("expected context value grpcauth.Online to be nil, received '%s'", v)
				}

				if v := authCtx.Value(grpcauth.Online); v != nil {
					t.Errorf("expected context value grpcauth.Online to be nil, received '%t'", v)
				}
			}
		})
	}
}

func TestVerify_Basic_Fail_MissingHeader(t *testing.T) {
	ctx := context.TODO()

	authCtx, err := grpcauth.VerifyAuthorizationFunc(basicAuthFunc, bearerAuthFunc)(ctx)
	if err == nil {
		t.Error("expected error to be returned, but error returned nil")
	}

	if authCtx == nil {
		t.Error("returned context should never be nil")
	}

	if authCtx != nil {
		if v := authCtx.Value(grpcauth.Username); v != nil {
			t.Errorf("expected context value grpcauth.Online to be nil, received '%s'", v)
		}

		if v := authCtx.Value(grpcauth.Online); v != nil {
			t.Errorf("expected context value grpcauth.Online to be nil, received '%t'", v)
		}
	}
}
