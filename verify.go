package grpcauth

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var re = regexp.MustCompile(`^(\S+)\s+(.*)$`)

const (
	authorizationHeader = "authorization"
)

// AuthVerifyBasicFunc is used to verify HTTP Basic Authorization headers.
type AuthVerifyBasicFunc = func(context.Context, string, string) (context.Context, string, bool)

// AuthVerifyBearerFunc is used to verify HTTP Bearer Authorization headers.
type AuthVerifyBearerFunc = func(context.Context, string) (context.Context, string, bool, bool)

type contextValue string

const (
	// Username is the context value of the username returned by the authentication verification function.
	Username contextValue = "username"

	// Online is the context value indicating if a authentication method was online or offline.
	Online contextValue = "online"
)

func getHeadersFromContext(ctx context.Context) []string {
	if headers, ok := metadata.FromIncomingContext(ctx); ok {
		return headers.Get(authorizationHeader)
	}

	return []string{}
}

//nolint:wrapcheck,mnd // expected set length based on format.
func verifyAuthBasic(ctx context.Context, basicAuth AuthVerifyBasicFunc, encodedAuth string) (context.Context, error) {
	bo, err := base64.StdEncoding.DecodeString(encodedAuth)
	if err != nil {
		return ctx, status.Error(codes.Unauthenticated, "authentication failed with Basic authorization scheme")
	}

	authString := strings.SplitN(string(bo), ":", 2)
	if len(authString) != 2 {
		return ctx, status.Error(codes.Unauthenticated, "authentication failed with Basic authorization scheme")
	}

	if outCtx, u, ok := basicAuth(ctx, authString[0], authString[1]); ok {
		outCtx = context.WithValue(outCtx, Username, u)
		outCtx = context.WithValue(outCtx, Online, true)

		return outCtx, nil
	}

	return ctx, status.Error(codes.Unauthenticated, "authentication failed with Basic authorization scheme")
}

func verifyAuthBearer(ctx context.Context, bearerAuth AuthVerifyBearerFunc, token string) (context.Context, error) {
	if outCtx, u, online, ok := bearerAuth(ctx, token); ok {
		outCtx = context.WithValue(outCtx, Username, u)
		outCtx = context.WithValue(outCtx, Online, online)

		return outCtx, nil
	}

	return ctx, status.Error(codes.Unauthenticated, "authentication failed with Bearer authorization scheme")
}

// VerifyAuthorizationFunc returns a function that can be used to verify the authentication on a gRPC request.
//
//nolint:mnd // expected set length based on format.
func VerifyAuthorizationFunc(
	basicAuth AuthVerifyBasicFunc,
	bearerAuth AuthVerifyBearerFunc,
) func(ctx context.Context) (context.Context, error) {
	return func(ctx context.Context) (context.Context, error) {
		for _, auth := range getHeadersFromContext(ctx) {
			if re.MatchString(auth) {
				r := re.FindStringSubmatch(auth)
				if len(r) >= 3 {
					switch strings.ToLower(r[1]) {
					case "basic":
						return verifyAuthBasic(ctx, basicAuth, r[2])
					case "bearer":
						return verifyAuthBearer(ctx, bearerAuth, r[2])
					}
				}
			}
		}

		return ctx, status.Errorf(codes.Unauthenticated, "authentication missing")
	}
}
