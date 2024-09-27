package test

import (
	"context"
	"net"

	"github.com/dosquad/go-grpcauth"
	"golang.org/x/net/nettest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func NewServer(
	basicAuthFunc grpcauth.AuthVerifyBasicFunc,
	bearerAuthFunc grpcauth.AuthVerifyBearerFunc,
	opts ...grpc.ServerOption,
) (net.Listener, *grpc.Server) {
	lis, err := nettest.NewLocalListener("tcp")
	if err != nil {
		return nil, nil
	}

	opts = append(
		opts,
		grpc.StreamInterceptor(
			grpcauth.StreamServerInterceptor(grpcauth.VerifyAuthorizationFunc(basicAuthFunc, bearerAuthFunc)),
		),
		grpc.UnaryInterceptor(
			grpcauth.UnaryServerInterceptor(grpcauth.VerifyAuthorizationFunc(basicAuthFunc, bearerAuthFunc)),
		),
	)
	grpcServer := grpc.NewServer(opts...)
	RegisterTestServer(grpcServer, &testServer{})

	go func() {
		_ = grpcServer.Serve(lis)
		defer lis.Close()
	}()

	return lis, grpcServer
}

type testServer struct{}

func (t *testServer) TestOnline(ctx context.Context, _ *EmptyRequest) (*Response, error) {
	if v, ok := ctx.Value(grpcauth.Online).(bool); ok && v {
		user := ""
		if u, userOk := ctx.Value(grpcauth.Username).(string); userOk {
			user = u
		}

		return &Response{
			User:   user,
			Online: v,
		}, nil
	}

	return nil, status.Error(codes.Unauthenticated, "request requires an online token")
}

func (t *testServer) TestOffline(ctx context.Context, _ *EmptyRequest) (*Response, error) {
	online := false
	user := ""

	if v, ok := ctx.Value(grpcauth.Online).(bool); ok {
		online = v
	}

	if u, ok := ctx.Value(grpcauth.Username).(string); ok {
		user = u
	}

	if online {
		return nil, status.Error(codes.Unauthenticated, "request requires an offline token")
	}

	return &Response{
		User:   user,
		Online: online,
	}, nil
}
