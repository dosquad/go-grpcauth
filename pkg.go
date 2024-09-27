// Package grpcauth is used to provide helper functions for client and server gRPC
// authentication using Basic or Bearer authorization.
package grpcauth

import grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"

var (
	// UnaryServerInterceptor returns a new unary server interceptors that performs per-request auth.
	//
	//nolint:gochecknoglobals // bringing in external function as virtual constants.
	UnaryServerInterceptor = grpc_auth.UnaryServerInterceptor

	// StreamServerInterceptor returns a new unary server interceptors that performs per-request auth.
	//
	//nolint:gochecknoglobals // bringing in external function as virtual constants.
	StreamServerInterceptor = grpc_auth.StreamServerInterceptor
)
