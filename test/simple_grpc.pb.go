// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.28.2
// source: github.com/dosquad/go-grpcauth/test/simple.proto

package test

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	Test_TestOffline_FullMethodName = "/grpcauth.test.Test/TestOffline"
	Test_TestOnline_FullMethodName  = "/grpcauth.test.Test/TestOnline"
)

// TestClient is the client API for Test service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TestClient interface {
	TestOffline(ctx context.Context, in *EmptyRequest, opts ...grpc.CallOption) (*Response, error)
	TestOnline(ctx context.Context, in *EmptyRequest, opts ...grpc.CallOption) (*Response, error)
}

type testClient struct {
	cc grpc.ClientConnInterface
}

func NewTestClient(cc grpc.ClientConnInterface) TestClient {
	return &testClient{cc}
}

func (c *testClient) TestOffline(ctx context.Context, in *EmptyRequest, opts ...grpc.CallOption) (*Response, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Response)
	err := c.cc.Invoke(ctx, Test_TestOffline_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *testClient) TestOnline(ctx context.Context, in *EmptyRequest, opts ...grpc.CallOption) (*Response, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Response)
	err := c.cc.Invoke(ctx, Test_TestOnline_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TestServer is the server API for Test service.
// All implementations should embed UnimplementedTestServer
// for forward compatibility.
type TestServer interface {
	TestOffline(context.Context, *EmptyRequest) (*Response, error)
	TestOnline(context.Context, *EmptyRequest) (*Response, error)
}

// UnimplementedTestServer should be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedTestServer struct{}

func (UnimplementedTestServer) TestOffline(context.Context, *EmptyRequest) (*Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TestOffline not implemented")
}
func (UnimplementedTestServer) TestOnline(context.Context, *EmptyRequest) (*Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TestOnline not implemented")
}
func (UnimplementedTestServer) testEmbeddedByValue() {}

// UnsafeTestServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TestServer will
// result in compilation errors.
type UnsafeTestServer interface {
	mustEmbedUnimplementedTestServer()
}

func RegisterTestServer(s grpc.ServiceRegistrar, srv TestServer) {
	// If the following call pancis, it indicates UnimplementedTestServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&Test_ServiceDesc, srv)
}

func _Test_TestOffline_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EmptyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TestServer).TestOffline(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Test_TestOffline_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TestServer).TestOffline(ctx, req.(*EmptyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Test_TestOnline_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EmptyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TestServer).TestOnline(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Test_TestOnline_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TestServer).TestOnline(ctx, req.(*EmptyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Test_ServiceDesc is the grpc.ServiceDesc for Test service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Test_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "grpcauth.test.Test",
	HandlerType: (*TestServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "TestOffline",
			Handler:    _Test_TestOffline_Handler,
		},
		{
			MethodName: "TestOnline",
			Handler:    _Test_TestOnline_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "github.com/dosquad/go-grpcauth/test/simple.proto",
}