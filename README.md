# gRPC Authentication Helpers

[![CI](https://github.com/dosquad/go-grpcauth/actions/workflows/ci.yml/badge.svg)](https://github.com/dosquad/go-grpcauth/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/dosquad/go-grpcauth/graph/badge.svg?token=vTWGDA0TWf)](https://codecov.io/gh/dosquad/go-grpcauth)

gRPC authentication helpers for providing access to gRPC servers using basic or bearer HTTP authentication.

## Example

### Client

```go
    pool, err := x509.SystemCertPool()
    checkErr(err)
    creds := credentials.NewClientTLSFromCert(pool, "")

    opts := []grpc.DialOption{
        grpc.WithTransportCredentials(creds),
        // For Basic Auth
        grpc.WithPerRPCCredentials(grpcauth.NewBasicCredentials("user", "pass")),
        // For Token Auth
        grpc.WithPerRPCCredentials(grpcauth.NewTokenCredentials("secret-token")),
    }
    gc, err := grpc.Dial("grpc.example.com:443", opts...)
    checkErr(err)
    defer gc.Close()

    client := api.NewRPCClient(gc)
    ctx := context.Background()
    resp, err := client.CallRPC(ctx, &api.RPCRequest{})
    checkErr(err)

    // ... do something with response ... 
```

### Server

```go
    lis, err := net.Listen("tcp", "localhost:8000")
    checkErr(err)
    defer lis.Close()

    basicAuthFunc := func(username string, password string) (string, bool) {
        if subtle.ConstantTimeCompare([]byte(username), []byte("user")) == 1 &&
         subtle.ConstantTimeCompare([]byte(password), []byte("pass")) == 1 {
            return username, true
        }

        return username, false
    }

    bearerAuthFunc := func(token string) (string, bool, bool) {
        if subtle.ConstantTimeCompare([]byte(token), []byte("secret-token")) == 1 {
            return "token-user", true, true
        }

        logrus.Infof("token does not match")

        return "", false, false
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
    api.RegisterTestServer(grpcServer, testServer)
    err := grpcServer.Serve(lis)
    checkErr(err)
```
