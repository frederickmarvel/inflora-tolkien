// Package palantir is the gRPC client wrapper for Tolkien's privileged calls
// to Palantir (the admin override boundary).
package palantir

import (
	"context"
	"time"

	sharedauth "github.com/frederickmarvel/inflora-shared/auth"
	pb "github.com/frederickmarvel/inflora-shared/gen/go/palantir/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	dialTimeout = 5 * time.Second
	rpcTimeout  = 5 * time.Second
)

// Client is a thin wrapper around the generated AdminServiceClient.
type Client struct {
	pb.AdminServiceClient
	conn *grpc.ClientConn
}

// New dials the Palantir service and authenticates every unary RPC with the
// shared engine API key.
func New(ctx context.Context, addr, engineAPIKey string, opts ...grpc.DialOption) (*Client, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		sharedauth.GRPCBearerAuthClient(engineAPIKey),
		grpc.WithBlock(),
	}
	dialOpts = append(dialOpts, opts...)
	conn, err := grpc.DialContext(dialCtx, addr, dialOpts...)
	if err != nil {
		return nil, err
	}
	return &Client{AdminServiceClient: pb.NewAdminServiceClient(conn), conn: conn}, nil
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// OverrideDonation forwards an admin override to Palantir.
func (c *Client) OverrideDonation(ctx context.Context, req *pb.OverrideDonationRequest) (*pb.OverrideDonationResponse, error) {
	rpcCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	return c.AdminServiceClient.OverrideDonation(rpcCtx, req)
}
