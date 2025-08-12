package client

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	delegatedapi "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

type connectionManager struct {
	logger hclog.Logger
	config Config

	grpcConn *grpc.ClientConn
	client   delegatedapi.DelegatedIdentityClient

	connected        bool
	lastConnectError error
	mu               sync.RWMutex

	connectionAttempts int
}

func newConnectionManager(logger hclog.Logger, config Config) *connectionManager {
	return &connectionManager{
		logger: logger,
		config: config,
	}
}

func (cm *connectionManager) connect(ctx context.Context) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.grpcConn != nil {
		cm.logger.Debug("closing existing connection")
		cm.grpcConn.Close()
		cm.grpcConn = nil
	}

	socketPath := cm.config.SpireSocketPath
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return fmt.Errorf("SPIRE socket (%s) does not exist: %w", socketPath, err)
	}

	unixPath := fmt.Sprintf("unix://%s", socketPath)
	cm.logger.Debug("creating gRPC connection", "path", unixPath)

	conn, err := cm.createGRPCConnection(unixPath)
	if err != nil {
		cm.connected = false
		cm.lastConnectError = err
		return err
	}

	cm.grpcConn = conn
	cm.client = delegatedapi.NewDelegatedIdentityClient(conn)
	cm.connected = true
	cm.lastConnectError = nil
	cm.connectionAttempts++

	cm.logger.Info("successfully connected to SPIRE agent")
	return nil
}

func (cm *connectionManager) createGRPCConnection(unixPath string) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(unixPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(20*1024*1024),
			grpc.MaxCallSendMsgSize(20*1024*1024),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: false,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc.Dial() failed on %s: %w", unixPath, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn.Connect()
	state := conn.GetState()
	if state != connectivity.Ready {
		cm.logger.Debug("waiting for connection to be ready", "current_state", state)
		if !conn.WaitForStateChange(ctx, state) {
			cm.logger.Warn("connection did not become ready in time", "state", conn.GetState())
		}
	}

	return conn, nil
}

func (cm *connectionManager) close() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.grpcConn != nil {
		cm.logger.Debug("closing gRPC connection")
		if err := cm.grpcConn.Close(); err != nil {
			cm.logger.Warn("error closing gRPC connection", "error", err)
		}
		cm.grpcConn = nil
	}
	cm.connected = false
}

func (cm *connectionManager) isHealthy() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if !cm.connected || cm.grpcConn == nil {
		return false
	}

	state := cm.grpcConn.GetState()
	cm.logger.Debug("gRPC connection state", "state", state)
	return state == connectivity.Ready || state == connectivity.Idle
}

func (cm *connectionManager) getClient() delegatedapi.DelegatedIdentityClient {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.client
}

func (cm *connectionManager) getStatus() (bool, string) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if !cm.connected {
		msg := "Not connected to SPIRE server"
		if cm.lastConnectError != nil {
			msg = fmt.Sprintf("Cannot connect to SPIRE server: %q", cm.lastConnectError)
		}
		return false, msg
	}
	return true, "Connected to SPIRE server"
}
