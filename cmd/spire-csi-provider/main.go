package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/hashicorp/go-hclog"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"

	"spire-csi-provider/internal/config"
	"spire-csi-provider/internal/hmac"
	"spire-csi-provider/internal/server"
	"spire-csi-provider/internal/version"
)

type healthServer struct{}

func (s *healthServer) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func (s *healthServer) Watch(req *healthpb.HealthCheckRequest, ws healthpb.Health_WatchServer) error {
	return nil
}

func main() {

	var flagsConfig config.FlagsConfig
	flag.StringVar(&flagsConfig.Endpoint, "endpoint", "/opt/spire-csi-provider/spire-csi-provider.sock", "gRPC server endpoint")
	flag.StringVar(&flagsConfig.LogLevel, "logLevel", "debug", "Log level (trace, debug, info, warn, error)")
	flag.BoolVar(&flagsConfig.Version, "version", false, "Print the version and exit")
	flag.StringVar(&flagsConfig.HealthAddr, "healthAddr", ":8080", "Address for health check server")
	flag.StringVar(&flagsConfig.HMACSecretName, "hmacSecretName", "spire-csi-provider-hmac", "Name of the Kubernetes secret containing the HMAC key")
	flag.IntVar(&flagsConfig.CacheSize, "cacheSize", 100, "Size of the client cache (set to <= 0 to disable caching)")
	flag.StringVar(&flagsConfig.SpireSocketPath, "socketPath", "/run/spire/agent-sockets/spire-agent.sock", "Path to the SPIRE Workload API socket")
	flag.Parse()

	if flagsConfig.Version {
		ver, err := version.GetVersion()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get version: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(ver)
		os.Exit(0)
	}

	logLevel := hclog.LevelFromString(flagsConfig.LogLevel)
	if logLevel == hclog.NoLevel {
		logLevel = hclog.Info
	}

	logger := hclog.New(&hclog.LoggerOptions{
		Name:       "spire-csi-provider",
		Level:      logLevel,
		JSONFormat: true,
	})

	logger.Info("starting spire-csi-provider", "version", version.BuildVersion)

	hmacGenerator := hmac.NewHMACGenerator(nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-signalCh
		logger.Info("received signal", "signal", sig)
		cancel()
	}()

	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(1024 * 1024 * 4),
	}
	grpcServer := grpc.NewServer(opts...)

	providerServer := server.NewServer(logger, flagsConfig, hmacGenerator)
	v1alpha1.RegisterCSIDriverProviderServer(grpcServer, providerServer)
	healthpb.RegisterHealthServer(grpcServer, &healthServer{})

	if err := os.Remove(flagsConfig.Endpoint); err != nil && !os.IsNotExist(err) {
		logger.Error("failed to remove existing socket", "error", err)
		os.Exit(1)
	}

	listener, err := net.Listen("unix", flagsConfig.Endpoint)
	if err != nil {
		logger.Error("failed to listen on socket", "error", err)
		os.Exit(1)
	}
	defer listener.Close()

	if err := os.Chmod(flagsConfig.Endpoint, 0660); err != nil {
		logger.Error("failed to set socket permissions", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	go func() {
		if err := http.ListenAndServe(flagsConfig.HealthAddr, mux); err != nil {
			logger.Error("health check server failed", "error", err)
		}
	}()

	logger.Info("starting gRPC server", "endpoint", flagsConfig.Endpoint)
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			logger.Error("gRPC server failed", "error", err)
			cancel()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	grpcServer.GracefulStop()
}
