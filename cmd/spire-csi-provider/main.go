package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"

	"spire-csi-provider/internal/config"
	"spire-csi-provider/internal/hmac"
	"spire-csi-provider/internal/metrics"
	"spire-csi-provider/internal/server"
	"spire-csi-provider/internal/version"
)

type healthServer struct {
	logger hclog.Logger
}

func (s *healthServer) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	s.logger.Trace("health check requested", "service", req.Service)
	metrics.HealthCheckStatus.Set(1)
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func (s *healthServer) Watch(req *healthpb.HealthCheckRequest, ws healthpb.Health_WatchServer) error {
	s.logger.Trace("health watch requested", "service", req.Service)
	return nil
}

func main() {
	var flagsConfig config.FlagsConfig
	flag.StringVar(&flagsConfig.Endpoint, "endpoint", "/opt/spire-csi-provider/spire-csi-provider.sock", "gRPC server endpoint")
	flag.StringVar(&flagsConfig.LogLevel, "logLevel", "info", "Log level (trace, debug, info, warn, error)")
	flag.BoolVar(&flagsConfig.Version, "version", false, "Print the version and exit")
	flag.StringVar(&flagsConfig.HealthAddr, "healthAddr", ":8080", "Address for health check server")
	flag.StringVar(&flagsConfig.HMACSecretName, "hmacSecretName", "spire-csi-provider-hmac", "Name of the Kubernetes secret containing the HMAC key")
	flag.IntVar(&flagsConfig.CacheSize, "cacheSize", 100, "Size of the client cache (set to <= 0 to disable caching)")
	flag.StringVar(&flagsConfig.SpireSocketPath, "socketPath", "/run/spire/agent-sockets/spire-agent.sock", "Path to the SPIRE Workload API socket")
	flag.StringVar(&flagsConfig.MetricsAddr, "metricsAddr", ":8081", "Address for metrics server")
	flag.DurationVar(&flagsConfig.ProviderStaleTimeout, "providerStaleTimeout", 10*time.Minute, "Time after which an unused SPIRE client is considered stale")
	flag.DurationVar(&flagsConfig.ProviderCleanupInterval, "providerCleanupInterval", 5*time.Minute, "Interval for cleaning up stale SPIRE clients")
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
		fmt.Fprintf(os.Stderr, "invalid log level: %s, defaulting to info\n", flagsConfig.LogLevel)
		logLevel = hclog.Info
	}

	logger := hclog.New(&hclog.LoggerOptions{
		Name:       "spire-csi-provider",
		Level:      logLevel,
		JSONFormat: true,
		TimeFormat: time.RFC3339,
	})

	logger.Info("starting spire-csi-provider",
		"version", version.BuildVersion,
		"build_date", version.BuildDate,
		"go_version", runtime.Version(),
		"pid", os.Getpid(),
		"log_level", flagsConfig.LogLevel,
	)

	logger.Debug("configuration loaded",
		"endpoint", flagsConfig.Endpoint,
		"health_addr", flagsConfig.HealthAddr,
		"metrics_addr", flagsConfig.MetricsAddr,
		"hmac_secret_name", flagsConfig.HMACSecretName,
		"cache_size", flagsConfig.CacheSize,
		"spire_socket_path", flagsConfig.SpireSocketPath,
		"provider_stale_timeout", flagsConfig.ProviderStaleTimeout,
		"provider_cleanup_interval", flagsConfig.ProviderCleanupInterval,
	)

	hmacGenerator := hmac.NewHMACGenerator(nil)
	logger.Debug("HMAC generator initialized")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-signalCh
		logger.Info("received shutdown signal", "signal", sig)
		cancel()
	}()

	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(4 * 1024 * 1024),
		grpc.UnaryInterceptor(loggingInterceptor(logger)),
	}
	grpcServer := grpc.NewServer(opts...)

	providerServer := server.NewServer(logger, flagsConfig, hmacGenerator)
	v1alpha1.RegisterCSIDriverProviderServer(grpcServer, providerServer)
	healthpb.RegisterHealthServer(grpcServer, &healthServer{logger: logger.Named("health")})

	if err := os.Remove(flagsConfig.Endpoint); err != nil && !os.IsNotExist(err) {
		logger.Error("failed to remove existing socket", "error", err, "socket", flagsConfig.Endpoint)
		os.Exit(1)
	}

	listener, err := net.Listen("unix", flagsConfig.Endpoint)
	if err != nil {
		logger.Error("failed to listen on socket", "error", err, "socket", flagsConfig.Endpoint)
		os.Exit(1)
	}
	defer listener.Close()

	if err := os.Chmod(flagsConfig.Endpoint, 0660); err != nil {
		logger.Error("failed to set socket permissions", "error", err, "socket", flagsConfig.Endpoint)
		os.Exit(1)
	}

	go func() {
		logger.Info("starting metrics server", "address", flagsConfig.MetricsAddr)
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(flagsConfig.MetricsAddr, mux); err != nil {
			logger.Error("metrics server failed", "error", err)
		}
	}()

	go func() {
		logger.Info("starting health check server", "address", flagsConfig.HealthAddr)
		mux := http.NewServeMux()
		mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
			logger.Trace("health check endpoint called", "path", r.URL.Path, "remote_addr", r.RemoteAddr)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		})
		mux.HandleFunc("/health/live", func(w http.ResponseWriter, r *http.Request) {
			logger.Trace("liveness check endpoint called", "path", r.URL.Path, "remote_addr", r.RemoteAddr)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		})
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
	logger.Info("shutting down gracefully")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	shutdownDone := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()

		if err := providerServer.Shutdown(); err != nil {
			logger.Error("failed to shutdown provider server", "error", err)
		}

		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
		logger.Info("graceful shutdown completed")
	case <-shutdownCtx.Done():
		logger.Warn("graceful shutdown timeout exceeded, forcing stop")
		grpcServer.Stop()
	}
}

func loggingInterceptor(logger hclog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()

		logger.Debug("gRPC request started",
			"method", info.FullMethod,
			"request_type", fmt.Sprintf("%T", req),
		)

		resp, err := handler(ctx, req)

		duration := time.Since(start)
		if err != nil {
			logger.Error("gRPC request failed",
				"method", info.FullMethod,
				"duration_ms", duration.Milliseconds(),
				"error", err,
			)
		} else {
			logger.Debug("gRPC request completed",
				"method", info.FullMethod,
				"duration_ms", duration.Milliseconds(),
			)
		}

		return resp, err
	}
}
