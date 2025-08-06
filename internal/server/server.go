package server

import (
	"context"
	"encoding/json"
	"fmt"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"time"

	"github.com/hashicorp/go-hclog"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
	"spire-csi-provider/internal/client"
	"spire-csi-provider/internal/config"
	"spire-csi-provider/internal/hmac"
	"spire-csi-provider/internal/metrics"
	"spire-csi-provider/internal/provider"
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

type Server struct {
	logger        hclog.Logger
	flagsConfig   config.FlagsConfig
	hmacGenerator *hmac.HMACGenerator

	clientPool client.ClientPoolInterface

	pb.UnimplementedCSIDriverProviderServer
}

func NewServer(logger hclog.Logger, flagsConfig config.FlagsConfig, hmacGenerator *hmac.HMACGenerator) *Server {
	s := &Server{
		logger:        logger.Named("server"),
		flagsConfig:   flagsConfig,
		hmacGenerator: hmacGenerator,
	}

	poolConfig := client.PoolConfig{
		StaleTimeout:    flagsConfig.ProviderStaleTimeout,
		CleanupInterval: flagsConfig.ProviderCleanupInterval,
	}
	s.clientPool = client.NewClientPool(logger, poolConfig)

	s.logger.Info("SPIRE client pool initialized",
		"stale_timeout", poolConfig.StaleTimeout,
		"cleanup_interval", poolConfig.CleanupInterval,
	)

	return s
}

func (s *Server) Version(ctx context.Context, req *pb.VersionRequest) (*pb.VersionResponse, error) {
	s.logger.Debug("version request received",
		"driver_version", req.GetVersion(),
		"request_id", generateRequestID(),
	)

	response := &pb.VersionResponse{
		Version:        "v1alpha1",
		RuntimeName:    "spire-csi-provider",
		RuntimeVersion: version.BuildVersion,
	}

	s.logger.Debug("version response sent",
		"runtime_version", response.RuntimeVersion,
		"api_version", response.Version,
	)

	return response, nil
}

func (s *Server) Mount(ctx context.Context, req *pb.MountRequest) (*pb.MountResponse, error) {
	start := time.Now()
	requestID := generateRequestID()

	var podNamespace, podName, podUID, serviceAccount string
	if req.Attributes != "" {
		var attrs map[string]string
		if err := json.Unmarshal([]byte(req.Attributes), &attrs); err != nil {
			s.logger.Warn("failed to parse attributes for logging",
				"request_id", requestID,
				"error", err,
			)
		} else {
			podNamespace = attrs["csi.storage.k8s.io/pod.namespace"]
			podName = attrs["csi.storage.k8s.io/pod.name"]
			podUID = attrs["csi.storage.k8s.io/pod.uid"]
			serviceAccount = attrs["csi.storage.k8s.io/serviceAccount.name"]
		}
	}

	// Create pod context for metrics
	podContext := metrics.PodContext{
		Namespace:      podNamespace,
		ServiceAccount: serviceAccount,
		PodUID:         podUID,
		PodName:        podName,
	}

	s.logger.Info("mount request received",
		"request_id", requestID,
		"target_path", req.GetTargetPath(),
		"permission", req.GetPermission(),
		"pod_namespace", podNamespace,
		"pod_name", podName,
		"pod_uid", podUID,
		"service_account", serviceAccount,
	)

	s.logger.Trace("mount request details",
		"request_id", requestID,
		"attributes_length", len(req.Attributes),
		"secrets_length", len(req.Secrets),
		"current_object_versions", len(req.CurrentObjectVersion),
	)

	if s.logger.IsTrace() {
		s.logger.Trace("mount request raw attributes",
			"request_id", requestID,
			"attributes", req.Attributes,
		)
	}

	cfg, err := config.Parse(req.Attributes, req.TargetPath, req.Permission)
	if err != nil {
		duration := time.Since(start)
		s.logger.Error("failed to parse configuration",
			"request_id", requestID,
			"error", err,
			"duration_ms", duration.Milliseconds(),
			"pod_namespace", podNamespace,
			"pod_name", podName,
		)
		metrics.RecordMountRequest("error_parse_config", duration.Seconds(), podContext)
		return nil, fmt.Errorf("error parsing configuration: %w", err)
	}

	s.logger.Debug("configuration parsed successfully",
		"request_id", requestID,
		"trust_domain", cfg.Parameters.TrustDomain,
		"use_case", cfg.Parameters.UseCase,
		"object_count", len(cfg.Parameters.Objects),
		"pod_namespace", cfg.Parameters.PodInfo.Namespace,
		"pod_name", cfg.Parameters.PodInfo.Name,
		"service_account", cfg.Parameters.PodInfo.ServiceAccountName,
	)

	for i, selector := range cfg.Parameters.Selectors {
		s.logger.Debug("parsed selector",
			"request_id", requestID,
			"index", i,
			"type", selector.Type,
			"value", selector.Value,
		)
	}

	for _, obj := range cfg.Parameters.Objects {
		s.logger.Debug("processing object",
			"request_id", requestID,
			"object_name", obj.ObjectName,
			"object_type", obj.Type,
			"paths", obj.Paths,
			"audience", obj.Audience,
			"file_permission", fmt.Sprintf("%o", obj.FilePermission),
		)
	}

	if len(req.CurrentObjectVersion) > 0 {
		s.logger.Debug("current object versions",
			"request_id", requestID,
			"count", len(req.CurrentObjectVersion),
		)
		for _, objVer := range req.CurrentObjectVersion {
			s.logger.Trace("current object version",
				"request_id", requestID,
				"id", objVer.Id,
				"version", objVer.Version,
			)
		}
	}

	var spireProvider *provider.Provider

	s.logger.Debug("creating provider with client pool",
		"request_id", requestID,
	)
	spireProvider = provider.NewProviderWithClientPool(
		s.logger.Named("provider"),
		s.hmacGenerator,
		podContext,
		s.clientPool,
	)

	resp, err := spireProvider.HandleMountRequest(ctx, cfg, s.flagsConfig)
	if err != nil {
		duration := time.Since(start)
		s.logger.Error("failed to handle mount request",
			"request_id", requestID,
			"error", err,
			"duration_ms", duration.Milliseconds(),
			"pod_namespace", podNamespace,
			"pod_name", podName,
			"trust_domain", cfg.Parameters.TrustDomain,
		)
		metrics.RecordMountRequest("error", duration.Seconds(), podContext)
		return nil, fmt.Errorf("error handling mount request: %w", err)
	}

	duration := time.Since(start)
	s.logger.Info("mount request completed successfully",
		"request_id", requestID,
		"target_path", req.GetTargetPath(),
		"file_count", len(resp.GetFiles()),
		"object_count", len(resp.GetObjectVersion()),
		"duration_ms", duration.Milliseconds(),
		"pod_namespace", podNamespace,
		"pod_name", podName,
	)

	for _, file := range resp.GetFiles() {
		s.logger.Debug("file created",
			"request_id", requestID,
			"path", file.Path,
			"mode", fmt.Sprintf("%o", file.Mode),
			"size", len(file.Contents),
		)
	}

	for _, objVer := range resp.GetObjectVersion() {
		s.logger.Debug("object version",
			"request_id", requestID,
			"id", objVer.Id,
			"version", objVer.Version,
		)
	}

	stats := s.clientPool.GetPoolStats()
	s.logger.Debug("client pool stats",
		"request_id", requestID,
		"total_clients", stats["total_clients"],
		"active_clients", stats["active_clients"],
		"total_refs", stats["total_refs"],
	)

	metrics.RecordMountRequest("success", duration.Seconds(), podContext)

	return resp, nil
}

func (s *Server) Shutdown() error {
	s.logger.Info("shutting down server")

	if err := s.clientPool.Shutdown(); err != nil {
		s.logger.Error("failed to shutdown client pool", "error", err)
		return err
	}

	return nil
}

func generateRequestID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
