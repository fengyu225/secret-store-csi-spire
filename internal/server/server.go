package server

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
	"spire-csi-provider/internal/config"
	"spire-csi-provider/internal/hmac"
	"spire-csi-provider/internal/provider"
	"spire-csi-provider/internal/version"
)

type Server struct {
	logger        hclog.Logger
	flagsConfig   config.FlagsConfig
	hmacGenerator *hmac.HMACGenerator
	pb.UnimplementedCSIDriverProviderServer
}

func NewServer(logger hclog.Logger, flagsConfig config.FlagsConfig, hmacGenerator *hmac.HMACGenerator) *Server {
	return &Server{
		logger:        logger,
		flagsConfig:   flagsConfig,
		hmacGenerator: hmacGenerator,
	}
}

func (s *Server) Version(ctx context.Context, req *pb.VersionRequest) (*pb.VersionResponse, error) {
	s.logger.Debug("Version request received", "driverVersion", req.GetVersion())

	return &pb.VersionResponse{
		Version:        "v1alpha1",
		RuntimeName:    "spire-csi-provider",
		RuntimeVersion: version.BuildVersion,
	}, nil
}

func (s *Server) Mount(ctx context.Context, req *pb.MountRequest) (*pb.MountResponse, error) {
	s.logger.Debug("Mount request received",
		"targetPath", req.GetTargetPath(),
		"permission", req.GetPermission())
	s.logger.Debug("context is: ", ctx)
	s.logger.Debug("request is: ", req)

	cfg, err := config.Parse(req.Attributes, req.TargetPath, req.Permission)
	if err != nil {
		s.logger.Error("Failed to parse configuration", "error", err)
		return nil, fmt.Errorf("error parsing configuration: %w", err)
	}
	s.logger.Debug("configuration is: ", cfg)

	spireProvider := provider.NewProvider(s.logger.Named("provider"), s.hmacGenerator)

	resp, err := spireProvider.HandleMountRequest(ctx, cfg, s.flagsConfig)
	if err != nil {
		s.logger.Error("Failed to handle mount request", "error", err)
		return nil, fmt.Errorf("error handling mount request: %w", err)
	}

	s.logger.Info("Mount request successful",
		"targetPath", req.GetTargetPath(),
		"fileCount", len(resp.GetFiles()))

	return resp, nil
}
