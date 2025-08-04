package client

import (
	"github.com/hashicorp/go-hclog"
)

// NewSpireClient creates either a Client or DualAgentClient based on configuration
func NewSpireClient(logger hclog.Logger, config Config) (SpireClient, error) {
	// If second socket path is provided, create DualAgentClient
	if config.SpireSocketPath2 != "" {
		logger.Info("creating dual agent client",
			"socket1", config.SpireSocketPath,
			"socket2", config.SpireSocketPath2)
		return NewDualAgentClient(logger, config)
	}

	// Otherwise create regular client
	logger.Info("creating single agent client",
		"socket", config.SpireSocketPath)
	return New(logger, config)
}
