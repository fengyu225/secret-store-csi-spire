package hmac

import (
	"context"
	cryptohmac "crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
	"spire-csi-provider/internal/config"
)

const (
	staticHMACKey = "spire-csi-provider-static-hmac-key-12345"
)

type HMACGenerator struct {
	staticKey []byte
}

func NewHMACGenerator(staticKey []byte) *HMACGenerator {
	if staticKey == nil || len(staticKey) == 0 {
		return &HMACGenerator{
			staticKey: []byte(staticHMACKey),
		}
	}

	return &HMACGenerator{
		staticKey: staticKey,
	}
}

func (g *HMACGenerator) GetOrCreateHMACKey(ctx context.Context) ([]byte, error) {
	return g.staticKey, nil
}

func (g *HMACGenerator) GenerateObjectVersion(object config.Object, content []byte) (*pb.ObjectVersion, error) {
	if g.staticKey == nil {
		return nil, fmt.Errorf("no static hmac key provided")
	}

	hash := cryptohmac.New(sha256.New, g.staticKey)
	cfg, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	if _, err := hash.Write(cfg); err != nil {
		return nil, err
	}
	if _, err := hash.Write(content); err != nil {
		return nil, err
	}

	return &pb.ObjectVersion{
		Id:      object.ObjectName,
		Version: base64.URLEncoding.EncodeToString(hash.Sum(nil)),
	}, nil
}
