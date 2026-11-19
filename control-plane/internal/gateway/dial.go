package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// DialUpstreamTLSConfig holds TLS and mTLS parameters for dialing an upstream gRPC service.
type DialUpstreamTLSConfig struct {
	Insecure   bool
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
}

// DialUpstream establishes a gRPC client connection with transport security and optional service token.
// It automatically chains the PassportUnaryClientInterceptor to propagate authenticated caller passports.
func DialUpstream(address string, tlsCfg DialUpstreamTLSConfig, serviceToken string) (*grpc.ClientConn, error) {
	var creds credentials.TransportCredentials
	if tlsCfg.Insecure {
		creds = insecure.NewCredentials()
	} else {
		tlsConfig := &tls.Config{
			ServerName: tlsCfg.ServerName,
			MinVersion: tls.VersionTLS12,
		}

		if tlsCfg.CertFile != "" && tlsCfg.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("load client cert/key: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		if tlsCfg.CAFile != "" {
			caPEM, err := os.ReadFile(tlsCfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("read ca file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, errors.New("failed to parse ca cert: file contains no valid certificates")
			}
			tlsConfig.RootCAs = pool
		}

		creds = credentials.NewTLS(tlsConfig)
	}

	interceptors := []grpc.UnaryClientInterceptor{PassportUnaryClientInterceptor()}
	if serviceToken != "" {
		interceptors = append(interceptors, ServiceTokenClientInterceptor(serviceToken))
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithChainUnaryInterceptor(interceptors...),
	}

	return grpc.NewClient(address, dialOpts...)
}
