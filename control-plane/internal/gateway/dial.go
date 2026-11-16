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
	Enabled    bool
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
}

// DialUpstream establishes a gRPC client connection with transport security and optional service token.
func DialUpstream(address string, tlsCfg DialUpstreamTLSConfig, serviceToken string, isDev bool) (*grpc.ClientConn, error) {
	var creds credentials.TransportCredentials

	if tlsCfg.CertFile != "" && tlsCfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ServerName:   tlsCfg.ServerName,
			MinVersion:   tls.VersionTLS12,
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
	} else if tlsCfg.CAFile != "" {
		caPEM, err := os.ReadFile(tlsCfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("failed to parse ca cert: file contains no valid certificates")
		}
		tlsConfig := &tls.Config{
			RootCAs:    pool,
			ServerName: tlsCfg.ServerName,
			MinVersion: tls.VersionTLS12,
		}
		creds = credentials.NewTLS(tlsConfig)
	} else if tlsCfg.Enabled {
		creds = credentials.NewTLS(&tls.Config{
			ServerName: tlsCfg.ServerName,
			MinVersion: tls.VersionTLS12,
		})
	} else if isDev {
		creds = insecure.NewCredentials()
	} else {
		return nil, errors.New("plaintext gRPC is only allowed when KR0N_ENV=dev")
	}

	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	if serviceToken != "" {
		dialOpts = append(dialOpts, grpc.WithUnaryInterceptor(ServiceTokenClientInterceptor(serviceToken)))
	}

	return grpc.NewClient(address, dialOpts...)
}
