package client

import "errors"

var (
	// ErrUnauthorized indicates the installation token was rejected by GitHub.
	ErrUnauthorized = errors.New("github token unauthorized")
	// ErrNotFound indicates the repository, branch, or ref does not exist.
	ErrNotFound = errors.New("github resource not found")
	// ErrRateLimited indicates GitHub rate limit or abuse detection was triggered.
	ErrRateLimited = errors.New("github rate limit exceeded")
	// ErrUpstream indicates a GitHub API communication or unexpected response failure.
	ErrUpstream = errors.New("github upstream error")
	// ErrInvalidInput indicates malicious or malformed parameters (e.g. path traversal).
	ErrInvalidInput = errors.New("invalid github request parameter")
)
