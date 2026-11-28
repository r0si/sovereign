package server

import (
	"net/http"
	"strings"
)

// authBodyLimit returns the global authenticated-request limit. Zero means the
// route owns its body budget (multipart uploads and the raw bundle verifier).
func authBodyLimit(method, path, contentType string) int64 {
	mediaType := strings.ToLower(strings.TrimSpace(contentType))
	if strings.HasPrefix(mediaType, "multipart/form-data") {
		return 0
	}
	if method == http.MethodPost && strings.HasSuffix(path, "/bundle/verify") {
		return 0
	}
	if method == http.MethodPut && strings.HasSuffix(path, "/chunk") {
		return TransferChunkJSONLimit
	}
	return MaxJSONBodySize
}
