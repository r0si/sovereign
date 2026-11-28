package server

import (
	"net/http"
	"testing"
)

func TestAuthBodyLimitUsesDedicatedBinaryBudgets(t *testing.T) {
	for _, tc := range []struct {
		name        string
		method      string
		path        string
		contentType string
		want        int64
	}{
		{name: "json default", method: http.MethodPost, path: "/api/ai/runs", contentType: "application/json", want: MaxJSONBodySize},
		{name: "transfer chunk", method: http.MethodPut, path: "/agents/a/transfers/1/chunk", contentType: "application/json", want: TransferChunkJSONLimit},
		{name: "multipart owns limit", method: http.MethodPost, path: "/api/ai/sessions/1/attachments", contentType: "multipart/form-data; boundary=x", want: 0},
		{name: "bundle owns limit", method: http.MethodPost, path: "/api/engagements/1/bundle/verify", contentType: "application/zip", want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := authBodyLimit(tc.method, tc.path, tc.contentType); got != tc.want {
				t.Fatalf("authBodyLimit = %d, want %d", got, tc.want)
			}
		})
	}
}
