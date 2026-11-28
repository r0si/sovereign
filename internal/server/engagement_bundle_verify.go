package server

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Bundle verification: does this archive still hold what its manifest says it holds.
//
// A handover travels - emailed, copied, re-zipped, sometimes transcoded by a mail gateway - and MANIFEST.json publishes
// a SHA-256 per member so a receiver can check. This endpoint is the server side of that check, for the same reason the
// plugin index has one: the party who produced a package is the party who can say whether a copy of it is intact.
//
// **What it proves and what it does not.** The digests are unkeyed and the manifest travels INSIDE the archive, so a
// deliberate rebuild of every member and every digest verifies. Like the audit chain, this detects damage and partial
// edits, not an adversary who redoes the whole package; only a signature made with a key that never travelled would
// close that gap, and saying so is more useful than implying otherwise.
//
// POST /api/engagements/:id/bundle/verify   (body: the zip, application/zip)

const engagementBundleVerifyMaxBytes = 128 << 20
const engagementBundleVerifyMaxMembers = 1024
const engagementBundleVerifyMaxMemberBytes = 64 << 20
const engagementBundleVerifyMaxTotalBytes = 256 << 20
const engagementBundleVerifyMaxManifestBytes = 1 << 20

// handleVerifyEngagementBundle re-computes the manifest digests of an uploaded bundle.
func (s *Server) handleVerifyEngagementBundle(c *gin.Context) {
	if _, _, ok := s.buildEngagementSummary(c); !ok {
		return // unknown engagement for this tenant; the summary helper already answered
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, engagementBundleVerifyMaxBytes)
	raw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		respondError(c, http.StatusBadRequest, "failed to read the uploaded bundle (limit 128 MiB)")
		return
	}
	if len(raw) == 0 {
		respondError(c, http.StatusBadRequest, "empty body: send the bundle zip as application/zip")
		return
	}

	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		respondError(c, http.StatusBadRequest, "the body is not a zip archive")
		return
	}

	digests := make(map[string][sha256.Size]byte, len(reader.File))
	sizes := make(map[string]int64, len(reader.File))
	names := make(map[string]struct{}, len(reader.File))
	var manifestRaw []byte
	var declaredTotal, actualTotal int64
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		if len(names) >= engagementBundleVerifyMaxMembers {
			respondError(c, http.StatusRequestEntityTooLarge, "bundle has too many members")
			return
		}
		if file.UncompressedSize64 > engagementBundleVerifyMaxMemberBytes {
			respondError(c, http.StatusRequestEntityTooLarge, "bundle member exceeds 64 MiB")
			return
		}
		declaredTotal += int64(file.UncompressedSize64)
		if declaredTotal > engagementBundleVerifyMaxTotalBytes {
			respondError(c, http.StatusRequestEntityTooLarge, "bundle expands beyond 256 MiB")
			return
		}
		if _, duplicate := names[file.Name]; duplicate {
			respondError(c, http.StatusBadRequest, "bundle contains duplicate member names")
			return
		}
		names[file.Name] = struct{}{}
		handle, err := file.Open()
		if err != nil {
			respondError(c, http.StatusBadRequest, "failed to open a member of the uploaded bundle")
			return
		}
		if file.Name == "MANIFEST.json" {
			content, readErr := io.ReadAll(io.LimitReader(handle, engagementBundleVerifyMaxManifestBytes+1))
			_ = handle.Close()
			if readErr != nil || len(content) > engagementBundleVerifyMaxManifestBytes {
				respondError(c, http.StatusRequestEntityTooLarge, "MANIFEST.json exceeds 1 MiB")
				return
			}
			manifestRaw = content
			actualTotal += int64(len(content))
			continue
		}
		hash := sha256.New()
		n, copyErr := io.Copy(hash, io.LimitReader(handle, engagementBundleVerifyMaxMemberBytes+1))
		_ = handle.Close()
		if copyErr != nil || n > engagementBundleVerifyMaxMemberBytes {
			respondError(c, http.StatusRequestEntityTooLarge, "bundle member exceeds 64 MiB")
			return
		}
		actualTotal += n
		if actualTotal > engagementBundleVerifyMaxTotalBytes {
			respondError(c, http.StatusRequestEntityTooLarge, "bundle expands beyond 256 MiB")
			return
		}
		digests[file.Name] = [sha256.Size]byte(hash.Sum(nil))
		sizes[file.Name] = n
	}

	if manifestRaw == nil {
		respondError(c, http.StatusBadRequest, "the archive has no MANIFEST.json, so there is nothing to verify against")
		return
	}
	var manifest struct {
		Engagement struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		} `json:"engagement"`
		GeneratedAt string           `json:"generated_at"`
		Signature   *bundleSignature `json:"signature"`
		Members     []struct {
			Name        string `json:"name"`
			Purpose     string `json:"purpose"`
			Source      string `json:"source"`
			Sensitivity string `json:"sensitivity"`
			SHA256      string `json:"sha256"`
			Bytes       int    `json:"bytes"`
		} `json:"members"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		respondError(c, http.StatusBadRequest, "MANIFEST.json is not valid JSON")
		return
	}

	type problem struct {
		Name    string `json:"name"`
		Problem string `json:"problem"`
	}
	checked := 0
	verified := 0
	unverifiable := make([]problem, 0, 2)
	problems := make([]problem, 0, 4)
	for _, entry := range manifest.Members {
		checked++
		if entry.SHA256 == "" {
			// MANIFEST.json is the legitimate case: it cannot contain its own digest.
			unverifiable = append(unverifiable, problem{entry.Name, "no digest published"})
			continue
		}
		sum, present := digests[entry.Name]
		if !present {
			problems = append(problems, problem{entry.Name, "listed in the manifest but missing from the archive"})
			continue
		}
		got := hex.EncodeToString(sum[:])
		if got != entry.SHA256 {
			want := entry.SHA256
			if len(want) > 16 {
				want = want[:16]
			}
			problems = append(problems, problem{entry.Name, fmt.Sprintf("digest mismatch: archive %s, manifest %s", got[:16], want)})
			continue
		}
		if entry.Bytes != 0 && int64(entry.Bytes) != sizes[entry.Name] {
			problems = append(problems, problem{entry.Name, fmt.Sprintf("size mismatch: archive %d, manifest %d", sizes[entry.Name], entry.Bytes)})
			continue
		}
		verified++
	}
	// A member that is present but not listed is also worth reporting: it arrived from somewhere.
	listed := make(map[string]bool, len(manifest.Members))
	for _, entry := range manifest.Members {
		listed[entry.Name] = true
	}
	extra := make([]string, 0, 2)
	for name := range names {
		if !listed[name] {
			extra = append(extra, name)
		}
	}

	// The signature is checked LAST, against the digests as they are written in the manifest - and the payload is
	// rebuilt from those digests, so a manifest whose numbers were edited after signing fails here even when every
	// member still matches its (edited) digest.
	descriptions := make([]bundleMemberDescription, 0, len(manifest.Members))
	for _, entry := range manifest.Members {
		descriptions = append(descriptions, bundleMemberDescription{
			Name: entry.Name, Purpose: entry.Purpose, Source: entry.Source,
			Sensitivity: entry.Sensitivity, SHA256: entry.SHA256, Bytes: entry.Bytes,
		})
	}
	payload := bundleManifestPayload(manifest.Engagement.ID, manifest.GeneratedAt, descriptions)
	signatureValid, signatureProblem := verifyBundleSignature(manifest.Signature, payload)
	// A key carried in the same archive proves nothing about origin, so `trusted` requires the caller to state the key
	// they already trust. Without that, a swapped manifest and a swapped key verify together.
	expectedKey := strings.ToLower(strings.TrimSpace(c.Query("public_key")))
	trusted := signatureValid && expectedKey != "" && strings.ToLower(manifest.Signature.PublicKey) == expectedKey
	signatureReport := gin.H{
		"present": manifest.Signature != nil,
		"valid":   signatureValid,
		"trusted": trusted,
		"problem": signatureProblem,
		// Which "signature" this is: the keyed one over the manifest, not an audit row signature.
		"kind": bundleSignatureKind,
	}
	if manifest.Signature != nil {
		signatureReport["public_key"] = manifest.Signature.PublicKey
		signatureReport["algorithm"] = manifest.Signature.Algorithm
		signatureReport["signed_members"] = manifest.Signature.SignedMembers
	}
	if expectedKey != "" && manifest.Signature != nil && strings.ToLower(manifest.Signature.PublicKey) != expectedKey {
		signatureReport["problem"] = "the manifest is signed by a different key than the one supplied"
	}

	inSync := len(problems) == 0 && len(extra) == 0
	s.LogAuditRecord(c, "engagement_bundle_verify", "engagement", fmt.Sprintf("%d", manifest.Engagement.ID),
		fmt.Sprintf("verified uploaded bundle: %d of %d member(s) intact, %d problem(s)", verified, checked, len(problems)), true, nil)

	respond(c, gin.H{
		"ok":           inSync,
		"checked":      checked,
		"verified":     verified,
		"mismatched":   problems,
		"unverifiable": unverifiable,
		"extra":        extra,
		"engagement":   manifest.Engagement,
		"generated_at": manifest.GeneratedAt,
		"signature":    signatureReport,
		"note": "digests are unkeyed and the manifest travels inside the archive, so this detects damage and " +
			"partial edits, not a package rebuilt wholesale. A signature closes that gap only when the receiver " +
			"compares it with a key they already trust, which is why trusted requires public_key",
	})
}
