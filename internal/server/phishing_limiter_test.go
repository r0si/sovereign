package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/r0si/sovereign/internal/testutil"
)

func TestPhishingLandingLimiterHasHardKeyCap(t *testing.T) {
	s := &Server{
		landingLimiterHits:  make(map[string]int, phishingLimiterMaxEntries),
		landingLimiterSince: make(map[string]time.Time, phishingLimiterMaxEntries),
		landingIPHits:       make(map[string]int),
		landingIPSince:      make(map[string]time.Time),
	}
	for i := 0; i < phishingLimiterMaxEntries; i++ {
		key := fmt.Sprintf("token-%d|ip", i)
		s.landingLimiterHits[key] = 1
		s.landingLimiterSince[key] = time.Now()
	}
	if s.phishingLandingAllowed("new-token", "new-ip") {
		t.Fatal("limiter accepted a new key beyond the hard cap")
	}
	if len(s.landingLimiterHits) != phishingLimiterMaxEntries {
		t.Fatalf("limiter grew to %d entries", len(s.landingLimiterHits))
	}
}

func TestPhishingLandingLimiterBoundsPerIP(t *testing.T) {
	s := &Server{}
	for i := 0; i < phishingLandingIPLimit; i++ {
		if !s.phishingLandingAllowed(fmt.Sprintf("token-%d", i), "192.0.2.1") {
			t.Fatalf("request %d was rejected before the IP limit", i)
		}
	}
	if s.phishingLandingAllowed("one-too-many", "192.0.2.1") {
		t.Fatal("per-IP limiter accepted one request too many")
	}
}

func TestPhishingLandingUnknownTokenDoesNotConsumeLimiter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Server{db: testutil.SetupTestDB(t)}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/phishing/l/unknown", nil)
	c.Params = gin.Params{{Key: "token", Value: "unknown"}}
	s.handlePhishingLanding(c)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown token status = %d, want 404", w.Code)
	}
	if len(s.landingLimiterHits) != 0 || len(s.landingIPHits) != 0 {
		t.Fatal("unknown token consumed unauthenticated limiter state")
	}
}
