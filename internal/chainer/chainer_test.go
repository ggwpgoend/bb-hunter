package chainer

import (
	"testing"

	"github.com/ggwpgoend/bb-hunter/internal/models"
)

func makeFindings(specs ...struct{ id, host, url, vulnClass string }) []*models.Finding {
	var findings []*models.Finding
	for _, s := range specs {
		findings = append(findings, &models.Finding{
			ID:        s.id,
			Host:      s.host,
			URL:       s.url,
			VulnClass: models.VulnClass(s.vulnClass),
			Severity:  models.SeverityMedium,
		})
	}
	return findings
}

func TestFindChainsAlgorithmic_SSRFtoRCE(t *testing.T) {
	c := NewChainer(nil, nil)

	findings := makeFindings(
		struct{ id, host, url, vulnClass string }{"f1", "example.com", "https://example.com/fetch?url=x", "ssrf"},
		struct{ id, host, url, vulnClass string }{"f2", "example.com", "https://example.com/api/exec", "rce"},
	)

	chains := c.FindChainsAlgorithmic(findings)

	if len(chains) == 0 {
		t.Fatal("expected at least one chain (SSRF → RCE)")
	}

	found := false
	for _, ch := range chains {
		if ch.Name == "SSRF → Internal API → RCE" {
			found = true
			if ch.Severity != "critical" {
				t.Errorf("expected critical severity, got %s", ch.Severity)
			}
			if len(ch.Steps) != 2 {
				t.Errorf("expected 2 steps, got %d", len(ch.Steps))
			}
			if ch.Confidence < 0.5 {
				t.Errorf("expected confidence >= 0.5, got %f", ch.Confidence)
			}
		}
	}
	if !found {
		t.Error("SSRF → Internal API → RCE chain not found")
	}
}

func TestFindChainsAlgorithmic_XSStoCSRF(t *testing.T) {
	c := NewChainer(nil, nil)

	findings := makeFindings(
		struct{ id, host, url, vulnClass string }{"f1", "app.com", "https://app.com/search?q=test", "xss"},
		struct{ id, host, url, vulnClass string }{"f2", "app.com", "https://app.com/api/transfer", "csrf"},
	)

	chains := c.FindChainsAlgorithmic(findings)

	found := false
	for _, ch := range chains {
		if ch.Name == "XSS → CSRF → Account Takeover" {
			found = true
			if ch.Severity != "high" {
				t.Errorf("expected high severity, got %s", ch.Severity)
			}
		}
	}
	if !found {
		t.Error("XSS → CSRF → Account Takeover chain not found")
	}
}

func TestFindChainsAlgorithmic_SameHost_HigherConfidence(t *testing.T) {
	c := NewChainer(nil, nil)

	// Same host → higher confidence
	findings := makeFindings(
		struct{ id, host, url, vulnClass string }{"f1", "same.com", "https://same.com/a", "ssrf"},
		struct{ id, host, url, vulnClass string }{"f2", "same.com", "https://same.com/b", "rce"},
	)

	chains := c.FindChainsAlgorithmic(findings)
	if len(chains) == 0 {
		t.Fatal("expected chain")
	}
	if chains[0].Confidence < 0.7 {
		t.Errorf("same-host chain should have confidence >= 0.7, got %f", chains[0].Confidence)
	}
}

func TestFindChainsAlgorithmic_NoMatch(t *testing.T) {
	c := NewChainer(nil, nil)

	// Two findings that don't form any known pattern
	findings := makeFindings(
		struct{ id, host, url, vulnClass string }{"f1", "a.com", "https://a.com/", "misconfig"},
		struct{ id, host, url, vulnClass string }{"f2", "b.com", "https://b.com/", "open_redirect"},
	)

	chains := c.FindChainsAlgorithmic(findings)
	if len(chains) != 0 {
		t.Errorf("expected no chains, got %d", len(chains))
	}
}

func TestFindChainsAlgorithmic_SingleFinding(t *testing.T) {
	c := NewChainer(nil, nil)

	findings := makeFindings(
		struct{ id, host, url, vulnClass string }{"f1", "a.com", "https://a.com/", "xss"},
	)

	chains := c.FindChainsAlgorithmic(findings)
	if len(chains) != 0 {
		t.Errorf("expected no chains for single finding, got %d", len(chains))
	}
}

func TestFindChainsAlgorithmic_MultiplePatterns(t *testing.T) {
	c := NewChainer(nil, nil)

	// Findings that match multiple patterns
	findings := makeFindings(
		struct{ id, host, url, vulnClass string }{"f1", "target.com", "https://target.com/proxy", "ssrf"},
		struct{ id, host, url, vulnClass string }{"f2", "target.com", "https://target.com/exec", "rce"},
		struct{ id, host, url, vulnClass string }{"f3", "target.com", "https://target.com/debug", "info_disclosure"},
	)

	chains := c.FindChainsAlgorithmic(findings)

	// Should match: SSRF→RCE, SSRF→InfoDisclosure
	if len(chains) < 2 {
		t.Errorf("expected at least 2 chains, got %d", len(chains))
	}
}

func TestParseChainerResponse(t *testing.T) {
	resp := `[
		{
			"name": "XSS → Token Theft",
			"steps": [
				{"order": 1, "finding_id": "f1", "vuln_class": "xss", "action": "Inject script"},
				{"order": 2, "finding_id": "f2", "vuln_class": "auth_bypass", "action": "Steal token"}
			],
			"impact": "Account takeover via XSS",
			"severity": "high",
			"confidence": 0.7
		}
	]`

	chains, err := parseChainerResponse(resp)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}

	ch := chains[0]
	if ch.Name != "XSS → Token Theft" {
		t.Errorf("name = %q", ch.Name)
	}
	if len(ch.Steps) != 2 {
		t.Errorf("steps = %d, want 2", len(ch.Steps))
	}
	if ch.Severity != "high" {
		t.Errorf("severity = %q, want high", ch.Severity)
	}
	if ch.Confidence != 0.7 {
		t.Errorf("confidence = %f, want 0.7", ch.Confidence)
	}
}

func TestParseChainerResponse_EmptyArray(t *testing.T) {
	chains, err := parseChainerResponse("[]")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(chains) != 0 {
		t.Errorf("expected 0 chains, got %d", len(chains))
	}
}

func TestParseChainerResponse_MarkdownWrapped(t *testing.T) {
	resp := "```json\n" + `[{"name":"test","steps":[],"impact":"x","severity":"low","confidence":0.5}]` + "\n```"

	chains, err := parseChainerResponse(resp)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(chains) != 1 {
		t.Errorf("expected 1 chain, got %d", len(chains))
	}
}

func TestDeduplicateChains(t *testing.T) {
	chains := []Chain{
		{Name: "A → B"},
		{Name: "A → B"},
		{Name: "C → D"},
	}

	result := deduplicateChains(chains)
	if len(result) != 2 {
		t.Errorf("expected 2 unique chains, got %d", len(result))
	}
}

func TestKnownPatterns_AllHaveRequiredFields(t *testing.T) {
	for i, p := range KnownPatterns {
		if p.Name == "" {
			t.Errorf("pattern %d: empty name", i)
		}
		if len(p.Steps) < 2 {
			t.Errorf("pattern %d (%s): needs >= 2 steps, has %d", i, p.Name, len(p.Steps))
		}
		if p.Severity == "" {
			t.Errorf("pattern %d (%s): empty severity", i, p.Name)
		}
		if p.Impact == "" {
			t.Errorf("pattern %d (%s): empty impact", i, p.Name)
		}
	}
}
