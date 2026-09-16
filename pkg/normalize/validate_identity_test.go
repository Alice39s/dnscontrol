package normalize

import (
	"strings"
	"testing"

	dnsv2 "codeberg.org/miekg/dns"

	"github.com/DNSControl/dnscontrol/v5/models"
	_ "github.com/DNSControl/dnscontrol/v5/providers/tencentdns"
)

const lineZone = "smart-cluster.hats-saas.top"

// Per-line answers for one name: four lines point at the same target.
var lineRoutes = []struct {
	line   string
	target string
}{
	{"0", "edge-hkg.sgs.smart-cluster.hats-saas.top."},
	{"7=0", "edge-hkg.sgs.smart-cluster.hats-saas.top."},
	{"5=2", "edge-hkg.sgs.smart-cluster.hats-saas.top."},
	{"5=5", "edge-hkg.sgs.smart-cluster.hats-saas.top."},
	{"5=4", "edge-lax.sgs.smart-cluster.hats-saas.top."},
	{"5=6", "edge-lax.sgs.smart-cluster.hats-saas.top."},
	{"5=3", "edge-lon.sgs.smart-cluster.hats-saas.top."},
	{"5=0", "edge-lon.sgs.smart-cluster.hats-saas.top."},
}

func lineDomain(providerType string) *models.DomainConfig {
	dc := models.MustNewDomainConfig(lineZone)
	dc.RegistrarName = "NONE"
	dc.DNSProviderNames = map[string]int{"lines": 1}
	dc.DNSProviderInstances = []*models.DNSProviderInstance{{
		Name:         "lines",
		ProviderType: providerType,
	}}
	return dc
}

func addLineRecords(dc *models.DomainConfig, rType uint16, target string) {
	for _, route := range lineRoutes {
		r := dc.MustNewRecordConfig("*.sgs", 60, rType, target)
		r.Metadata["tencentdns_line_id"] = route.line
		dc.AddRecordConfig(r)
	}
}

func validateDomain(t *testing.T, dc *models.DomainConfig) []error {
	t.Helper()
	return ValidateAndNormalizeConfig(&models.DNSConfig{
		Domains: []*models.DomainConfig{dc},
	})
}

func TestPerLineCNAMEsShareOneName(t *testing.T) {
	dc := lineDomain("TENCENTDNS")
	for _, route := range lineRoutes {
		r := dc.MustNewRecordConfig("*.sgs", 60, dnsv2.TypeCNAME, route.target)
		r.Metadata["tencentdns_line_id"] = route.line
		dc.AddRecordConfig(r)
	}

	if errs := validateDomain(t, dc); len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %v", errs)
	}
}

func TestPerLineAddressesMayShareOneTarget(t *testing.T) {
	dc := lineDomain("TENCENTDNS")
	addLineRecords(dc, dnsv2.TypeA, "109.105.193.70")

	if errs := validateDomain(t, dc); len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %v", errs)
	}
}

func TestPerLineRecordsStillFailWithoutProviderIdentity(t *testing.T) {
	dc := lineDomain("ROUTE53")
	addLineRecords(dc, dnsv2.TypeA, "109.105.193.70")

	errs := validateDomain(t, dc)
	if len(errs) == 0 {
		t.Fatal("expected duplicate errors for a provider that declares no record identity")
	}
	if !strings.Contains(errs[0].Error(), "exact duplicate record found") {
		t.Fatalf("unexpected first error: %v", errs[0])
	}
}

func TestTwoCNAMEsOnOneLineRemainAnError(t *testing.T) {
	dc := lineDomain("TENCENTDNS")
	first := dc.MustNewRecordConfig("*.sgs", 60, dnsv2.TypeCNAME, lineRoutes[0].target)
	first.Metadata["tencentdns_line_id"] = lineRoutes[0].line
	dc.AddRecordConfig(first)
	second := dc.MustNewRecordConfig("*.sgs", 60, dnsv2.TypeCNAME, "other.example.net.")
	second.Metadata["tencentdns_line_id"] = lineRoutes[0].line
	dc.AddRecordConfig(second)

	errs := validateDomain(t, dc)
	if len(errs) == 0 {
		t.Fatal("expected an error for two CNAMEs on the same line")
	}
	if !strings.Contains(errs[0].Error(), "cannot have multiple CNAMEs with same name") {
		t.Fatalf("unexpected first error: %v", errs[0])
	}
}

func TestWeightDoesNotSplitTheIdentity(t *testing.T) {
	dc := lineDomain("TENCENTDNS")
	for _, weight := range []string{"10", "20"} {
		r := dc.MustNewRecordConfig("weighted.sgs", 60, dnsv2.TypeA, "203.0.113.10")
		r.Metadata["tencentdns_line_id"] = "5=2"
		r.Metadata["tencentdns_weight"] = weight
		dc.AddRecordConfig(r)
	}

	errs := validateDomain(t, dc)
	if len(errs) == 0 {
		t.Fatal("expected duplicate detection: the service keys records without weight")
	}
	if !strings.Contains(errs[0].Error(), "exact duplicate record found") {
		t.Fatalf("unexpected first error: %v", errs[0])
	}
}

func TestLineNamesAloneAlsoCarryIdentity(t *testing.T) {
	dc := lineDomain("TENCENTDNS")
	for _, line := range []string{"电信", "联通"} {
		r := dc.MustNewRecordConfig("named.sgs", 60, dnsv2.TypeA, "203.0.113.10")
		r.Metadata["tencentdns_line"] = line
		dc.AddRecordConfig(r)
	}

	if errs := validateDomain(t, dc); len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %v", errs)
	}
}
