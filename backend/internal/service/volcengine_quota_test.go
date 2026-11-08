//go:build unit

package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The signature is the one Volcengine's own SDK makes (golden vector taken from
// volc-sdk-golang GetSignRequest): POST open.volcengineapi.com/ with Action and
// Version in the query, body `{}`, content-type application/json, service ark.
func TestVolcengineSignMatchesSDK(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 9, 8, 30, 15, 0, time.UTC)
	cases := []struct {
		region string
		action string
		sig    string
	}{
		{"cn-beijing", volcengineActionCodingPlan, "deb80c0cd8bd77768ca40f6d47c7204621c0994428f6ab77e23b76e15dc4c047"},
		{"cn-shanghai", volcengineActionAgentPlan, "8a241be0996c93de4dfcd9e8b1db37494bf63170804fcaebe8380ff7dca2bb23"},
	}
	for _, tc := range cases {
		auth, xDate, contentSHA := volcengineSign(
			"AKLTexample", "c2VjcmV0LWV4YW1wbGU=", tc.region,
			volcengineCanonicalQuery(tc.action), []byte("{}"), now)
		require.Equal(t, "20261009T083015Z", xDate)
		require.Equal(t, "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", contentSHA)
		require.Equal(t,
			"HMAC-SHA256 Credential=AKLTexample/20261009/"+tc.region+"/ark/request, "+
				"SignedHeaders=content-type;host;x-content-sha256;x-date, Signature="+tc.sig,
			auth)
	}

	// A time in another zone signs as the same instant in UTC.
	cst := time.Date(2026, 10, 9, 16, 30, 15, 0, time.FixedZone("CST", 8*3600))
	_, xDate, _ := volcengineSign("a", "b", "cn-beijing", volcengineCanonicalQuery(volcengineActionAgentPlan), nil, cst)
	require.Equal(t, "20261009T083015Z", xDate)
}

func TestVolcenginePlanForBaseURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		baseURL string
		action  string
		plan    string
		region  string
		ok      bool
	}{
		{"https://ark.cn-beijing.volces.com/api/coding/v3", volcengineActionCodingPlan, "Coding Plan", "cn-beijing", true},
		{"https://ark.cn-beijing.volces.com/api/coding", volcengineActionCodingPlan, "Coding Plan", "cn-beijing", true},
		{"https://ark.cn-shanghai.volces.com/api/plan/v3", volcengineActionAgentPlan, "Agent Plan", "cn-shanghai", true},
		{"https://ark.ap-southeast.volces.com/api/plan", volcengineActionAgentPlan, "Agent Plan", "ap-southeast", true},
		{"https://ark.cn-beijing.volces.com/api/v3", "", "", "", false},
		{"https://relay.example.com/api/coding/v3", "", "", "", false},
		{"https://ark.cn-beijing.volces.com/api/coding/v3?x=1", "", "", "", false},
	}
	for _, tc := range cases {
		got, ok := volcenginePlanForBaseURL(tc.baseURL)
		require.Equal(t, tc.ok, ok, tc.baseURL)
		require.Equal(t, tc.action, got.Action, tc.baseURL)
		require.Equal(t, tc.plan, got.Plan, tc.baseURL)
		require.Equal(t, tc.region, got.Region, tc.baseURL)
	}
}

func TestParseVolcengineCodingPlanTiers(t *testing.T) {
	t.Parallel()
	body := []byte(`{"Result":{"QuotaUsage":[
		{"Level":"session","Percent":10.5,"ResetTimestamp":1758100000},
		{"Level":"weekly","Percent":20.25,"ResetTimestamp":1758200000},
		{"Level":"monthly","Percent":"30.75","ResetTimestamp":1758300000},
		{"Level":"daily","Percent":1},
		{"Level":"session","Percent":99,"ResetTimestamp":1758400000}
	]}}`)
	tiers := parseVolcengineCodingPlanTiers(body)
	require.Len(t, tiers, 3)
	require.Equal(t, "5h", tiers[0].Window)
	require.InDelta(t, 10.5, tiers[0].UsedPercent, 1e-9)
	require.Equal(t, "2025-09-17T09:06:40Z", tiers[0].ResetAt)
	require.Equal(t, "weekly", tiers[1].Window)
	require.InDelta(t, 20.25, tiers[1].UsedPercent, 1e-9)
	require.Equal(t, "monthly", tiers[2].Window)
	require.InDelta(t, 30.75, tiers[2].UsedPercent, 1e-9)
}

func TestParseVolcengineAFPTiers(t *testing.T) {
	t.Parallel()
	// Quota form: absolute AFP, reset in milliseconds. AFPDaily is intentionally ignored.
	body := []byte(`{"Result":{
		"PlanType":"Medium",
		"AFPFiveHour":{"Quota":"100","Used":"42","ResetTime":1790000000000},
		"AFPDaily":{"Quota":"500","Used":"400"},
		"AFPWeekly":{"Quota":"0","Used":"5"},
		"AFPMonthly":{"Quota":"200","Used":"50"}
	}}`)
	tiers, tier := parseVolcengineAFPTiers(body)
	require.Equal(t, "Medium", tier)
	require.Len(t, tiers, 2)
	require.Equal(t, "5h", tiers[0].Window)
	require.InDelta(t, 42.0, tiers[0].UsedPercent, 1e-9)
	require.Equal(t, "2026-09-21T14:13:20Z", tiers[0].ResetAt)
	require.Equal(t, "monthly", tiers[1].Window)
	require.InDelta(t, 25.0, tiers[1].UsedPercent, 1e-9)
	require.Empty(t, tiers[1].ResetAt)

	// Percent/Total form and a different tier field.
	body = []byte(`{"Result":{"Tier":"Large",
		"AFPFiveHour":{"Percent":12.5,"ResetTimestamp":1790000000},
		"AFPWeekly":{"Used":"30","Total":"120","ResetTime":"2026-10-12T00:00:00Z"}}}`)
	tiers, tier = parseVolcengineAFPTiers(body)
	require.Equal(t, "Large", tier)
	require.Len(t, tiers, 2)
	require.InDelta(t, 12.5, tiers[0].UsedPercent, 1e-9)
	require.Equal(t, "2026-09-21T14:13:20Z", tiers[0].ResetAt)
	require.Equal(t, "weekly", tiers[1].Window)
	require.InDelta(t, 25.0, tiers[1].UsedPercent, 1e-9)
	require.Equal(t, "2026-10-12T00:00:00Z", tiers[1].ResetAt)
}

func TestVolcengineAccountPlanDetection(t *testing.T) {
	t.Parallel()
	coding := &Account{
		Platform: PlatformVolcengine,
		Type:     AccountTypeAPIKey,
		Credentials: map[string]any{
			"api_key":      "ark-key",
			"account_mode": AccountModeCoding,
			"base_url":     DefaultVolcengineCodingBaseURL,
		},
	}
	require.Equal(t, AccountModeCoding, coding.GetAccountMode())
	require.True(t, coding.IsCodingPlan())
	require.True(t, coding.HasRollingQuotaPlan())
	require.Equal(t, PlatformVolcengine, coding.GetCodingPlanProvider())

	agent := &Account{
		Platform: PlatformVolcengine,
		Type:     AccountTypeAPIKey,
		Credentials: map[string]any{
			"api_key":      "ark-key",
			"account_mode": AccountModeAgent,
			"base_url":     DefaultVolcengineAgentBaseURL,
		},
	}
	require.Equal(t, AccountModeAgent, agent.GetAccountMode())
	require.True(t, agent.IsAgentPlan())
	require.True(t, agent.HasRollingQuotaPlan())
	require.Equal(t, PlatformVolcengine, agent.GetCodingPlanProvider())

	// Missing account_mode defaults to Coding Plan for Volcengine.
	defaulted := &Account{
		Platform:    PlatformVolcengine,
		Type:        AccountTypeAPIKey,
		Credentials: map[string]any{"api_key": "ark-key"},
	}
	require.Equal(t, AccountModeCoding, defaulted.GetAccountMode())
	require.Equal(t, DefaultVolcengineCodingBaseURL, defaulted.GetOpenAIBaseURL())

	// Anthropic-only base_url still identifies the plan.
	anthropic := &Account{
		Platform: PlatformVolcengine,
		Type:     AccountTypeAPIKey,
		Credentials: map[string]any{
			"api_key":      "ark-key",
			"account_mode": AccountModeAgent,
			"api_protocol": APIProtocolAnthropic,
			"base_url":     DefaultVolcengineAgentAnthropicBaseURL,
		},
	}
	require.Equal(t, PlatformVolcengine, anthropic.GetCodingPlanProvider())

	// Third-party relay and pay-as-you-go endpoints are not routed to the control plane.
	relay := &Account{
		Platform: PlatformVolcengine,
		Type:     AccountTypeAPIKey,
		Credentials: map[string]any{
			"api_key":      "ark-key",
			"account_mode": AccountModeCoding,
			"base_url":     "https://relay.example.com/api/coding/v3",
		},
	}
	require.Empty(t, relay.GetCodingPlanProvider())
	payg := &Account{
		Platform: PlatformVolcengine,
		Type:     AccountTypeAPIKey,
		Credentials: map[string]any{
			"api_key":      "ark-key",
			"account_mode": AccountModePayG,
			"base_url":     DefaultVolcengineCodingBaseURL,
		},
	}
	require.Empty(t, payg.GetCodingPlanProvider())
}
