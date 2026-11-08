package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/tidwall/gjson"
)

// 火山方舟订阅套餐（Coding Plan / Agent Plan）额度探测。
//
// 推理走数据面（ark.<region>.volces.com/api/coding|plan），额度只能由控制面
// OpenAPI 查询：POST https://open.volcengineapi.com/?Action=...&Version=2024-01-01，
// 且强制使用账号的 AccessKey ID / Secret 做火山签名 V4。推理 API Key（api_key）
// 与控制面 AK/SK 是两套凭据，后者仅发往固定的控制面主机。
//
// 套餐类型由推理 base_url 决定，与账号 account_mode 一致：
//   - /api/coding → GetCodingPlanUsage（session / weekly / monthly 百分比）
//   - /api/plan   → GetAFPUsage（5h / weekly / monthly AFP 绝对用量）
//
// 不复用 cc-switch 的“先查 Agent Plan 再回落 Coding Plan”自动探测：同一火山账号
// 可能同时持有两种套餐，自动探测会把 Coding 账号误报成 Agent 额度。
const (
	volcengineOpenAPIHost       = "open.volcengineapi.com"
	volcengineOpenAPIAPIVersion = "2024-01-01"
	volcengineOpenAPIService    = "ark"
	volcengineOpenAPIRegion     = "cn-beijing"
	volcengineContentType       = "application/json"

	volcengineActionCodingPlan = "GetCodingPlanUsage"
	volcengineActionAgentPlan  = "GetAFPUsage"

	volcengineAKSKHint = "check the AccessKey ID / Secret and that the IAM user may query Ark usage (OpenAPI)"
)

type volcenginePlanEndpoint struct {
	Action string
	Plan   string
	Region string
}

// volcenginePlanForBaseURL 从官方推理 base_url 解析套餐类型与签名 Region。
// 只认 ark.<region>.volces.com 的 /api/coding[/v3] 与 /api/plan[/v3]。
func volcenginePlanForBaseURL(baseURL string) (volcenginePlanEndpoint, bool) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(baseURL, "#") {
		return volcenginePlanEndpoint{}, false
	}
	host := strings.ToLower(parsed.Hostname())
	labels := strings.Split(host, ".")
	if len(labels) != 4 || labels[0] != "ark" || labels[1] == "" ||
		labels[2] != "volces" || labels[3] != "com" {
		return volcenginePlanEndpoint{}, false
	}
	region := labels[1]
	if !strings.HasPrefix(region, "cn-") && !strings.HasPrefix(region, "ap-") {
		region = volcengineOpenAPIRegion
	}
	path := parsed.EscapedPath()
	switch {
	case path == "/api/coding" || strings.HasPrefix(path, "/api/coding/"):
		return volcenginePlanEndpoint{Action: volcengineActionCodingPlan, Plan: "Coding Plan", Region: region}, true
	case path == "/api/plan" || strings.HasPrefix(path, "/api/plan/"):
		return volcenginePlanEndpoint{Action: volcengineActionAgentPlan, Plan: "Agent Plan", Region: region}, true
	default:
		return volcenginePlanEndpoint{}, false
	}
}

// volcengineCanonicalQuery 生成按 key 字母序、RFC3986 编码的 canonical query，
// 同一份字符串同时用于签名与实际请求 URL。
func volcengineCanonicalQuery(action string) string {
	values := url.Values{
		"Action":  {action},
		"Version": {volcengineOpenAPIAPIVersion},
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(values.Get(key)))
	}
	return strings.Join(parts, "&")
}

// volcengineSign 复刻火山引擎签名 V4（volc-sdk-golang GetSignRequest）：
// SignedHeaders 按字母序、scope 结尾为 request、密钥派生不加 AWS4 前缀。
// 返回 Authorization / X-Date / X-Content-Sha256，三者都要写入请求头。
func volcengineSign(
	accessKeyID, secretAccessKey, region, canonicalQuery string,
	body []byte,
	now time.Time,
) (authorization, xDate, contentSHA string) {
	now = now.UTC()
	xDate = now.Format("20060102T150405Z")
	shortDate := xDate[:8]
	contentSHA = volcengineSHA256Hex(body)

	const signedHeaders = "content-type;host;x-content-sha256;x-date"
	canonicalHeaders := "content-type:" + volcengineContentType + "\n" +
		"host:" + volcengineOpenAPIHost + "\n" +
		"x-content-sha256:" + contentSHA + "\n" +
		"x-date:" + xDate + "\n"
	canonicalRequest := "POST\n/\n" + canonicalQuery + "\n" + canonicalHeaders + "\n" +
		signedHeaders + "\n" + contentSHA

	scope := shortDate + "/" + region + "/" + volcengineOpenAPIService + "/request"
	stringToSign := "HMAC-SHA256\n" + xDate + "\n" + scope + "\n" +
		volcengineSHA256Hex([]byte(canonicalRequest))

	key := volcengineHMAC([]byte(secretAccessKey), shortDate)
	key = volcengineHMAC(key, region)
	key = volcengineHMAC(key, volcengineOpenAPIService)
	key = volcengineHMAC(key, "request")
	signature := hex.EncodeToString(volcengineHMAC(key, stringToSign))

	authorization = "HMAC-SHA256 Credential=" + accessKeyID + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	return authorization, xDate, contentSHA
}

func volcengineHMAC(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(data))
	return mac.Sum(nil)
}

func volcengineSHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (s *CNProviderQuotaService) queryVolcengineUsage(ctx context.Context, account *Account) (*CNProviderQuotaProbeResult, error) {
	plan, ok := volcenginePlanForBaseURL(account.GetOpenAIBaseURL())
	if !ok {
		return nil, infraerrors.New(http.StatusBadRequest, "CN_QUOTA_VOLCENGINE_ENDPOINT",
			"volcengine base_url must be the official /api/coding or /api/plan endpoint")
	}
	if (account.IsAgentPlan() && plan.Action != volcengineActionAgentPlan) ||
		(account.IsCodingPlan() && plan.Action != volcengineActionCodingPlan) {
		return nil, infraerrors.New(http.StatusBadRequest, "CN_QUOTA_VOLCENGINE_PLAN_MISMATCH",
			"account mode does not match the volcengine base_url plan endpoint")
	}
	accessKeyID := account.GetVolcengineAccessKeyID()
	secretAccessKey := account.GetVolcengineSecretAccessKey()
	if accessKeyID == "" || secretAccessKey == "" {
		return nil, infraerrors.Newf(http.StatusBadRequest, "CN_QUOTA_VOLCENGINE_NO_AKSK",
			"volcengine usage query requires access_key_id and secret_access_key; %s", volcengineAKSKHint)
	}

	canonicalQuery := volcengineCanonicalQuery(plan.Action)
	targetURL := "https://" + volcengineOpenAPIHost + "/?" + canonicalQuery
	validatedURL, err := cnValidateProbeURL(s.cfg, targetURL)
	if err != nil {
		return nil, infraerrors.New(http.StatusForbidden, "CN_QUOTA_URL_REJECTED", err.Error())
	}
	targetURL = validatedURL

	// 空 body 与 SDK 的差异只在 Content-SHA256；固定用 {} 与官方 SDK 示例一致。
	body := []byte("{}")
	authorization, xDate, contentSHA := volcengineSign(
		accessKeyID, secretAccessKey, plan.Region, canonicalQuery, body, time.Now())
	callCtx, cancel := context.WithTimeout(ctx, cnQuotaUpstreamTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, targetURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, infraerrors.Newf(http.StatusInternalServerError, "CN_QUOTA_REQUEST_BUILD_FAILED", "build request: %v", err)
	}
	req.Header.Set("Content-Type", volcengineContentType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Date", xDate)
	req.Header.Set("X-Content-Sha256", contentSHA)
	req.Header.Set("Authorization", authorization)

	proxyURL := s.resolveProxyURL(ctx, account)
	resp, err := s.httpUpstream.Do(req, proxyURL, account.ID, maxInt(account.Concurrency, 1))
	if err != nil {
		return nil, infraerrors.Newf(http.StatusBadGateway, "CN_QUOTA_REQUEST_FAILED", "upstream request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, cnQuotaMaxBodyBytes))

	now := time.Now().UTC()
	result := &CNProviderQuotaProbeResult{
		Provider:   PlatformVolcengine,
		Source:     "coding_plan",
		FetchedAt:  now.Unix(),
		StatusCode: resp.StatusCode,
		PlanLevel:  plan.Plan,
	}

	code, message, hasError := volcengineOpenAPIError(bodyBytes)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
		(hasError && volcengineIsAuthErrorCode(code)) {
		result.Error = volcengineAuthErrorText(resp.StatusCode, code, message)
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if hasError {
			result.Error = "API error (HTTP " + http.StatusText(resp.StatusCode) + ", " + code + "): " + message
		} else {
			result.Error = "API error (HTTP " + http.StatusText(resp.StatusCode) + "): " +
				truncate(strings.TrimSpace(string(bodyBytes)), 240)
		}
		return result, nil
	}
	if hasError {
		result.Error = "API error (" + code + "): " + message
		return result, nil
	}

	var tiers []CNQuotaTier
	switch plan.Action {
	case volcengineActionCodingPlan:
		tiers = parseVolcengineCodingPlanTiers(bodyBytes)
	case volcengineActionAgentPlan:
		var tier string
		tiers, tier = parseVolcengineAFPTiers(bodyBytes)
		if tier != "" {
			result.PlanLevel = plan.Plan + " " + tier
		}
	}
	if len(tiers) == 0 {
		result.Error = "No active " + plan.Plan + " subscription windows found"
		return result, nil
	}

	result.Tiers = tiers
	result.Success = true
	result.CredentialValid = true

	updates := cnQuotaExtraUpdates(PlatformVolcengine, tiers, now)
	if err := s.accountRepo.UpdateExtra(ctx, account.ID, updates); err != nil {
		slog.Warn("cn_quota_persist_failed", "account_id", account.ID, "provider", PlatformVolcengine, "error", err)
	} else {
		result.Persisted = true
	}
	return result, nil
}

func volcengineOpenAPIError(body []byte) (code, message string, ok bool) {
	errNode := gjson.GetBytes(body, "ResponseMetadata.Error")
	if !errNode.Exists() {
		errNode = gjson.GetBytes(body, "Error")
	}
	if !errNode.Exists() {
		return "", "", false
	}
	code = strings.TrimSpace(errNode.Get("Code").String())
	message = strings.TrimSpace(errNode.Get("Message").String())
	if code == "" && message == "" {
		return "", "", false
	}
	return code, message, true
}

func volcengineIsAuthErrorCode(code string) bool {
	code = strings.ToLower(code)
	for _, marker := range []string{
		"accesskey", "signature", "accessdenied", "denied", "unauthorized",
		"forbidden", "credential", "authfailure", "token", "auth",
	} {
		if strings.Contains(code, marker) {
			return true
		}
	}
	return false
}

func volcengineAuthErrorText(status int, code, message string) string {
	switch {
	case code != "" && message != "":
		return "Authentication failed (HTTP " + http.StatusText(status) + ", " + code + "): " + message + "; " + volcengineAKSKHint
	case status > 0:
		return "Authentication failed (HTTP " + http.StatusText(status) + "); " + volcengineAKSKHint
	default:
		return "Authentication failed; " + volcengineAKSKHint
	}
}

// parseVolcengineCodingPlanTiers 解析 GetCodingPlanUsage 的 Result：
// QuotaUsage[{Level: session|weekly|monthly, Percent, ResetTimestamp}]，百分比为已用
// 比例，重置时间为秒级时间戳。字段名做防御式兼容。
func parseVolcengineCodingPlanTiers(body []byte) []CNQuotaTier {
	result := gjson.GetBytes(body, "Result")
	if !result.Exists() {
		result = gjson.ParseBytes(body)
	}
	usage := result.Get("QuotaUsage")
	if !usage.IsArray() {
		usage = result.Get("Usages")
	}
	if !usage.IsArray() {
		return nil
	}
	var tiers []CNQuotaTier
	seen := make(map[string]struct{}, 3)
	usage.ForEach(func(_, item gjson.Result) bool {
		window := volcengineCodingWindow(volcengineFirstNonEmpty(
			item.Get("Level").String(), item.Get("Type").String(),
			item.Get("Period").String(), item.Get("Window").String()))
		if window == "" {
			return true
		}
		if _, dup := seen[window]; dup {
			return true
		}
		used, ok := cnParseF64(volcengineFirstExisting(
			item.Get("Percent"), item.Get("UsedPercent"), item.Get("UsagePercent")))
		if !ok {
			return true
		}
		if used < 0 {
			used = 0
		}
		seen[window] = struct{}{}
		tiers = append(tiers, CNQuotaTier{
			Window:      window,
			UsedPercent: used,
			ResetAt: cnNormalizeResetTime(volcengineFirstExisting(
				item.Get("ResetTimestamp"), item.Get("ResetTime"))),
		})
		return true
	})
	return tiers
}

// parseVolcengineAFPTiers 解析 GetAFPUsage 的 Result：AFPFiveHour / AFPWeekly /
// AFPMonthly 各含 Quota、Used、ResetTime（毫秒）。AFPDaily 与控制台一致不展示。
// Quota<=0 视为该窗口未订阅。兼容 Total/Percent 形态与 PlanType/Tier 两种档位字段。
func parseVolcengineAFPTiers(body []byte) ([]CNQuotaTier, string) {
	result := gjson.GetBytes(body, "Result")
	if !result.Exists() {
		result = gjson.ParseBytes(body)
	}
	var tiers []CNQuotaTier
	for _, bucket := range []struct {
		key    string
		window string
	}{
		{key: "AFPFiveHour", window: "5h"},
		{key: "AFPWeekly", window: "weekly"},
		{key: "AFPMonthly", window: "monthly"},
	} {
		node := result.Get(bucket.key)
		if !node.Exists() {
			continue
		}
		used, hasPercent := cnParseF64(node.Get("Percent").Value())
		if !hasPercent {
			quota, ok := cnParseF64(volcengineFirstExisting(node.Get("Quota"), node.Get("Total")))
			if !ok || quota <= 0 {
				continue
			}
			usedRaw, usedOK := cnParseF64(node.Get("Used").Value())
			if !usedOK {
				continue
			}
			used = usedRaw / quota * 100
		}
		if used < 0 {
			used = 0
		}
		tiers = append(tiers, CNQuotaTier{
			Window:      bucket.window,
			UsedPercent: used,
			ResetAt: cnNormalizeResetTime(volcengineFirstExisting(
				node.Get("ResetTime"), node.Get("ResetTimestamp"))),
		})
	}
	tier := strings.TrimSpace(result.Get("PlanType").String())
	if tier == "" {
		tier = strings.TrimSpace(result.Get("Tier").String())
	}
	return tiers, tier
}

func volcengineCodingWindow(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "session", "5h", "fivehour", "five_hour", "rolling_5h":
		return "5h"
	case "weekly", "week", "7d":
		return "weekly"
	case "monthly", "month":
		return "monthly"
	default:
		return ""
	}
}

func volcengineFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func volcengineFirstExisting(values ...gjson.Result) any {
	for _, value := range values {
		if value.Exists() {
			return value.Value()
		}
	}
	return nil
}
