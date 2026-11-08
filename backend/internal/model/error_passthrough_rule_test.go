package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAllPlatformsIncludesEveryConcretePlatform(t *testing.T) {
	require.ElementsMatch(t, []string{
		"anthropic",
		"openai",
		"gemini",
		"antigravity",
		"kiro",
		"grok",
		"kimi",
		"zhipu",
		"deepseek",
		"minimax",
		"volcengine",
		"opencode_go",
		"typesafe",
		"command_code",
		"cline",
		"leonardo",
		"fish",
	}, AllPlatforms())
}
