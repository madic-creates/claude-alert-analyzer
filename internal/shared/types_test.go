package shared

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestToolRequestJSON(t *testing.T) {
	req := ToolRequest{
		Model:     "claude-sonnet-4-6",
		MaxTokens: 2048,
		System:    []SystemBlock{{Type: "text", Text: "You are an SRE."}},
		Tools: []Tool{{
			Name:        "execute_command",
			Description: "Run a command via SSH",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"command": {Type: "array", Description: "Command argv"},
				},
				Required: []string{"command"},
			},
		}},
		Messages: []ToolMessage{{
			Role:    "user",
			Content: "Investigate this alert.",
		}},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	tools := parsed["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	tool := tools[0].(map[string]any)
	if tool["name"] != "execute_command" {
		t.Errorf("expected tool name execute_command, got %v", tool["name"])
	}
}

func TestToolMessageJSON_StringContent(t *testing.T) {
	msg := ToolMessage{Role: "user", Content: "hello"}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed map[string]any
	json.Unmarshal(data, &parsed)
	if parsed["content"] != "hello" {
		t.Errorf("expected string content, got %v", parsed["content"])
	}
}

func TestToolMessageJSON_BlockContent(t *testing.T) {
	msg := ToolMessage{
		Role: "user",
		Content: []ContentBlock{
			{Type: "tool_result", ToolUseID: "toolu_123", Content: "output here"},
		},
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed map[string]any
	json.Unmarshal(data, &parsed)
	blocks := parsed["content"].([]any)
	if len(blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(blocks))
	}
	block := blocks[0].(map[string]any)
	if block["type"] != "tool_result" {
		t.Errorf("expected tool_result, got %v", block["type"])
	}
}

func TestToolResponseParse_EndTurn(t *testing.T) {
	raw := `{
		"content": [{"type": "text", "text": "Analysis complete."}],
		"stop_reason": "end_turn",
		"usage": {"input_tokens": 100, "output_tokens": 50}
	}`
	var resp ToolResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.StopReason != "end_turn" {
		t.Errorf("expected end_turn, got %s", resp.StopReason)
	}
	if len(resp.Content) != 1 || resp.Content[0].Text != "Analysis complete." {
		t.Error("unexpected content")
	}
}

func TestFormatForPrompt(t *testing.T) {
	ac := AnalysisContext{
		Sections: []ContextSection{
			{Name: "Metrics", Content: "cpu=90%"},
			{Name: "Events", Content: "pod restarted"},
		},
	}
	got := ac.FormatForPrompt()
	want := "## Metrics\ncpu=90%\n\n## Events\npod restarted\n\n"
	if got != want {
		t.Errorf("FormatForPrompt() =\n%q\nwant:\n%q", got, want)
	}
}

func TestFormatForPrompt_Empty(t *testing.T) {
	ac := AnalysisContext{}
	got := ac.FormatForPrompt()
	if got != "" {
		t.Errorf("FormatForPrompt() = %q, want empty", got)
	}
}

func TestAlertPayload_HasSeverityField(t *testing.T) {
	p := AlertPayload{SeverityLevel: SeverityCritical}
	if p.SeverityLevel != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", p.SeverityLevel)
	}
}

func TestToolResponseParse_ToolUse(t *testing.T) {
	raw := `{
		"content": [
			{"type": "text", "text": "Let me check disk usage."},
			{"type": "tool_use", "id": "toolu_abc", "name": "execute_command", "input": {"command": ["df", "-h"]}}
		],
		"stop_reason": "tool_use",
		"usage": {"input_tokens": 200, "output_tokens": 80}
	}`
	var resp ToolResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.StopReason != "tool_use" {
		t.Errorf("expected tool_use, got %s", resp.StopReason)
	}
	if len(resp.Content) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(resp.Content))
	}
	toolBlock := resp.Content[1]
	if toolBlock.Name != "execute_command" || toolBlock.ID != "toolu_abc" {
		t.Error("unexpected tool_use block")
	}
}

func TestSystemBlock_JSON(t *testing.T) {
	b := SystemBlock{
		Type:         "text",
		Text:         "hello",
		CacheControl: &CacheControl{Type: "ephemeral"},
	}
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"text","text":"hello","cache_control":{"type":"ephemeral"}}`
	if string(out) != want {
		t.Errorf("got %s, want %s", out, want)
	}
}

func TestSystemBlock_JSON_OmitsCacheControlWhenNil(t *testing.T) {
	b := SystemBlock{Type: "text", Text: "hello"}
	out, _ := json.Marshal(b)
	if !strings.Contains(string(out), `"text":"hello"`) || strings.Contains(string(out), "cache_control") {
		t.Errorf("unexpected JSON: %s", out)
	}
}

func TestToolRequest_SystemIsBlocks(t *testing.T) {
	req := ToolRequest{
		Model:     "x",
		MaxTokens: 1,
		System:    []SystemBlock{{Type: "text", Text: "p"}},
	}
	out, _ := json.Marshal(req)
	if !strings.Contains(string(out), `"system":[{"type":"text","text":"p"}]`) {
		t.Errorf("system not serialized as blocks: %s", out)
	}
}

func TestToolResponse_UsageHasCacheFields(t *testing.T) {
	body := []byte(`{"usage":{"input_tokens":1,"output_tokens":2,"cache_creation_input_tokens":3,"cache_read_input_tokens":4}}`)
	var resp ToolResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Usage.CacheCreationInputTokens != 3 {
		t.Errorf("CacheCreation: got %d", resp.Usage.CacheCreationInputTokens)
	}
	if resp.Usage.CacheReadInputTokens != 4 {
		t.Errorf("CacheRead: got %d", resp.Usage.CacheReadInputTokens)
	}
}
