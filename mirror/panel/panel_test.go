package panel

import (
	"strings"
	"testing"
)

func TestNormalizeAPIHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{
			name:  "trim surrounding spaces",
			input: " https://example.com/ ",
			want:  "https://example.com",
		},
		{
			name:  "trim whitespace after scheme",
			input: "https:// example.com/api/v1/",
			want:  "https://example.com/api/v1",
		},
		{
			name:  "trim copied wrapping punctuation",
			input: "(https://www.example.com/)",
			want:  "https://www.example.com",
		},
		{
			name:    "reject whitespace in host",
			input:   "https://exa mple.com",
			wantErr: "host contains whitespace",
		},
		{
			name:    "reject empty value",
			input:   "   ",
			wantErr: "value is empty",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := normalizeAPIHost(tc.input)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestCheckResponseWithNilResponse(t *testing.T) {
	t.Parallel()

	client := &Client{APIHost: "https://example.com"}
	err := client.checkResponse(nil, "/api/v1/server/UniProxy/config", nil)
	if err == nil {
		t.Fatal("expected error for nil response, got nil")
	}
	if !strings.Contains(err.Error(), "empty response") {
		t.Fatalf("expected empty response error, got %q", err.Error())
	}
}

func TestAssembleURLPreservesScheme(t *testing.T) {
	t.Parallel()

	client := &Client{APIHost: "https://example.com/api"}
	got := client.assembleURL("/v1/server/UniProxy/config")
	want := "https://example.com/api/v1/server/UniProxy/config"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestRedactPanelSecrets(t *testing.T) {
	t.Parallel()

	input := "Get \"https://example.com/api?node_id=1&token=tasty-secret&node_type=vless\": timeout {\"ApiKey\":\"json-secret\"}"
	got := redactPanelSecrets(input)
	if strings.Contains(got, "tasty-secret") || strings.Contains(got, "json-secret") || strings.Contains(got, "secret") {
		t.Fatalf("expected secrets to be redacted, got %q", got)
	}
	if !strings.Contains(got, "token=<redacted>&node_type") || !strings.Contains(got, "\"ApiKey\":\"<redacted>\"") {
		t.Fatalf("expected redacted markers, got %q", got)
	}
}
