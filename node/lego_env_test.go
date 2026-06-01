package node

import (
	"os"
	"testing"
)

func TestSanitizeCloudflareAuthEnv_WithToken_UnsetsLegacyAuth(t *testing.T) {
	t.Setenv("CF_API_EMAIL", "legacy@example.com")
	t.Setenv("CF_API_KEY", "legacy-key")
	t.Setenv("CLOUDFLARE_EMAIL", "legacy-alias@example.com")
	t.Setenv("CLOUDFLARE_API_KEY", "legacy-alias-key")

	sanitizeCloudflareAuthEnv(map[string]string{
		"CF_DNS_API_TOKEN": "token-value",
	})

	for _, key := range []string{
		"CF_API_EMAIL",
		"CF_API_KEY",
		"CLOUDFLARE_EMAIL",
		"CLOUDFLARE_API_KEY",
	} {
		if value := os.Getenv(key); value != "" {
			t.Fatalf("expected %s to be unset, got %q", key, value)
		}
	}
}

func TestSanitizeCloudflareAuthEnv_WithoutToken_KeepsLegacyAuth(t *testing.T) {
	t.Setenv("CF_API_EMAIL", "legacy@example.com")
	t.Setenv("CF_API_KEY", "legacy-key")

	sanitizeCloudflareAuthEnv(map[string]string{
		"CF_API_EMAIL": "legacy@example.com",
		"CF_API_KEY":   "legacy-key",
	})

	if value := os.Getenv("CF_API_EMAIL"); value != "legacy@example.com" {
		t.Fatalf("expected CF_API_EMAIL to remain set, got %q", value)
	}

	if value := os.Getenv("CF_API_KEY"); value != "legacy-key" {
		t.Fatalf("expected CF_API_KEY to remain set, got %q", value)
	}
}

func TestCloudflareTokenAuthConfigured(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{
			name: "dns token",
			env: map[string]string{
				"CF_DNS_API_TOKEN": "token-value",
			},
			want: true,
		},
		{
			name: "zone token file",
			env: map[string]string{
				"CLOUDFLARE_ZONE_API_TOKEN_FILE": "/run/secrets/cf-zone-token",
			},
			want: true,
		},
		{
			name: "legacy auth only",
			env: map[string]string{
				"CF_API_EMAIL": "legacy@example.com",
				"CF_API_KEY":   "legacy-key",
			},
			want: false,
		},
		{
			name: "empty token",
			env: map[string]string{
				"CF_DNS_API_TOKEN": "   ",
			},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cloudflareTokenAuthConfigured(tc.env)
			if got != tc.want {
				t.Fatalf("cloudflareTokenAuthConfigured() = %v, want %v", got, tc.want)
			}
		})
	}
}
