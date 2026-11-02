package sources

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProviderZoomEyeHostFromConfig(t *testing.T) {
	provider := &Provider{
		ZoomEye: []string{"test-token:zoomeye.org"},
	}
	keys := provider.GetKeys()
	require.Equal(t, "test-token", keys.ZoomEyeToken)
	require.Equal(t, "zoomeye.org", keys.ZoomEyeHost)
}

func TestProviderZoomEyeHostFromEnv(t *testing.T) {
	t.Setenv("ZOOMEYE_API_KEY", "env-zoomeye-token")
	t.Setenv("ZOOMEYE_HOST", "api.zoomeye.org")

	provider := &Provider{}
	provider.LoadProviderKeysFromEnv()

	require.Len(t, provider.ZoomEye, 1)
	require.Equal(t, "env-zoomeye-token:api.zoomeye.org", provider.ZoomEye[0])

	keys := provider.GetKeys()
	require.Equal(t, "env-zoomeye-token", keys.ZoomEyeToken)
	require.Equal(t, "api.zoomeye.org", keys.ZoomEyeHost)
}

func TestProviderZoomEyeHostEnvFallbackWithConfigToken(t *testing.T) {
	t.Setenv("ZOOMEYE_HOST", "zoomeye.org")

	provider := &Provider{
		ZoomEye: []string{"config-only-token"},
	}
	keys := provider.GetKeys()
	require.Equal(t, "config-only-token", keys.ZoomEyeToken)
	require.Equal(t, "zoomeye.org", keys.ZoomEyeHost)
}
