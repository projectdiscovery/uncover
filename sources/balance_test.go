package sources

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccountBalance_String(t *testing.T) {
	// Case 1: Custom message set
	b1 := &AccountBalance{
		Engine:  "shodan",
		Message: "Query Credits: 100 | Scan Credits: 50",
	}
	require.Equal(t, "Query Credits: 100 | Scan Credits: 50", b1.String())

	// Case 2: Details set without message
	b2 := &AccountBalance{
		Engine: "netlas",
		Details: map[string]string{
			"Coins": "50",
		},
	}
	require.Equal(t, "Coins: 50", b2.String())

	// Case 3: Only Remaining set
	b3 := &AccountBalance{
		Engine:    "custom",
		Remaining: 42,
	}
	require.Equal(t, "Remaining: 42", b3.String())
}

func TestKeys_HasKeysFor(t *testing.T) {
	keys := Keys{}
	require.False(t, keys.HasKeysFor("shodan"))
	require.False(t, keys.HasKeysFor("censys"))
	require.False(t, keys.HasKeysFor("unknown"))

	keys.Shodan = "test-shodan-key"
	require.True(t, keys.HasKeysFor("shodan"))

	keys.CensysToken = "token"
	require.False(t, keys.HasKeysFor("censys")) // Needs both token and org id
	keys.CensysOrgId = "org"
	require.True(t, keys.HasKeysFor("censys"))

	keys.FofaKey = "fofa-key"
	require.True(t, keys.HasKeysFor("fofa"))

	keys.HunterToken = "hunter-token"
	require.True(t, keys.HasKeysFor("hunter"))

	keys.QuakeToken = "quake-token"
	require.True(t, keys.HasKeysFor("quake"))

	keys.ZoomEyeToken = "zoomeye-token"
	require.True(t, keys.HasKeysFor("zoomeye"))

	keys.NetlasToken = "netlas-token"
	require.True(t, keys.HasKeysFor("netlas"))

	keys.CriminalIPToken = "criminalip-token"
	require.True(t, keys.HasKeysFor("criminalip"))

	require.False(t, keys.HasKeysFor("google"))
}
