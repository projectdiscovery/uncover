package sources

import (
	"context"
	"fmt"
	"strings"
)

// AccountBalance represents credit and quota details for a search engine provider
type AccountBalance struct {
	Engine    string            `json:"engine"`
	Remaining int64             `json:"remaining,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
	Message   string            `json:"message,omitempty"`
}

// BalanceAccount is an optional interface implemented by Agents that support balance/credit checking
type BalanceAccount interface {
	Balance(ctx context.Context, session *Session) (*AccountBalance, error)
}

// String returns a human readable representation of the account balance
func (b *AccountBalance) String() string {
	if b.Message != "" {
		return b.Message
	}
	if len(b.Details) == 0 {
		return fmt.Sprintf("Remaining: %d", b.Remaining)
	}
	var parts []string
	for k, v := range b.Details {
		parts = append(parts, fmt.Sprintf("%s: %s", k, v))
	}
	return strings.Join(parts, " | ")
}
