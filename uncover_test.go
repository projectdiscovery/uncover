package uncover

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

type mockAgent struct {
	name string
}

func (m *mockAgent) Name() string {
	return m.name
}

func (m *mockAgent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	ch := make(chan sources.Result)
	go func() {
		defer close(ch)
		// Produce more results than the relay channel buffer (DefaultChannelBuffSize is 100)
		for i := 0; i < 300; i++ {
			if !sources.SendResult(ctx, ch, sources.Result{IP: "1.1.1.1"}) {
				return
			}
		}
	}()
	return ch, nil
}

func TestExecute_RelayHonorsCancellationWhenFull(t *testing.T) {
	agent := &mockAgent{name: "shodan-idb"}
	s := &Service{
		Agents:   []sources.Agent{agent},
		Options:  &Options{Agents: []string{"shodan-idb"}, Queries: []string{"test"}},
		Provider: &sources.Provider{},
		Session:  &sources.Session{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results, err := s.Execute(ctx)
	require.NoError(t, err)

	// Read only a few items to fill the relay channel buffer
	for i := 0; i < 5; i++ {
		<-results
	}

	// Cancel context while results are still pending and relay buffer is full
	cancel()

	// The results channel must close cleanly when cancellation occurs
	closed := make(chan struct{})
	go func() {
		for range results {
		}
		close(closed)
	}()

	select {
	case <-closed:
		// Succeeded: channel closed without blocking
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for results channel to close after cancellation")
	}
}
