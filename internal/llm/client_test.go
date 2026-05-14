package llm

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockProvider is a test provider.
type mockProvider struct {
	name      string
	model     string
	available bool
	response  *Response
	err       error
}

func (m *mockProvider) Name() string  { return m.name }
func (m *mockProvider) Model() string { return m.model }
func (m *mockProvider) Available() bool { return m.available }
func (m *mockProvider) Complete(ctx context.Context, req *Request) (*Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	resp := *m.response
	resp.Provider = m.name
	resp.Model = m.model
	return &resp, nil
}

func TestClient_Complete_FirstAvailable(t *testing.T) {
	p1 := &mockProvider{
		name: "provider1", model: "model1", available: true,
		response: &Response{Content: "hello from p1", InputTokens: 10, OutputTokens: 5, Latency: time.Millisecond},
	}
	p2 := &mockProvider{
		name: "provider2", model: "model2", available: true,
		response: &Response{Content: "hello from p2"},
	}

	client, err := NewClient(p1, p2)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Complete(context.Background(), &Request{
		Messages: []Message{{Role: RoleUser, Content: "test"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Provider != "provider1" {
		t.Errorf("expected provider1, got %s", resp.Provider)
	}
	if resp.Content != "hello from p1" {
		t.Errorf("unexpected content: %s", resp.Content)
	}
}

func TestClient_Complete_Failover(t *testing.T) {
	p1 := &mockProvider{
		name: "provider1", model: "model1", available: true,
		err: errors.New("provider1 down"),
	}
	p2 := &mockProvider{
		name: "provider2", model: "model2", available: true,
		response: &Response{Content: "failover to p2"},
	}

	client, _ := NewClient(p1, p2)
	resp, err := client.Complete(context.Background(), &Request{
		Messages: []Message{{Role: RoleUser, Content: "test"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Provider != "provider2" {
		t.Errorf("expected failover to provider2, got %s", resp.Provider)
	}
}

func TestClient_Complete_SkipUnavailable(t *testing.T) {
	p1 := &mockProvider{
		name: "provider1", model: "model1", available: false,
		response: &Response{Content: "should not reach"},
	}
	p2 := &mockProvider{
		name: "provider2", model: "model2", available: true,
		response: &Response{Content: "from available"},
	}

	client, _ := NewClient(p1, p2)
	resp, err := client.Complete(context.Background(), &Request{
		Messages: []Message{{Role: RoleUser, Content: "test"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Provider != "provider2" {
		t.Errorf("expected provider2 (skip unavailable p1), got %s", resp.Provider)
	}
}

func TestClient_Complete_AllFailed(t *testing.T) {
	p1 := &mockProvider{name: "p1", model: "m1", available: true, err: errors.New("fail")}
	p2 := &mockProvider{name: "p2", model: "m2", available: true, err: errors.New("fail")}

	client, _ := NewClient(p1, p2)
	_, err := client.Complete(context.Background(), &Request{
		Messages: []Message{{Role: RoleUser, Content: "test"}},
	})
	if !errors.Is(err, ErrAllFailed) {
		t.Errorf("expected ErrAllFailed, got %v", err)
	}
}

func TestClient_KillSwitch(t *testing.T) {
	p1 := &mockProvider{
		name: "p1", model: "m1", available: true,
		response: &Response{Content: "should not reach"},
	}

	client, _ := NewClient(p1)
	client.ActivateKillSwitch()

	_, err := client.Complete(context.Background(), &Request{
		Messages: []Message{{Role: RoleUser, Content: "test"}},
	})
	if !errors.Is(err, ErrKillSwitch) {
		t.Errorf("expected ErrKillSwitch, got %v", err)
	}
}

func TestClient_SentinelDetection(t *testing.T) {
	sentinel := "550e8400-e29b-41d4-a716-446655440000"
	p1 := &mockProvider{
		name: "p1", model: "m1", available: true,
		response: &Response{Content: "Here is your answer " + sentinel + " done"},
	}

	client, _ := NewClient(p1)
	resp, err := client.Complete(context.Background(), &Request{
		Messages:     []Message{{Role: RoleUser, Content: "test"}},
		SentinelUUID: sentinel,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.SentinelLeaked {
		t.Error("expected SentinelLeaked=true when UUID appears in output")
	}
}

func TestClient_SentinelNotLeaked(t *testing.T) {
	p1 := &mockProvider{
		name: "p1", model: "m1", available: true,
		response: &Response{Content: "Normal response without any UUID"},
	}

	client, _ := NewClient(p1)
	resp, err := client.Complete(context.Background(), &Request{
		Messages:     []Message{{Role: RoleUser, Content: "test"}},
		SentinelUUID: "550e8400-e29b-41d4-a716-446655440000",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.SentinelLeaked {
		t.Error("expected SentinelLeaked=false when UUID is not in output")
	}
}

func TestNewClient_NoProviders(t *testing.T) {
	_, err := NewClient()
	if !errors.Is(err, ErrNoProviders) {
		t.Errorf("expected ErrNoProviders, got %v", err)
	}
}
