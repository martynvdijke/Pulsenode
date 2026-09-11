package npm

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"synapse/internal/db"
	"synapse/internal/logging"
)

// InstanceClient pairs a NPM instance ID with its Client.
type InstanceClient struct {
	InstanceID int
	Client     *Client
}

// Registry provides access to NPM instances with JWT token caching.
type Registry struct {
	mu      sync.Mutex
	db      *db.DB
	clients map[int64]*Client
}

func NewRegistry(database *db.DB) *Registry {
	return &Registry{
		db:      database,
		clients: make(map[int64]*Client),
	}
}

// All returns an InstanceClient for each enabled NPM instance.
// Clients are cached with their JWT tokens; instances that fail to
// authenticate are skipped with a logged warning.
func (r *Registry) All() ([]InstanceClient, error) {
	instances, err := r.db.GetEnabledNPMInstances()
	if err != nil {
		return nil, err
	}
	result := make([]InstanceClient, 0, len(instances))
	for _, inst := range instances {
		c, err := r.getOrCreate(int(inst.ID), inst.URL, inst.Username, inst.Password)
		if err != nil {
			logging.LogWarn("npm", "Failed to connect to NPM instance, skipping",
				slog.String("instance", inst.Name),
				slog.String("error", err.Error()),
			)
			continue
		}
		result = append(result, InstanceClient{InstanceID: int(inst.ID), Client: c})
	}
	return result, nil
}

// Get returns a Client for the given NPM instance ID.
func (r *Registry) Get(id int) (*Client, error) {
	inst, err := r.db.GetNPMInstance(int64(id))
	if inst == nil || err != nil {
		return nil, fmt.Errorf("npm instance %d not found", id)
	}
	return r.getOrCreate(int(inst.ID), inst.URL, inst.Username, inst.Password)
}

// Invalidate drops the cached client for an instance, forcing re-login
// on the next access. Call after credential changes.
func (r *Registry) Invalidate(id int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.clients, int64(id))
}

// getOrCreate returns a cached client if its token is still valid, or
// creates and logs in a new one.
func (r *Registry) getOrCreate(id int, url, user, pass string) (*Client, error) {
	r.mu.Lock()
	cached, exists := r.clients[int64(id)]
	r.mu.Unlock()

	if exists && cached.token != "" && time.Now().Before(cached.tokenExpiry) {
		return cached, nil
	}

	c := NewClient(url, user, pass)
	if err := c.Login(context.Background()); err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.clients[int64(id)] = c
	r.mu.Unlock()
	return c, nil
}
