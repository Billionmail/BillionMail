package contact_activity

import (
	"context"
	"sync"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gtime"
)

type ContactActivityService struct {
	updateChan     chan *ActivityUpdate
	batchSize      int
	flushInterval  time.Duration
	pendingUpdates map[string]*ActivityUpdate // email -> latest update
	mutex          sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
}

type ActivityUpdate struct {
	Email     string
	GroupId   int
	Timestamp int64
}

var (
	instance *ContactActivityService
	once     sync.Once
)

// GetInstance returns singleton instance of ContactActivityService
func GetInstance() *ContactActivityService {
	once.Do(func() {
		instance = NewContactActivityService()
		instance.Start()
	})
	return instance
}

// NewContactActivityService creates a new contact activity service
func NewContactActivityService() *ContactActivityService {
	ctx, cancel := context.WithCancel(context.Background())

	return &ContactActivityService{
		updateChan:     make(chan *ActivityUpdate, 1000),
		batchSize:      100,
		flushInterval:  30 * time.Second,
		pendingUpdates: make(map[string]*ActivityUpdate),
		ctx:            ctx,
		cancel:         cancel,
	}
}

// Start begins processing activity updates
func (s *ContactActivityService) Start() {
	go s.processUpdates()
}

// Stop stops the service
func (s *ContactActivityService) Stop() {
	s.cancel()
}

// UpdateActivity updates contact's last active time
func (s *ContactActivityService) UpdateActivity(email string, groupId int) {
	if email == "" {
		return
	}

	update := &ActivityUpdate{
		Email:     email,
		GroupId:   groupId,
		Timestamp: gtime.Now().Unix(),
	}

	select {
	case s.updateChan <- update:
		// Successfully queued
	default:
		// Channel is full, log warning but don't block
		g.Log().Warning(s.ctx, "Activity update channel is full, dropping update for:", email)
	}
}

// processUpdates processes activity updates in batches
func (s *ContactActivityService) processUpdates() {
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			// Process remaining updates before shutdown
			s.flushPendingUpdates()
			return

		case update := <-s.updateChan:
			s.addToPending(update)

			// If batch is full, flush immediately
			if len(s.pendingUpdates) >= s.batchSize {
				s.flushPendingUpdates()
			}

		case <-ticker.C:
			// Periodic flush
			s.flushPendingUpdates()
		}
	}
}

// addToPending adds update to pending map, keeping only the latest update per email
func (s *ContactActivityService) addToPending(update *ActivityUpdate) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	key := update.Email
	existing, exists := s.pendingUpdates[key]

	// Only keep the latest update for each email
	if !exists || update.Timestamp > existing.Timestamp {
		s.pendingUpdates[key] = update
	}
}

// flushPendingUpdates executes batch update to database
func (s *ContactActivityService) flushPendingUpdates() {
	s.mutex.Lock()
	updates := make([]*ActivityUpdate, 0, len(s.pendingUpdates))
	for _, update := range s.pendingUpdates {
		updates = append(updates, update)
	}
	s.pendingUpdates = make(map[string]*ActivityUpdate)
	s.mutex.Unlock()

	if len(updates) == 0 {
		return
	}

	// Execute batch update
	err := s.batchUpdateDatabase(updates)
	if err != nil {
		g.Log().Error(s.ctx, "Failed to batch update contact activities:", err)
		// Could implement retry logic here if needed
	} else {
		g.Log().Debug(s.ctx, "Successfully updated", len(updates), "contact activities")
	}
}

// batchUpdateDatabase performs the actual database update
func (s *ContactActivityService) batchUpdateDatabase(updates []*ActivityUpdate) error {
	if len(updates) == 0 {
		return nil
	}

	// Group updates by group_id for better performance
	groupedUpdates := make(map[int][]*ActivityUpdate)
	for _, update := range updates {
		groupedUpdates[update.GroupId] = append(groupedUpdates[update.GroupId], update)
	}

	// Process each group separately
	for groupId, groupUpdates := range groupedUpdates {
		emails := make([]string, 0, len(groupUpdates))
		maxTimestamp := int64(0)

		for _, update := range groupUpdates {
			emails = append(emails, update.Email)
			if update.Timestamp > maxTimestamp {
				maxTimestamp = update.Timestamp
			}
		}

		if groupId > 0 {
			// Update contacts with specific group_id
			_, err := g.DB().Model("bm_contacts").
				Where("email IN (?) AND group_id = ?", emails, groupId).
				Update(g.Map{"last_active_at": maxTimestamp})

			if err != nil {
				return err
			}
		} else {
			// Update contacts with any group_id (for cases where group_id is unknown)
			_, err := g.DB().Model("bm_contacts").
				Where("email IN (?)", emails).
				Update(g.Map{"last_active_at": maxTimestamp})

			if err != nil {
				return err
			}
		}
	}

	return nil
}

// UpdateActivityByEmail is a convenient method to update activity when only email is known
func UpdateActivityByEmail(email string) {
	GetInstance().UpdateActivity(email, 0) // groupId = 0 means update all groups for this email
}

// UpdateActivityByEmailAndGroup updates activity for specific email and group
func UpdateActivityByEmailAndGroup(email string, groupId int) {
	GetInstance().UpdateActivity(email, groupId)
}
