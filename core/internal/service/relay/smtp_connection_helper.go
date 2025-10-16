package relay

import (
	"billionmail-core/internal/model/entity"
	"billionmail-core/internal/service/mail_service"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcache"
	"strings"
	"sync"
	"time"
)

// Cache instance for storing SMTP connection states.
var smtpStatusCache = gcache.New()

// Cache expiration time (5 minutes).
const smtpStatusCacheExpire = 5 * time.Minute

// SMTP status cache key format.
const smtpStatusCacheKeyFormat = "smtp_status:%s:%s:%s"

// SmtpConnectionStatus Represents the SMTP connection status.
type SmtpConnectionStatus struct {
	Status   bool   `json:"status"`   // Whether the connection was successful.
	Msg      string `json:"msg"`      // Status description.
	LastTime int64  `json:"lastTime"` // Last test time (Unix timestamp).
}

// SmtpConnectionTestResult Complete SMTP connection test result.
type SmtpConnectionTestResult struct {
	Success         bool   // Whether the connection test was successful.
	Message         string // Connection test result message.
	ServerInfo      string // Server information (server welcome message).
	TlsStatus       string // TLS status (enabled and type).
	AuthStatus      string // Authentication status (success, failure, or unauthenticated).
	ConnectionTime  int64  // Time to establish the connection (milliseconds).
	SupportedAuth   string // Authentication methods supported by the server.
	RecommendConfig bool   // Whether this configuration is recommended.
}

// TestSmtpConnection Complete SMTP connection testing method.
func TestSmtpConnection(host, port, user, password string) *SmtpConnectionTestResult {
	result := &SmtpConnectionTestResult{
		Success:         false,
		Message:         "",
		ServerInfo:      "",
		TlsStatus:       "",
		AuthStatus:      "",
		ConnectionTime:  0,
		SupportedAuth:   "",
		RecommendConfig: false,
	}

	startTime := time.Now()

	// Validate basic required parameters
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	user = strings.TrimSpace(user)
	password = strings.TrimSpace(password)

	if host == "" || port == "" {
		result.Message = public.Lang("SMTP host and port are required.")
		return result
	}

	// Validate authentication parameters - if user is provided, password must also be provided
	if user != "" && password == "" {
		result.Message = public.Lang("Password is required when username is provided.")
		return result
	}

	sender := mail_service.NewEmailSender()
	sender.Host = host
	sender.Port = port
	sender.Email = "test_connection@billionmail.com" // Temporary email for testing

	// Handle authentication based on whether credentials are provided
	isAuthRequired := user != "" && password != ""
	if isAuthRequired {
		sender.UserName = user
		sender.Password = password
	} else {
		// For no-auth relays, ensure UserName and Password are empty
		// This should signal the mail service not to attempt SASL authentication
		sender.UserName = ""
		sender.Password = ""
	}

	defer sender.Close()

	// Attempt to establish a connection
	err := sender.Connect()

	if err != nil {
		// Check if this is an authentication-related error for a no-auth relay
		if !isAuthRequired {
			authErrorPatterns := []string{
				"authentication not enabled",
				"AUTH not enabled",
				"503 5.5.1",
				"AUTH command not supported",
			}

			errorMsg := strings.ToLower(err.Error())
			isAuthError := false
			for _, pattern := range authErrorPatterns {
				if strings.Contains(errorMsg, strings.ToLower(pattern)) {
					isAuthError = true
					break
				}
			}

			if isAuthError {
				// This is expected for no-auth relays, treat as success
				result.Success = true
				result.Message = "SMTP connection test succeeded (no authentication required)."
				result.AuthStatus = "No authentication (server has authentication disabled)."
				result.ConnectionTime = time.Since(startTime).Milliseconds()
				if result.ConnectionTime < 1000 {
					result.RecommendConfig = true
				}
				return result
			}
		}

		result.Message = public.Lang("SMTP connection failed: {}", err.Error())
		return result
	}

	// Calculate connection time
	connectionTime := time.Since(startTime).Milliseconds()
	result.ConnectionTime = connectionTime

	// Set success status
	result.Success = true
	result.Message = "SMTP connection test succeeded."

	// Set authentication status based on whether credentials were used
	if isAuthRequired {
		result.AuthStatus = "Authentication succeeded."
	} else {
		result.AuthStatus = "No authentication (direct connection)."
	}

	// Provide configuration recommendations based on connection time and setup
	if connectionTime < 1000 {
		result.RecommendConfig = true
	}

	return result
}

// UpdateRelayStatus Periodically updates the SMTP connection status of all relay configurations.
func UpdateRelayStatus(ctx context.Context) {
	g.Log().Debug(ctx, "Starting periodic update of SMTP connection statuses...")

	// Query all active relay configurations.
	var relayConfigs []*entity.BmRelay
	err := g.DB().Model("bm_relay").Where("active", 1).Scan(&relayConfigs)
	if err != nil {
		//g.Log().Error(ctx, "Failed to query relay configurations:", err)
		return
	}

	if len(relayConfigs) == 0 {
		//g.Log().Debug(ctx, "No active relay configurations found, skipping SMTP status update.")
		return
	}

	//g.Log().Debugf(ctx, "Found %d active relay configurations, starting to check SMTP connection statuses.", len(relayConfigs))

	// Use WaitGroup to wait for all checks to complete.
	var wg sync.WaitGroup
	// Limit concurrency to avoid establishing too many connections simultaneously.
	semaphore := make(chan struct{}, 5)

	for _, config := range relayConfigs {
		wg.Add(1)

		// Use goroutines for concurrent checks.
		go func(cfg *entity.BmRelay) {
			defer wg.Done()

			// Acquire semaphore to limit concurrency.
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Decrypt password.
			password, err := DecryptPassword1(ctx, cfg.AuthPassword)
			if err != nil {
				g.Log().Warningf(ctx, "Failed to decrypt password for relay configuration ID=%d: %v", cfg.Id, err)
				return
			}

			// Perform SMTP connection check.
			status := checkSmtpConnectionImpl(cfg.RelayHost, cfg.RelayPort, cfg.AuthUser, password)

			// Generate cache key.
			cacheKey := fmt.Sprintf(smtpStatusCacheKeyFormat, cfg.RelayHost, cfg.RelayPort, cfg.AuthUser)

			// Store result in cache.
			err = smtpStatusCache.Set(ctx, cacheKey, status, smtpStatusCacheExpire)
			if err != nil {
				g.Log().Warningf(ctx, "Failed to cache SMTP status for relay configuration ID=%d: %v", cfg.Id, err)
			}

			g.Log().Debugf(ctx, "Updated SMTP status for relay configuration (ID=%d, Host=%s:%s): %v - %s",
				cfg.Id, cfg.RelayHost, cfg.RelayPort, status.Status, status.Msg)
		}(config)
	}

	// Wait for all checks to complete.
	wg.Wait()
	g.Log().Debug(ctx, "All SMTP connection statuses have been updated.")
}

// CheckSmtpConnection
func CheckSmtpConnection(ctx context.Context, host, port, user, password string) *SmtpConnectionStatus {

	cacheKey := fmt.Sprintf(smtpStatusCacheKeyFormat, host, port, user)

	if v, err := smtpStatusCache.Get(ctx, cacheKey); err == nil && v != nil {
		var status SmtpConnectionStatus
		if err := v.Scan(&status); err == nil {
			return &status
		}
	}

	return &SmtpConnectionStatus{
		Status:   false,
		Msg:      "Status unknown (under check)",
		LastTime: time.Now().Unix(),
	}
}

// checkSmtpConnectionImpl Actual implementation of SMTP connection checking.
func checkSmtpConnectionImpl(host, port, user, password string) *SmtpConnectionStatus {
	status := &SmtpConnectionStatus{
		Status:   false,
		Msg:      "Not checked",
		LastTime: time.Now().Unix(),
	}

	ret := TestSmtpConnection(host, port, user, password)

	if !ret.Success {
		status.Msg = ret.Message
		return status
	}

	// All checks passed
	status.Status = true
	status.Msg = public.Lang("Connection normal")
	return status
}

func DecryptPassword1(ctx context.Context, encryptedHex string) (string, error) {

	password, err := DecryptPassword(ctx, encryptedHex)
	if password == "" {
		password = "********"
	}
	return password, err
}
