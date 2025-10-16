package database_initialization

import (
	"billionmail-core/internal/model"
	"billionmail-core/internal/service/public"
	"billionmail-core/internal/service/rbac"
	"context"
	"github.com/gogf/gf/v2/frame/g"
	"time"
)

// Initialize RBAC related table structures
func init() {
	registerHandler(func() {
		rbacSQLList := []string{
			// Account table
			`CREATE TABLE IF NOT EXISTS account (
				account_id SERIAL PRIMARY KEY,
				username VARCHAR(64) NOT NULL UNIQUE,
				password VARCHAR(255) NOT NULL,
				email VARCHAR(255) NOT NULL,
				status INT NOT NULL DEFAULT 1, -- 1: enabled, 0: disabled
				language VARCHAR(50) NOT NULL DEFAULT 'en',
				last_login_time INT NOT NULL DEFAULT 0,
				create_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
				update_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
			)`,

			// Role table
			`CREATE TABLE IF NOT EXISTS role (
				role_id SERIAL PRIMARY KEY,
				role_name VARCHAR(64) NOT NULL UNIQUE,
				description TEXT,
				status INT NOT NULL DEFAULT 1, -- 1: enabled, 0: disabled
				create_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
				update_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
			)`,

			// Permission table
			`CREATE TABLE IF NOT EXISTS permission (
				permission_id SERIAL PRIMARY KEY,
				permission_name VARCHAR(64) NOT NULL UNIQUE,
				description TEXT,
				module VARCHAR(64) NOT NULL, -- Module name
				action VARCHAR(64) NOT NULL, -- Action type: create, read, update, delete
				resource VARCHAR(64) NOT NULL, -- Resource type
				status INT NOT NULL DEFAULT 1, -- 1: enabled, 0: disabled
				create_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
				update_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
				UNIQUE(module, action, resource)
			)`,

			// Account-Role mapping table
			`CREATE TABLE IF NOT EXISTS account_role (
				id SERIAL PRIMARY KEY,
				account_id INT NOT NULL,
				role_id INT NOT NULL,
				create_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
				UNIQUE(account_id, role_id),
				FOREIGN KEY (account_id) REFERENCES account(account_id) ON DELETE CASCADE,
				FOREIGN KEY (role_id) REFERENCES role(role_id) ON DELETE CASCADE
			)`,

			// Role-Permission mapping table
			`CREATE TABLE IF NOT EXISTS role_permission (
				id SERIAL PRIMARY KEY,
				role_id INT NOT NULL,
				permission_id INT NOT NULL,
				create_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
				UNIQUE(role_id, permission_id),
				FOREIGN KEY (role_id) REFERENCES role(role_id) ON DELETE CASCADE,
				FOREIGN KEY (permission_id) REFERENCES permission(permission_id) ON DELETE CASCADE
			)`,
		}

		// Execute SQL statements
		for _, sql := range rbacSQLList {
			_, err := g.DB().Exec(context.Background(), sql)
			if err != nil {
				g.Log().Error(context.Background(), "Failed to execute RBAC SQL:", err, sql)
				return
			}
		}

		// Get Admin Username and Password from docker environment variables
		adminUsername, err := public.DockerEnv("ADMIN_USERNAME")

		if err != nil {
			g.Log().Error(context.Background(), "Failed to get admin username", err)
			return
		}

		adminPassword, err := public.DockerEnv("ADMIN_PASSWORD")
		if err != nil {
			g.Log().Error(context.Background(), "Failed to get admin password", err)
			return
		}

		// Create admin role if it doesn't exist
		adminRoleId := int64(0)
		adminRoleIdVal, err := g.DB().Model("role").Where("role_name = ?", "admin").Value("role_id")

		if err != nil {
			g.Log().Error(context.Background(), "Failed to check admin role:", err)
			return
		}

		if adminRoleIdVal == nil {
			adminRoleId, err = rbac.Role().Create(context.Background(), "admin", "System administrator with full access", 1)

			if err != nil {
				g.Log().Error(context.Background(), "Failed to create admin role:", err)
				return
			}
		} else {
			adminRoleId = adminRoleIdVal.Int64()
		}

		// Create admin account if it doesn't exist
		adminId := int64(0)

		// Find admin account from account_role table
		adminIdVal, err := g.DB().Model("account_role").Where("role_id = ?", adminRoleId).Value("account_id")

		if err != nil || adminIdVal == nil {
			// Find admin account from account table
			adminIdVal, err = g.DB().Model("account").Where("username = ?", adminUsername).Value("account_id")
		}

		if err != nil {
			g.Log().Error(context.Background(), "Failed to check admin role:", err)
			return
		}

		if adminIdVal == nil {
			adminId, err = rbac.Account().Create(context.Background(), &model.Account{
				Username: adminUsername,
				Password: adminPassword,
				Email:    "",
				Status:   1,
			})

			if err != nil {
				g.Log().Error(context.Background(), "Failed to create admin account:", err)
				return
			}
		} else {
			adminId = adminIdVal.Int64()
			// Update admin account username and password
			passwd, err := rbac.Account().GeneratePasswordHash(adminPassword)

			if err != nil {
				g.Log().Error(context.Background(), "Failed to hash admin password:", err)
				return
			}

			_, err = g.DB().Model("account").Data(g.Map{
				"username":    adminUsername,
				"password":    passwd,
				"update_time": time.Now().Unix(),
			}).Where("account_id = ?", adminId).Update()

			if err != nil {
				g.Log().Error(context.Background(), "Failed to update admin account:", err)
				return
			}
		}

		// Assign admin role to admin account
		_, _ = g.DB().Model("account_role").InsertIgnore(g.Map{
			"account_id": adminId,
			"role_id":    adminRoleId,
		})

		// Generate default API Token
		var api_token string
		if err = public.OptionsMgrInstance.GetOption(context.Background(), "API_TOKEN", &api_token); err != nil || api_token == "" {
			api_token, _, err = rbac.JWT().GenerateApiToken(adminId, adminUsername, []string{"admin"})
			if err == nil {
				if err = public.OptionsMgrInstance.SetOption(context.Background(), "API_TOKEN", api_token); err != nil {

				}
			}
		}

		g.Log().Info(context.Background(), "RBAC tables initialized successfully")
	})
}
