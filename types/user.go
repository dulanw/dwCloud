package types

import (
	"time"

	"github.com/google/uuid"
)

type DbUser struct {
	ID            uuid.UUID `db:"id" json:"id"`
	Username      string    `db:"username" json:"username"`
	Provider      string    `db:"provider" json:"provider"`
	Subject       string    `db:"subject" json:"subject"`
	Role          string    `db:"role" json:"role"`
	Email         *string   `db:"email" json:"email"`
	EmailVerified bool      `db:"email_verified" json:"email_verified"`
	DisplayName   *string   `db:"display_name" json:"display_name"`
	AvatarURL     *string   `db:"avatar_url" json:"avatar_url"`
	Timezone      string    `db:"timezone" json:"timezone"`
	Language      string    `db:"language" json:"language"`
	Locale        *string   `db:"locale" json:"locale"`
	CreatedAt     time.Time `db:"created_at" json:"created_at"`
	LastLoginAt   time.Time `db:"last_login_at" json:"last_login_at"`
	StorageDir    string    `db:"storage_dir" json:"storage_dir"`
	QuotaBytes    int64     `db:"quota_bytes" json:"quota_bytes"`
}

type AdminUserView struct {
	User       DbUser `json:"user"`
	UsageBytes int64  `json:"usage_bytes"`
}

type DbAppPassword struct {
	ID                    uuid.UUID  `db:"id" json:"id"`
	UserID                uuid.UUID  `db:"user_id" json:"user_id"`
	Label                 string     `db:"label" json:"label"`
	SecretHash            string     `db:"secret_hash" json:"secret_hash"`
	CreatedAt             time.Time  `db:"created_at" json:"created_at"`
	LastUsedAt            *time.Time `db:"last_used_at" json:"last_used_at"`
	RevokedAt             *time.Time `db:"revoked_at" json:"revoked_at"`
	RemoteWipeAt          *time.Time `db:"remote_wipe_at" json:"remote_wipe_at"`
	RemoteWipeCompletedAt *time.Time `db:"remote_wipe_completed_at" json:"remote_wipe_completed_at"`
}

type DbLoginV2Session struct {
	ID         uuid.UUID  `db:"id" json:"id"`
	UserAgent  string     `db:"user_agent" json:"user_agent"`
	PollToken  string     `db:"poll_token" json:"poll_token"`
	FlowToken  string     `db:"flow_token" json:"flow_token"`
	StateToken *string    `db:"state_token" json:"state_token"`
	CreatedAt  time.Time  `db:"created_at" json:"created_at"`
	ExpiresAt  time.Time  `db:"expires_at" json:"expires_at"`
	ApprovedAt *time.Time `db:"approved_at" json:"approved_at"`
	UserID     *uuid.UUID `db:"user_id" json:"user_id"`
}

type DbFile struct {
	ID          int64     `db:"id" json:"id"`
	UserID      uuid.UUID `db:"user_id" json:"user_id"`
	Path        string    `db:"path" json:"path"`
	IsDir       bool      `db:"is_dir" json:"is_dir"`
	OCID        string    `db:"ocid" json:"ocid"`
	Version     int64     `db:"version" json:"version"`
	SizeBytes   int64     `db:"size_bytes" json:"size_bytes"`
	Mtime       time.Time `db:"mtime" json:"mtime"`
	ContentSHA1 *string   `db:"content_sha1" json:"content_sha1"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}

type DbFileProperty struct {
	UserID    uuid.UUID `db:"user_id" json:"user_id"`
	Path      string    `db:"path" json:"path"`
	Namespace string    `db:"namespace" json:"namespace"`
	LocalName string    `db:"local_name" json:"local_name"`
	Value     string    `db:"value" json:"value"`
}
