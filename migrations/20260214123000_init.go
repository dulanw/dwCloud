package migrations

import (
	"context"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/migrate"
)

// A collection of migrations.
var Migrations = migrate.NewMigrations()

func init() {
	Migrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		if _, err := db.Exec(`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`); err != nil {
			return err
		}

		_, err := db.Exec(`
				CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
					username TEXT NOT NULL UNIQUE,
                    
				  	provider TEXT NOT NULL,
				 	subject  TEXT NOT NULL,
                    
                    role TEXT NOT NULL DEFAULT 'user',
                    
                    email TEXT,
					email_verified BOOLEAN NOT NULL DEFAULT false,
					display_name TEXT,
					avatar_url TEXT,
                    
                    timezone TEXT NOT NULL DEFAULT 'Europe/London',
                    language TEXT NOT NULL DEFAULT 'en_GB',
                    locale TEXT,
				
					created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
					last_login_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    
                    storage_dir TEXT NOT NULL,
                    quota_bytes BIGINT NOT NULL DEFAULT 1099511627776,
				
					UNIQUE (provider, subject)
                );
                
    			-- app passwords
				----------------------------------
				CREATE TABLE IF NOT EXISTS app_passwords (
					id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
					user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

					label TEXT NOT NULL,
					secret_hash TEXT NOT NULL,

					created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
					last_used_at TIMESTAMPTZ,
					revoked_at TIMESTAMPTZ,
					remote_wipe_at TIMESTAMPTZ,
					remote_wipe_completed_at TIMESTAMPTZ
				);

				CREATE INDEX IF NOT EXISTS idx_app_passwords_user_id
					ON app_passwords (user_id);

				CREATE INDEX IF NOT EXISTS idx_app_passwords_user_active
					ON app_passwords (user_id)
					WHERE revoked_at IS NULL;

				CREATE INDEX IF NOT EXISTS idx_app_passwords_remote_wipe
					ON app_passwords (remote_wipe_at)
					WHERE remote_wipe_at IS NOT NULL;

				CREATE INDEX IF NOT EXISTS idx_app_passwords_remote_wipe_pending
					ON app_passwords (remote_wipe_at)
					WHERE remote_wipe_at IS NOT NULL
					  AND remote_wipe_completed_at IS NULL;
					
				-- nextcloud login flow
				----------------------------------
				CREATE TABLE IF NOT EXISTS login_v2_sessions (
					id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
				    
				    user_agent TEXT NOT NULL,

					poll_token TEXT NOT NULL UNIQUE,
					flow_token TEXT NOT NULL UNIQUE,
				    
				    state_token TEXT UNIQUE,

					created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
					expires_at TIMESTAMPTZ NOT NULL,

					approved_at TIMESTAMPTZ,
				    -- consumed_at TIMESTAMPTZ,

					user_id UUID REFERENCES users(id) ON DELETE CASCADE

					-- login_name TEXT,
					-- app_password_plain TEXT,

					-- app_password_id UUID REFERENCES app_passwords(id) ON DELETE CASCADE
				);
            `)
		if err != nil {
			return err
		}

		// create a files table and a trigger function to create ocid, which is just padded_id + "oc" + 10 hex chars
		_, err = db.Exec(`
				CREATE TABLE IF NOT EXISTS files (
			  		id BIGSERIAL PRIMARY KEY,
				  	user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				  	path TEXT NOT NULL,
					is_dir BOOLEAN NOT NULL DEFAULT false,
					
					ocid TEXT NOT NULL UNIQUE,
					
					-- other metadata
					version BIGINT NOT NULL DEFAULT 1,
					size_bytes BIGINT NOT NULL DEFAULT 0,
					mtime TIMESTAMPTZ NOT NULL DEFAULT now(),
					content_sha1 TEXT,
					
					created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
					updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
					
					UNIQUE (user_id, path)
				);

				-- Trigger function to create ocid
				CREATE OR REPLACE FUNCTION dwcloud_set_ocid()
				RETURNS trigger
				LANGUAGE plpgsql
				AS $$
				BEGIN
					IF NEW.ocid IS NULL OR NEW.ocid = '' THEN
						-- 8-digit zero-padded id + "oc" + 10 base36 chars
						NEW.ocid :=
					  		lpad(NEW.id::text, 8, '0')
					  		|| 'oc'
					  		|| substr(encode(gen_random_bytes(8), 'hex'), 1, 10);
					END IF;
					RETURN NEW;
				END;
				$$;
				
				DROP TRIGGER IF EXISTS trg_files_set_ocid ON files;

				CREATE TRIGGER trg_files_set_ocid
				BEFORE INSERT ON files
				FOR EACH ROW
				EXECUTE FUNCTION dwcloud_set_ocid();

				-- properties table for files, webdav proppatch
				CREATE TABLE IF NOT EXISTS file_properties (
					user_id    UUID NOT NULL,
					path       TEXT NOT NULL,
					namespace  TEXT NOT NULL,
					local_name TEXT NOT NULL,
					value      TEXT NOT NULL,
					PRIMARY KEY (user_id, path, namespace, local_name),
					FOREIGN KEY (user_id, path) REFERENCES files (user_id, path) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
				);
			`)

		if err != nil {
			return err
		}

		//dav lock/unlock
		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS locks (
				token      TEXT PRIMARY KEY,
				user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				path       TEXT NOT NULL,
				depth      TEXT NOT NULL DEFAULT 'infinity',
				scope      TEXT NOT NULL DEFAULT 'exclusive',
				owner_xml  TEXT NOT NULL DEFAULT '',
				timeout_at TIMESTAMPTZ NOT NULL,
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
			);
			
			CREATE INDEX IF NOT EXISTS locks_user_path ON locks(user_id, path);
			CREATE INDEX IF NOT EXISTS locks_timeout ON locks(timeout_at);
		`)

		return err
	}, func(ctx context.Context, db *bun.DB) error {
		_, err := db.Exec(`
				DROP TRIGGER IF EXISTS trg_files_set_ocid ON files;
				DROP TABLE IF EXISTS locks;
				DROP TABLE IF EXISTS file_properties;
				DROP TABLE IF EXISTS files;
				DROP TABLE IF EXISTS login_v2_sessions;
				DROP TABLE IF EXISTS app_passwords;
				DROP TABLE IF EXISTS users;
				DROP FUNCTION IF EXISTS dwcloud_set_ocid();
			`)
		return err
	})
}
