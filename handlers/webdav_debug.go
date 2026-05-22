//go:build debug || DEBUG

package handlers

import (
	"context"
	"fmt"

	"dwCloud/types"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type davDebugAdvisoryLock struct {
	ClassID int64 `db:"classid"`
	ObjID   int64 `db:"objid"`
}

func debugCheckDAVAncestorLocks(ctx context.Context, conn *sqlx.Conn, userID uuid.UUID, rows []types.DbFile) error {
	if len(rows) == 0 {
		return nil
	}

	var locks []davDebugAdvisoryLock
	if err := conn.SelectContext(ctx, &locks, `
		SELECT classid::bigint AS classid, objid::bigint AS objid
		FROM pg_locks
		WHERE pid = pg_backend_pid()
		  AND locktype = 'advisory'
		  AND granted
		  AND objsubid = 1
	`); err != nil {
		return fmt.Errorf("debug DAV ancestor lock check failed: %w", err)
	}

	held := make(map[int64]struct{}, len(locks))
	for _, lock := range locks {
		key := int64((uint64(uint32(lock.ClassID)) << 32) | uint64(uint32(lock.ObjID)))
		held[key] = struct{}{}
	}

	for _, row := range rows {
		key := davLockKey(userID, row.Path)
		if _, ok := held[key]; !ok {
			return fmt.Errorf("debug DAV lock check: row %q has no held advisory lock", row.Path)
		}
	}

	return nil
}
