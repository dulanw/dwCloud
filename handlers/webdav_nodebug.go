//go:build !debug && !DEBUG

package handlers

import (
	"context"

	"dwCloud/types"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

func debugCheckDAVAncestorLocks(context.Context, *sqlx.Conn, uuid.UUID, []types.DbFile) error {
	return nil
}
