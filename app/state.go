package app

import (
	"context"
	"database/sql"
	"dwCloud/migrations"
	"fmt"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/migrate"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
)

type State struct {
	Db       *sqlx.DB
	Previews *PreviewService
}

func (s *State) Init(cfg *Config) error {
	dsn := cfg.GetDSN()

	sqlxDb, err := sqlx.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	s.Db = sqlxDb

	sqlDb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	bunDb := bun.NewDB(sqlDb, pgdialect.New())

	migrator := migrate.NewMigrator(bunDb, migrations.Migrations)
	ctx := context.Background()

	if err := migrator.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialise migrations: %w", err)
	}

	//if err := migrator.Lock(ctx); err != nil {
	//	slog.Error("failed to lock migrations", "error", err)
	//	os.Exit(1)
	//}
	//defer func(migrator *migrate.Migrator, ctx context.Context) {
	//	err := migrator.Unlock(ctx)
	//	if err != nil {
	//		fmt.Println("failed to unlock migrations", "error", err)
	//	}
	//}(migrator, ctx)

	if _, err := migrator.Migrate(ctx); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	previews, err := NewPreviewService(cfg, sqlxDb)
	if err != nil {
		return fmt.Errorf("failed to initialise preview service: %w", err)
	}
	s.Previews = previews
	s.Previews.Start(ctx)

	//err := migrator.Unlock(ctx)
	//if err != nil {
	//	slog.Error("failed to unlock migrations", "error", err)
	//	return
	//}

	return nil
}
