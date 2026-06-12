package app

import "context"

type App struct {
	Cfg   *Config
	State *State
}

func (a *App) Init(ctx context.Context) error {
	a.Cfg = &Config{}
	a.State = &State{}

	if err := a.Cfg.Load(ctx); err != nil {
		return err
	}

	if err := a.State.Init(ctx, a.Cfg); err != nil {
		return err
	}

	return nil
}
