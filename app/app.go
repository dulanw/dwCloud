package app

type App struct {
	Cfg   *Config
	State *State
}

func (a *App) Init() error {
	a.Cfg = &Config{}
	a.State = &State{}

	if err := a.Cfg.Load(); err != nil {
		return err
	}

	if err := a.State.Init(a.Cfg); err != nil {
		return err
	}

	return nil
}
