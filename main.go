package main

import (
	"context"
	stdlog "log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"

	"github.com/bokunodev/normalvisor/visor"
)

func init() {
	stdlog.SetFlags(stdlog.Lmsgprefix | stdlog.Lshortfile | stdlog.Ltime | stdlog.Ldate | stdlog.LUTC)
	stdlog.SetPrefix("[STD] ")
	stdlog.SetOutput(os.Stdout)

	log.Logger = log.
		With().
		Timestamp().
		Logger().
		Level(zerolog.ErrorLevel).
		Output(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			NoColor:    true,
			TimeFormat: time.RFC3339,
		})
}

func main() {
	app := cli.NewApp()
	app.Name = "normalvisor"
	app.Usage = "A process supervisor written in Go with minimal dependency"
	app.Flags = []cli.Flag{
		&cli.PathFlag{
			Name:     "config",
			Usage:    "path to normalvisor config file",
			EnvVars:  []string{"CONFIG"},
			Required: true,
		},
		&cli.BoolFlag{
			Name:    "debug",
			Usage:   "enable debug log",
			EnvVars: []string{"DEBUG"},
		},
	}

	app.Action = func(ctx *cli.Context) error {
		if ctx.Bool("debug") {
			log.Logger = log.
				With().
				Timestamp().
				Caller().
				Logger().
				Level(zerolog.DebugLevel).
				Output(zerolog.ConsoleWriter{
					Out:        os.Stderr,
					NoColor:    false,
					TimeFormat: time.RFC3339,
				})
		}

		v := visor.New(ctx.Context)

		err := v.Supervise("/home/boku/Public/normalvisor/daemon/daemon", "", "", "", "", nil, nil)
		if err != nil {
			return err
		}

		return v.Run()
	}

	ctx, cancel := signal.NotifyContext(context.TODO(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Debug().Err(app.RunContext(ctx, os.Args)).Send()
}
