package visor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/aofei/sandid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Visor struct {
	wg    *sync.WaitGroup
	ctx   context.Context
	procs map[sandid.SandID]proc
	wd    string
	env   []string
}

func New(ctx context.Context) (*Visor, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	v := &Visor{
		ctx:   ctx,
		procs: make(map[sandid.SandID]proc),
		wd:    wd,
		wg:    &sync.WaitGroup{},
		env:   os.Environ(),
	}

	return v, nil
}

func (v *Visor) Run() error {
	for _, proc := range v.procs {
		v.wg.Add(1)
		go proc.start()
	}

	<-v.ctx.Done()
	v.wg.Wait()

	return nil
}

func (v *Visor) Supervise(cmd string, wd, stderr, stdout, pid string, clean bool, envs, args []string) {
	if cmd == "" {
		panic("argument `cmd` cannot be empty")
	}

	if !filepath.IsAbs(wd) {
		wd = filepath.Join(v.wd, wd)
	}

	if pid == "" {
		pid = filepath.Base(cmd) + ".pid"
	}

	if !filepath.IsAbs(pid) {
		pid = filepath.Join(wd, pid)
	}

	if stderr == "" {
		stderr = filepath.Base(cmd) + ".stderr"
	}

	if !filepath.IsAbs(stderr) {
		stderr = filepath.Join(wd, stderr)
	}

	if stdout == "" {
		stdout = filepath.Base(cmd) + ".stdout"
	}

	if !filepath.IsAbs(stdout) {
		stdout = filepath.Join(wd, stdout)
	}

	p := proc{
		visor:      v,
		stderrPath: stderr,
		stdoutPath: stdout,
		pidFile:    pid,
		id:         sandid.New(),
	}

	p.cmd = exec.CommandContext(v.ctx, cmd, args...)
	if p.cmd.Err != nil {
		panic(p.cmd.Err)
	}
	p.cmd.Cancel = p.stop
	p.cmd.Dir = wd
	if !clean {
		p.cmd.Env = append([]string(nil), v.env...)
	}
	p.cmd.Env = append([]string(nil), envs...)

	v.procs[p.id] = p
}

type procStatus uint8

const (
	stopped procStatus = iota
	started
	stoping
	failed
	exited
	killed
)

func (s procStatus) String() string {
	switch s {
	case stopped:
		return "STOPPED"
	case started:
		return "STARTED"
	case stoping:
		return "STOPING"
	case failed:
		return "FAILED"
	case exited:
		return "EXITED"
	}

	return "UNKNOWN"
}

type proc struct {
	cmd        *exec.Cmd
	visor      *Visor
	stderrFile *os.File
	stdoutFile *os.File
	done       chan struct{}
	stderrPath string
	stdoutPath string
	pidFile    string
	id         sandid.SandID
	status     procStatus
}

func (p *proc) MarshalZerologObject(e *zerolog.Event) {
	e.Str("cmd", p.cmd.Path).
		Str("status", p.status.String()).
		Str("id", p.id.String())
}

func (p *proc) start() {
	defer p.visor.wg.Done()

	p.done = make(chan struct{})
	defer close(p.done)

	defer func() {
		log.Debug().
			AnErr("stderr", p.stderrFile.Close()).
			AnErr("stderr", p.stdoutFile.Close()).
			AnErr("pid", os.Remove(p.pidFile)).
			Object("proc", p).
			Send()
	}()

	var err error
	if p.stderrFile, err = os.OpenFile(p.stderrPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err != nil {
		p.status = failed
		log.Error().Object("proc", p).Err(err).Send()
		return
	}

	if p.stdoutFile, err = os.OpenFile(p.stdoutPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err != nil {
		p.status = failed
		log.Error().Object("proc", p).Err(err).Send()
		return
	}

	p.cmd.Stderr = p.stderrFile
	p.cmd.Stdout = p.stdoutFile

restart:

	for err = p.cmd.Start(); err != nil; err = p.cmd.Start() {
		p.status = failed
		log.Error().Object("proc", p).Err(err).Send()

		select {
		case <-p.visor.ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}

	p.status = started
	log.Info().Object("proc", p).Send()

	if err = os.WriteFile(p.pidFile, []byte(strconv.Itoa(p.cmd.Process.Pid)), 0o600); err != nil {
		log.Error().Object("proc", p).Err(err).Send()
	}

	log.Info().Object("proc", p).Msg("waiting ...")
	if waitErr := p.cmd.Wait(); waitErr != nil {
		log.Error().Object("proc", p).Err(waitErr).Send()
	}

	p.status = exited
	log.Info().Object("proc", p).Send()

	select {
	case <-p.visor.ctx.Done():
	default:
		goto restart
	}
}

func (p *proc) stop() error {
	p.status = stoping

	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		log.Error().Object("proc", p).Err(err).Send()
		if killErr := p.cmd.Process.Kill(); killErr != nil {
			p.status = killed
			log.Error().Object("proc", p).Err(killErr).Send()
		}
		return err
	}

	select {
	case <-time.After(3 * time.Second):
		if err := p.cmd.Process.Kill(); err != nil {
			p.status = killed
			log.Error().Object("proc", p).Err(err).Send()
		}
	case <-p.done:
	}

	return nil
}
