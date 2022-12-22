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
	ctx    context.Context
	cancel func()
	procs  map[string]*proc
	wd     string
	envs   []string
	wg     sync.WaitGroup
}

func New(ctx context.Context) *Visor {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(ctx)

	return &Visor{
		wd:     wd,
		ctx:    ctx,
		cancel: cancel,
		procs:  map[string]*proc{},
		envs:   os.Environ(),
	}
}

func (v *Visor) Run() (err error) {
	for _, p := range v.procs {
		if err = p.init(); err != nil {
			v.cancel()
			break
		}

		v.wg.Add(1)
		go p.start()
	}

	<-v.ctx.Done()
	v.wg.Wait()

	return err
}

func (v *Visor) Supervise(exe, wd, stderr, stdout, pid string, envs, args []string) error {
	exe, err := exec.LookPath(exe)
	if err != nil {
		return err
	}

	if !filepath.IsAbs(wd) {
		wd = filepath.Join(v.wd, wd)
	}

	if pid == "" {
		pid = filepath.Base(exe) + ".pid"
	}

	if !filepath.IsAbs(pid) {
		pid = filepath.Join(wd, pid)
	}

	if stderr == "" {
		stderr = filepath.Base(exe) + ".stderr"
	}

	if !filepath.IsAbs(stderr) {
		stderr = filepath.Join(wd, stderr)
	}

	if stdout == "" {
		stdout = filepath.Base(exe) + ".stdout"
	}

	if !filepath.IsAbs(stdout) {
		stdout = filepath.Join(wd, stdout)
	}

	v.procs[exe] = &proc{
		stderrPath: stderr,
		stdoutPath: stdout,
		pidPath:    pid,
		exe:        exe,
		ctx:        v.ctx,
		wd:         wd,
		wg:         &v.wg,
		envs:       append(envs, v.envs...),
		args:       args,
		id:         sandid.New(),
	}

	return nil
}

type status uint8

const (
	stopped status = iota
	running
	stoping
	failed
	exited
)

func (s status) String() string {
	switch s {
	case stopped:
		return "STOPPED"
	case running:
		return "RUNNING"
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
	ctx context.Context

	wg         *sync.WaitGroup
	stderrFile *os.File
	stdoutFile *os.File
	cmd        *exec.Cmd

	done chan struct{}

	exe        string
	pidPath    string
	stdoutPath string
	wd         string
	stderrPath string

	envs []string
	args []string

	mu sync.Mutex

	id sandid.SandID

	status status
}

func (p *proc) MarshalZerologObject(e *zerolog.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e.
		Str("id", p.id.String()).
		Str("exe", p.exe).
		Str("status", p.status.String()).
		Int("exit_code", p.cmd.ProcessState.ExitCode())
}

func (p *proc) setStatus(s status) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status = s
}

func (p *proc) init() (err error) {
	p.done = make(chan struct{})

	if p.stderrFile, err = os.OpenFile(p.stderrPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err != nil {
		return err
	}

	if p.stdoutFile, err = os.OpenFile(p.stdoutPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err != nil {
		return err
	}

	return err
}

func (p *proc) cleanup() {
	close(p.done)
	log.Debug().
		AnErr("stderr", p.stderrFile.Close()).
		AnErr("stdout", p.stdoutFile.Close()).
		AnErr("pid", os.Remove(p.pidPath)).
		Send()
}

func (p *proc) start() {
	defer func() {
		p.cleanup()
		p.wg.Done()
	}()

beginning:

	p.cmd = exec.CommandContext(p.ctx, p.exe, p.args...)
	p.cmd.Cancel = p.stop
	p.cmd.Dir = p.wd
	p.cmd.Env = p.envs

	p.cmd.Stderr = p.stderrFile
	p.cmd.Stdout = p.stdoutFile

	for err := p.cmd.Start(); err != nil; err = p.cmd.Start() {
		p.setStatus(failed)
		log.Error().Object("proc", p).Err(err).Send()

		select {
		case <-p.ctx.Done():
			return
		case <-time.After(3 * time.Second): // backoff
		}
	}

	p.setStatus(running)
	log.Info().Object("proc", p).Send()

	err := os.WriteFile(p.pidPath, []byte(strconv.Itoa(p.cmd.Process.Pid)), 0o600)
	if err != nil {
		log.Error().Object("proc", p).Err(err).Send()
	}

	err = p.cmd.Wait()
	if err != nil {
		if !p.cmd.ProcessState.Success() {
			p.setStatus(failed)
			log.Error().Object("proc", p).Err(err).Send()
		}
	}

	p.setStatus(exited)
	log.Info().Object("proc", p).Send()

	select {
	case <-p.ctx.Done():
	default:
		goto beginning // restart
	}
}

func (p *proc) stop() error {
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		log.Error().Object("proc", p).Err(err).Send()
		return p.cmd.Process.Kill()
	}

	select {
	case <-time.After(3 * time.Second):
		return p.cmd.Process.Kill()
	case <-p.done:
	}

	return nil
}
