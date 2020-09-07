package opcua_test_infra

import (
	"fmt"
	"github.com/gopcua/opcua"
	"github.com/pkg/errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Server runs a python test server.
type Server struct {
	// Path is the path to the Python server.
	Path string

	// Endpoint is the endpoint address which will be set
	// after the server has started.
	Endpoint string

	// Opts contains the client options required to connect to the server.
	// They are valid after the server has been started.
	Opts []opcua.Option

	cmd  *exec.Cmd
	Port uint
}

// NewServer creates a test server and starts it. The function
// panics if the server cannot be started.
func NewServer(path string, opts ...opcua.Option) *Server {
	port, err := freePort()
	if err != nil {
		panic(err)
	}
	s := &Server{
		Path:     path,
		Endpoint: fmt.Sprintf("opc.tcp://localhost:%d/opc", port),
		Opts:     opts,
		Port:     port,
	}
	if err := s.Run(); err != nil {
		panic(err)
	}
	return s
}

func (s *Server) Run() error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	path := filepath.Join(wd, s.Path)

	py, err := exec.LookPath("python3")
	if err != nil {
		// fallback to python and hope it still points to a python3 version.
		// the Windows python3 installer doesn't seem to create a `python3.exe`
		py, err = exec.LookPath("python")
		if err != nil {
			return errors.Errorf("unable to find Python executable")
		}
	}

	s.cmd = exec.Command(py, path, s.Endpoint)
	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr
	if err := s.cmd.Start(); err != nil {
		return err
	}

	// wait until endpoint is available
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.Port))
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		c.Close()
		return nil
	}
	return errors.Errorf("timeout")
}

func (s *Server) Close() error {
	if s.cmd == nil {
		return errors.Errorf("not running")
	}
	go func() { s.cmd.Process.Kill() }()
	return s.cmd.Wait()
}

func freePort() (uint, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return uint(l.Addr().(*net.TCPAddr).Port), nil
}
