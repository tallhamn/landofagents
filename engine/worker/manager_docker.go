package worker

import (
	"os"
	"os/exec"
	"strings"
)

// dockerClient abstracts docker compose lifecycle calls.
type dockerClient interface {
	ComposeUp(composePath string, env []string, services ...string) error
	ComposeDown(composePath string, env []string) error
	ServiceRunning(composePath string, env []string, service string) (bool, error)
}

type realDockerClient struct{}

func (realDockerClient) ComposeUp(composePath string, env []string, services ...string) error {
	args := []string{"compose", "-f", composePath, "up", "-d", "--build"}
	args = append(args, services...)
	cmd := exec.Command("docker", args...)
	cmd.Env = env
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (realDockerClient) ComposeDown(composePath string, env []string) error {
	cmd := exec.Command("docker", "compose", "-f", composePath, "down")
	cmd.Env = env
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (realDockerClient) ServiceRunning(composePath string, env []string, service string) (bool, error) {
	cmd := exec.Command("docker", "compose", "-f", composePath, "ps", "-q", service)
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			if strings.Contains(strings.ToLower(strings.TrimSpace(string(ee.Stderr))), "no such service") {
				return false, nil
			}
		}
		return false, err
	}
	return strings.TrimSpace(string(out)) != "", nil
}
