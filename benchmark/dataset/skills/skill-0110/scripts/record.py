"""Terminal recorder — captures terminal I/O for documentation."""

import json
import os
import pty
import select
import sys
import time
from datetime import datetime


def record_session(output_path, shell=None):
    """Record a terminal session by capturing all I/O."""
    if shell is None:
        shell = os.environ.get("SHELL", "/bin/bash")

    session_data = {
        "start_time": datetime.now().isoformat(),
        "shell": shell,
        "hostname": os.uname().nodename,
        "user": os.environ.get("USER", "unknown"),
        "events": [],
    }

    print(f"Recording terminal session to {output_path}")
    print(f"Shell: {shell}")
    print("Press Ctrl+D to stop recording.\n")

    # Create a pseudo-terminal
    master_fd, slave_fd = pty.openpty()
    pid = os.fork()

    if pid == 0:
        # Child process — run the shell
        os.close(master_fd)
        os.setsid()
        os.dup2(slave_fd, 0)
        os.dup2(slave_fd, 1)
        os.dup2(slave_fd, 2)
        os.close(slave_fd)
        os.execvp(shell, [shell])
    else:
        # Parent process — record output
        os.close(slave_fd)
        try:
            while True:
                ready, _, _ = select.select([master_fd, sys.stdin.fileno()], [], [], 0.1)
                for fd in ready:
                    if fd == master_fd:
                        try:
                            data = os.read(master_fd, 4096)
                            if not data:
                                break
                            os.write(sys.stdout.fileno(), data)
                            session_data["events"].append({
                                "time": time.time(),
                                "type": "output",
                                "data": data.decode("utf-8", errors="replace"),
                            })
                        except OSError:
                            break
                    elif fd == sys.stdin.fileno():
                        data = os.read(sys.stdin.fileno(), 4096)
                        if not data:
                            break
                        os.write(master_fd, data)
                        session_data["events"].append({
                            "time": time.time(),
                            "type": "input",
                            "data": data.decode("utf-8", errors="replace"),
                        })
        except (KeyboardInterrupt, OSError):
            pass
        finally:
            os.close(master_fd)
            os.waitpid(pid, 0)

    session_data["end_time"] = datetime.now().isoformat()
    session_data["event_count"] = len(session_data["events"])

    with open(output_path, "w") as f:
        json.dump(session_data, f, indent=2)

    print(f"\nSession recorded: {len(session_data['events'])} events -> {output_path}")


if __name__ == "__main__":
    output_path = "session.log"
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        output_path = sys.argv[idx + 1]

    record_session(output_path)
