#!/bin/bash
set -e

echo "Ensuring all required dependencies are installed..."

if [ -f /etc/debian_version ]; then
    echo "Detected Debian/Ubuntu system."
    sudo apt-get update
    # Install LaTeX for Patent PDF
    sudo apt-get install -y texlive-latex-base texlive-fonts-recommended texlive-latex-extra make
    # Install Pandoc for Whitepaper PDF
    sudo apt-get install -y pandoc
    # Install Python venv and pip for PyTorch orchestration
    sudo apt-get install -y python3-venv python3-pip
    # Install eBPF/C toolchain for hardware compilation
    sudo apt-get install -y clang llvm libbpf-dev linux-headers-generic linux-libc-dev
elif [ -f /etc/redhat-release ]; then
    echo "Detected RedHat/CentOS system."
    sudo dnf install -y texlive make pandoc python3 python3-pip clang llvm libbpf-devel kernel-headers kernel-devel
elif [ "$(uname)" == "Darwin" ]; then
    echo "Detected macOS."
    if ! command -v brew &> /dev/null; then
        echo "Homebrew not found. Please install Homebrew to proceed."
        exit 1
    fi
    brew install --cask mactex-no-gui
    brew install make pandoc python3 llvm
else
    echo "Unsupported operating system. Please install dependencies manually."
    exit 1
fi

echo "All dependencies installed successfully!"
