#!/bin/bash

# Install mise
curl https://mise.run | sh

# Add to bash config
echo 'eval "$(~/.local/bin/mise activate bash)"' >> ~/.bashrc

# Reload shell
source ~/.bashrc

# Install the latest stable Python globally
mise use -g python@latest

# Install the latest uv globally
mise use -g uv@latest