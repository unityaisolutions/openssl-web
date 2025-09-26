#!/bin/bash

# Script to update emsdk submodule and install/activate the latest version

set -e  # Exit on any error

echo "Updating emsdk submodule..."
git submodule update --remote emsdk

echo "Installing latest Emscripten..."
cd emsdk
./emsdk install latest

echo "Activating latest Emscripten..."
./emsdk activate latest

echo "Sourcing emsdk environment..."
source ./emsdk_env.sh

echo "Emscripten installation complete. The environment variables are now set for this shell session."

# Automatically add sourcing to .bashrc for new terminals
BASHRC="$HOME/.bashrc"
EMSOURCING="source emsdk/emsdk_env.sh"
if ! grep -q "$EMSOURCING" "$BASHRC"; then
    echo "" >> "$BASHRC"
    echo "# Emscripten environment (added by install-emsdk.sh)" >> "$BASHRC"
    echo "$EMSOURCING" >> "$BASHRC"
    echo "Added emsdk environment sourcing to $BASHRC for automatic activation in new terminals."
else
    echo "Emscripten environment sourcing already present in $BASHRC."
fi