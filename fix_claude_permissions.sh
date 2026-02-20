#!/bin/bash

echo "Fixing Claude CLI permissions..."

# Fix npm global directory permissions
echo "Fixing npm global directory permissions..."
sudo chown -R $USER:$(id -gn) /usr/local/lib/node_modules
sudo chown -R $USER:$(id -gn) /usr/local/bin

# Verify the fix
echo ""
echo "Verifying permissions..."
ls -la /usr/local/lib/node_modules/@anthropic-ai/

echo ""
echo "Done! You can now run 'claude doctor' to verify the fix."
echo ""
echo "Alternatively, you can migrate to the local installation by running:"
echo "claude migrate-installer"