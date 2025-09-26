#!/bin/bash

# Script to deploy the WebOpenSSL demo to Vercel
# Prerequisites: npm installed, Vercel account

set -e  # Exit on any error

echo "Deploying WebOpenSSL demo to Vercel..."

# Install Vercel CLI if not present
if ! command -v vercel &> /dev/null; then
    echo "Installing Vercel CLI..."
    npm install -g vercel
fi

# Build the library if not already built
if [ ! -f "lib/webopenssl.min.js" ]; then
    echo "Building the library..."
    npm run build
else
    echo "Library already built, skipping build step."
fi

# Create vercel-build directory and copy necessary files
echo "Preparing vercel-build directory..."
rm -rf vercel-build
mkdir vercel-build
cp -r src vercel-build/
cp -r lib vercel-build/
cp -r demo vercel-build/

# Move index.html from demo to root of vercel-build
mv vercel-build/demo/index.html vercel-build/index.html

# Fix script path in index.html (change ../lib/ to lib/)
sed -i 's|\.\./lib/webopenssl\.min\.js|lib/webopenssl.min.js|g' vercel-build/index.html

# Login to Vercel if not already logged in
if ! vercel whoami &> /dev/null; then
    echo "Logging in to Vercel..."
    vercel login
fi

# Link to Vercel project
echo "Linking to Vercel project..."
cd vercel-build
vercel link

# Deploy the vercel-build directory
echo "Deploying to Vercel..."
vercel --prod

echo "Deployment complete! Check the URL provided by Vercel."