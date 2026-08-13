#!/bin/bash

# ==============================================================================
# UNIVERSAL GIT COMPRESSION & SNAPSHOT AUTOMATION ENGINE
# ==============================================================================

# CONFIGURATION: Enter your GitHub details once right here
GH_USER="anthonymroso-star"
GH_TOKEN="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"

# Automatically grab the exact folder name where this script is executed
CURRENT_REPO=$(basename "$PWD")

# Display a user choices menu on the terminal screen
echo "=================================================="
echo "          UNIVERSAL GIT PORTFOLIO UTILITY         "
echo "=================================================="
echo "Target Repository: $CURRENT_REPO"
echo "--------------------------------------------------"
echo "Select your deployment execution path:"
echo "1) Standard Update Push (Regular commits)"
echo "2) Full History Wipe & Initial Reset (Force overwrite)"
echo "--------------------------------------------------"
read -p "Enter choice [1 or 2]: " USER_CHOICE

# Formulate the clear-text authentication target string wrapper safely
AUTH_URL="https://${GH_USER}:${GH_TOKEN}@github.com/${GH_USER}/${CURRENT_REPO}.git"

# Clean up any broken or old remote handles first to prevent conflict crashes
git remote remove origin 2>/dev/null

# Bind the fresh authenticated token URL straight to the default 'origin' name
git remote add origin "$AUTH_URL"

if [ "$USER_CHOICE" == "1" ]; then
    echo "[*] Initializing standard repository synchronization sweep..."
    
    # 1. Stage all modified local files for tracking
    git add .
    
    # 2. Lock the changes into your local history with a summary note
    git commit -m "docs: update local configurations and documentation"
    
    # 3. Push the fresh commits straight to the cloud repository
    git push origin main

elif [ "$USER_CHOICE" == "2" ]; then
    echo "[*] Warning: Commencing deep history purge and initial reset..."
    
    # 1a. Delete the local main branch reference pointer to wipe history logs
    git update-ref -d refs/heads/main
    
    # 2a. Re-stage all directory assets
    git add .
    
    # 3a. Seal a fresh, singular initial commit block
    git commit -m "Initial commit: Complete portfolio project documentation"
    
    # 4a. Forcefully launch the clean slate, completely overwriting the cloud
    git push origin main --force
else
    echo "[-] Invalid selection. Aborting execution loop."
    exit 1
fi

echo "[+] Playbook execution completed successfully!"
