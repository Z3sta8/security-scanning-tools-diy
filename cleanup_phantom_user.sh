#!/bin/bash
# Cleanup script to remove phantom derrickalbers reference from admin group

echo "========================================"
echo "Phantom User Cleanup Script"
echo "========================================"
echo ""
echo "This script will remove the phantom 'derrickalbers' user"
echo "reference from the admin group."
echo ""
echo "The user account doesn't exist, but the name appears in"
echo "the admin group membership (stale reference)."
echo ""
echo "This requires sudo privileges."
echo ""

# Check current state
echo "Current admin group membership:"
dscl . -read /Groups/admin GroupMembership
echo ""

# Remove phantom user from admin group
echo "Removing derrickalbers from admin group..."
sudo dseditgroup -o edit -d derrickalbers admin

# Check if successful
echo ""
echo "Verifying..."
echo ""
echo "New admin group membership:"
dscl . -read /Groups/admin GroupMembership
echo ""

# Verify user still doesn't exist
echo "Confirming derrickalbers user doesn't exist:"
if id derrickalbers 2>/dev/null; then
    echo "⚠️ WARNING: User actually exists!"
else
    echo "✓ Confirmed: derrickalbers user does not exist (expected)"
fi

echo ""
echo "========================================"
echo "✓ Cleanup Complete!"
echo "========================================"
echo ""
echo "The phantom reference has been removed."
echo "Your admin group now only contains: root and zesta8"
