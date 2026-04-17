#!/bin/bash
# Quick start script for Security Monitor

set -e

echo "================================"
echo "Security Monitor - Quick Start"
echo "================================"
echo ""

# Create directories for persistence
echo "[1/4] Creating data directories..."
mkdir -p logs data

# Build Docker image
echo "[2/4] Building Docker image..."
docker-compose build

# Start the container
echo "[3/4] Starting container..."
docker-compose up -d

# Wait for service to be ready
echo "[4/4] Waiting for service to start..."
sleep 5

# Check if running
if docker-compose ps | grep -q "Up"; then
    echo ""
    echo "✓ Security Monitor is running!"
    echo ""
    echo "Web Dashboard: http://localhost:8080"
    echo ""
    echo "Useful commands:"
    echo "  docker-compose logs -f          # View logs"
    echo "  docker-compose ps               # Check status"
    echo "  docker-compose down             # Stop monitor"
    echo "  docker-compose restart          # Restart monitor"
    echo ""
else
    echo ""
    echo "✗ Failed to start. Check logs:"
    echo "  docker-compose logs"
    echo ""
    exit 1
fi
