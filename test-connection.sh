#!/bin/bash

# Test script for Unbound Exporter

echo "Testing Unbound Exporter Connection..."

# Check if Unbound is running
echo ""
echo "1. Checking Unbound service..."
if systemctl is-active --quiet unbound; then
    echo "OK: Unbound is running"
else
    echo "FAIL: Unbound is not running"
    echo "Start it with: sudo systemctl start unbound"
    exit 1
fi

# Check if socket exists
echo ""
echo "2. Checking Unbound socket..."
if [ -S /run/unbound.ctl ]; then
    echo "OK: Socket exists at /run/unbound.ctl"
    ls -la /run/unbound.ctl
else
    echo "FAIL: Socket not found at /run/unbound.ctl"
    echo "Check your Unbound configuration for control-interface"
    exit 1
fi

# Build the exporter if needed
echo ""
echo "3. Building exporter..."
if [ ! -f "unbound-exporter" ]; then
    echo "Building Go binary..."
    go build -o unbound-exporter exporter.go
    if [ $? -eq 0 ]; then
        echo "OK: Build successful"
    else
        echo "FAIL: Build failed"
        exit 1
    fi
else
    echo "OK: Binary already exists"
fi

# Test socket connection
echo ""
echo "4. Testing socket connection..."
timeout 5 ./unbound-exporter --socket-path=/run/unbound.ctl --log-level=debug &
EXPORTER_PID=$!
sleep 2

# Check if process is running
if kill -0 $EXPORTER_PID 2>/dev/null; then
    echo "OK: Exporter started successfully"

    # Test metrics endpoint
    echo ""
    echo "5. Testing metrics endpoint..."
    sleep 1
    METRICS=$(curl -s http://127.0.0.1:9167/metrics | head -10)
    if [ $? -eq 0 ] && [ ! -z "$METRICS" ]; then
        echo "OK: Metrics endpoint working"
        echo "Sample metrics:"
        echo "$METRICS"
    else
        echo "FAIL: Metrics endpoint failed"
    fi

    # Clean up
    kill $EXPORTER_PID 2>/dev/null
else
    echo "FAIL: Exporter failed to start"
    echo "Check logs above for errors"
fi

echo ""
echo "6. Next steps:"
echo "   ./unbound-exporter --help"
echo "   sudo cp unbound-exporter /usr/local/bin/"
echo "   sudo cp unbound-exporter.service /etc/systemd/system/"
echo "   sudo systemctl enable --now unbound-exporter"

echo ""
echo "Test complete."
