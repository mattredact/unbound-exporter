#!/bin/bash

# Test script for Unbound Exporter on Pi 4

echo "🔍 Testing Unbound Exporter Connection..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Unbound is running
echo -e "\n${YELLOW}1. Checking Unbound service...${NC}"
if systemctl is-active --quiet unbound; then
    echo -e "${GREEN}✅ Unbound is running${NC}"
else
    echo -e "${RED}❌ Unbound is not running${NC}"
    echo "Start it with: sudo systemctl start unbound"
    exit 1
fi

# Check if socket exists
echo -e "\n${YELLOW}2. Checking Unbound socket...${NC}"
if [ -S /run/unbound.ctl ]; then
    echo -e "${GREEN}✅ Socket exists at /run/unbound.ctl${NC}"
    ls -la /run/unbound.ctl
else
    echo -e "${RED}❌ Socket not found at /run/unbound.ctl${NC}"
    echo "Check your Unbound configuration for control-interface"
    exit 1
fi

# Build the exporter if needed
echo -e "\n${YELLOW}3. Building exporter...${NC}"
if [ ! -f "unbound-exporter" ]; then
    echo "Building Go binary..."
    go build -o unbound-exporter exporter-go1.19.go
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Build successful${NC}"
    else
        echo -e "${RED}❌ Build failed${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✅ Binary already exists${NC}"
fi

# Test socket connection
echo -e "\n${YELLOW}4. Testing socket connection...${NC}"
timeout 5 ./unbound-exporter --socket-path=/run/unbound.ctl --log-level=debug &
EXPORTER_PID=$!
sleep 2

# Check if process is running
if kill -0 $EXPORTER_PID 2>/dev/null; then
    echo -e "${GREEN}✅ Exporter started successfully${NC}"
    
    # Test metrics endpoint
    echo -e "\n${YELLOW}5. Testing metrics endpoint...${NC}"
    sleep 1
    METRICS=$(curl -s http://127.0.0.1:9167/metrics | head -10)
    if [ $? -eq 0 ] && [ ! -z "$METRICS" ]; then
        echo -e "${GREEN}✅ Metrics endpoint working${NC}"
        echo "Sample metrics:"
        echo "$METRICS"
    else
        echo -e "${RED}❌ Metrics endpoint failed${NC}"
    fi
    
    # Clean up
    kill $EXPORTER_PID 2>/dev/null
else
    echo -e "${RED}❌ Exporter failed to start${NC}"
    echo "Check logs above for errors"
fi

echo -e "\n${YELLOW}6. Connection summary:${NC}"
echo "If all tests passed, you can:"
echo "1. Run: ./unbound-exporter --help"
echo "2. Install service: sudo cp unbound-exporter /usr/local/bin/"
echo "3. Configure Prometheus with prometheus.yml"
echo "4. Import unbound-dashboard.json into Grafana"

echo -e "\n${GREEN}🎉 Test complete!${NC}"