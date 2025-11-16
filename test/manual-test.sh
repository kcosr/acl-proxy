#!/bin/bash

# Manual test script for ACL Proxy
# This script starts the proxy and tests various URLs

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CONFIG_FILE="${ACL_PROXY_CONFIG:-config/test-config.json}"
HTTP_PORT=18881
HTTPS_PORT=18889
PROXY_HOST="127.0.0.1"

echo -e "${YELLOW}ACL Proxy Test Suite${NC}"
echo "===================="
echo ""

# Build the project
echo -e "${YELLOW}Building project...${NC}"
npm run build

# Start the proxy in the background
echo -e "${YELLOW}Starting proxy with config: ${CONFIG_FILE}${NC}"
ACL_PROXY_CONFIG="${CONFIG_FILE}" node dist/index.js &
PROXY_PID=$!

# Wait for proxy to start
echo "Waiting for proxy to start..."
sleep 2

# Function to test a URL
test_url() {
    local url=$1
    local expected_status=$2
    local description=$3

    echo -n "Testing: ${description}... "

    status=$(curl -k -s -o /dev/null -w "%{http_code}" \
        --proxy "http://${PROXY_HOST}:${HTTP_PORT}" \
        "${url}" || echo "000")

    if [ "$status" = "$expected_status" ]; then
        echo -e "${GREEN}✓ PASS${NC} (HTTP ${status})"
        return 0
    else
        echo -e "${RED}✗ FAIL${NC} (Expected: ${expected_status}, Got: ${status})"
        return 1
    fi
}

# Function to test transparent HTTPS
test_transparent_https() {
    local host=$1
    local expected_status=$2
    local description=$3

    echo -n "Testing (Transparent HTTPS): ${description}... "

    status=$(curl -k -s -o /dev/null -w "%{http_code}" \
        -H "Host: ${host}" \
        "https://${PROXY_HOST}:${HTTPS_PORT}/" || echo "000")

    if [ "$status" = "$expected_status" ]; then
        echo -e "${GREEN}✓ PASS${NC} (HTTP ${status})"
        return 0
    else
        echo -e "${RED}✗ FAIL${NC} (Expected: ${expected_status}, Got: ${status})"
        return 1
    fi
}

# Track results
passed=0
failed=0

# Run tests
echo ""
echo -e "${YELLOW}Running HTTP Proxy Tests${NC}"
echo "------------------------"

if test_url "https://www.google.com/" "200" "Allowed URL (www.google.com)"; then
    ((passed++))
else
    ((failed++))
fi

if test_url "https://example.com/test" "200" "Allowed URL with path (example.com)"; then
    ((passed++))
else
    ((failed++))
fi

if test_url "https://httpbin.org/get" "200" "Allowed URL (httpbin.org)"; then
    ((passed++))
else
    ((failed++))
fi

if test_url "https://blocked.com/anything" "403" "Explicitly denied URL"; then
    ((passed++))
else
    ((failed++))
fi

if test_url "https://random-blocked-site.com/" "403" "Not in allow list (default deny)"; then
    ((passed++))
else
    ((failed++))
fi

if test_url "https://subdomain.allowed.test/path" "200" "Wildcard subdomain match"; then
    ((passed++))
else
    ((failed++))
fi

echo ""
echo -e "${YELLOW}Running Transparent HTTPS Tests${NC}"
echo "--------------------------------"

if test_transparent_https "www.google.com" "200" "Allowed host"; then
    ((passed++))
else
    ((failed++))
fi

if test_transparent_https "blocked.com" "403" "Blocked host"; then
    ((passed++))
else
    ((failed++))
fi

# Stop the proxy
echo ""
echo -e "${YELLOW}Stopping proxy (PID: ${PROXY_PID})...${NC}"
kill $PROXY_PID 2>/dev/null || true
wait $PROXY_PID 2>/dev/null || true

# Print results
echo ""
echo "===================="
echo -e "${YELLOW}Test Results${NC}"
echo "===================="
echo -e "${GREEN}Passed: ${passed}${NC}"
echo -e "${RED}Failed: ${failed}${NC}"
echo ""

if [ $failed -eq 0 ]; then
    echo -e "${GREEN}All tests passed! ✓${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed! ✗${NC}"
    exit 1
fi
