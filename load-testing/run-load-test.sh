#!/bin/bash

# CyberShield-IronCore Load Testing Script
# Enterprise-grade performance validation for 1M RPS capability
# Target: $1B acquisition readiness validation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
LOAD_TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$LOAD_TEST_DIR")"
RESULTS_DIR="$LOAD_TEST_DIR/results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
TEST_NAME="cybershield_load_test_$TIMESTAMP"

# Create results directory
mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}🚀 CyberShield-IronCore Load Testing Suite${NC}"
echo -e "${BLUE}============================================${NC}"
echo -e "${YELLOW}Target: 1M requests/second capability validation${NC}"
echo -e "${YELLOW}Enterprise-grade performance testing${NC}"
echo ""

# Check prerequisites
check_prerequisites() {
    echo -e "${BLUE}🔍 Checking prerequisites...${NC}"
    
    # Check if Artillery is installed
    if ! command -v artillery &> /dev/null; then
        echo -e "${RED}❌ Artillery not found. Installing...${NC}"
        npm install -g artillery@latest
    else
        echo -e "${GREEN}✅ Artillery found: $(artillery version)${NC}"
    fi
    
    # Check if Node.js is available
    if ! command -v node &> /dev/null; then
        echo -e "${RED}❌ Node.js not found. Please install Node.js${NC}"
        exit 1
    else
        echo -e "${GREEN}✅ Node.js found: $(node --version)${NC}"
    fi
    
    # Check if backend is running
    echo -e "${BLUE}🔍 Checking backend availability...${NC}"
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Backend is running and accessible${NC}"
    else
        echo -e "${YELLOW}⚠️  Backend not accessible at localhost:8000${NC}"
        echo -e "${YELLOW}   Starting backend services...${NC}"
        start_backend
    fi
    
    echo ""
}

# Start backend services
start_backend() {
    echo -e "${BLUE}🚀 Starting CyberShield backend services...${NC}"
    
    # Start backend in background
    cd "$PROJECT_ROOT/backend"
    
    # Install dependencies if needed
    if [ ! -d "venv" ]; then
        echo -e "${YELLOW}📦 Setting up Python virtual environment...${NC}"
        python3 -m venv venv
        source venv/bin/activate
        pip install -r requirements.txt
    else
        source venv/bin/activate
    fi
    
    # Start FastAPI server
    echo -e "${BLUE}🌐 Starting FastAPI server...${NC}"
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4 &
    BACKEND_PID=$!
    
    # Wait for backend to be ready
    echo -e "${YELLOW}⏳ Waiting for backend to be ready...${NC}"
    for i in {1..30}; do
        if curl -s http://localhost:8000/health > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Backend is ready!${NC}"
            break
        fi
        sleep 2
    done
    
    cd "$LOAD_TEST_DIR"
}

# System resource monitoring
start_monitoring() {
    echo -e "${BLUE}📊 Starting system monitoring...${NC}"
    
    # Create monitoring script
    cat > "$RESULTS_DIR/monitor_resources.sh" << 'EOF'
#!/bin/bash
RESULTS_DIR="$1"
TIMESTAMP="$2"

while true; do
    {
        echo "$(date '+%Y-%m-%d %H:%M:%S')"
        echo "CPU: $(top -l 1 | grep "CPU usage" | awk '{print $3}' | sed 's/[^0-9.]//g')%"
        echo "Memory: $(top -l 1 | grep "PhysMem" | awk '{print $2}' | sed 's/[^0-9.]//g')MB used"
        echo "Network: $(netstat -I en0 | tail -1 | awk '{print "In:", $7, "Out:", $10}')"
        echo "Load: $(uptime | awk -F'load averages:' '{print $2}')"
        echo "Connections: $(netstat -an | grep :8000 | wc -l)"
        echo "---"
    } >> "$RESULTS_DIR/system_metrics_$TIMESTAMP.log"
    sleep 5
done
EOF
    
    chmod +x "$RESULTS_DIR/monitor_resources.sh"
    "$RESULTS_DIR/monitor_resources.sh" "$RESULTS_DIR" "$TIMESTAMP" &
    MONITOR_PID=$!
    
    echo -e "${GREEN}✅ Monitoring started (PID: $MONITOR_PID)${NC}"
}

# Run load test phases
run_load_test() {
    echo -e "${BLUE}🔧 Preparing load test configuration...${NC}"
    
    # Copy configuration files
    cp "$LOAD_TEST_DIR/artillery.yml" "$RESULTS_DIR/artillery_$TIMESTAMP.yml"
    cp "$LOAD_TEST_DIR/data-generator.js" "$RESULTS_DIR/data-generator_$TIMESTAMP.js"
    
    echo -e "${BLUE}🚀 Starting load test phases...${NC}"
    echo -e "${YELLOW}This will run through multiple phases:${NC}"
    echo -e "${YELLOW}  1. Warm-up (100 RPS for 1 minute)${NC}"
    echo -e "${YELLOW}  2. Ramp-up (1K to 10K RPS over 5 minutes)${NC}"
    echo -e "${YELLOW}  3. Sustained (50K RPS for 10 minutes)${NC}"
    echo -e "${YELLOW}  4. Peak (100K to 500K RPS over 5 minutes)${NC}"
    echo -e "${YELLOW}  5. Ultimate (1M RPS for 3 minutes)${NC}"
    echo -e "${YELLOW}  6. Cool-down (1K RPS for 2 minutes)${NC}"
    echo ""
    
    # Run the load test
    artillery run \
        --output "$RESULTS_DIR/artillery_results_$TIMESTAMP.json" \
        "$RESULTS_DIR/artillery_$TIMESTAMP.yml" \
        2>&1 | tee "$RESULTS_DIR/artillery_output_$TIMESTAMP.log"
    
    # Generate HTML report
    echo -e "${BLUE}📊 Generating performance report...${NC}"
    artillery report \
        --output "$RESULTS_DIR/artillery_report_$TIMESTAMP.html" \
        "$RESULTS_DIR/artillery_results_$TIMESTAMP.json"
    
    echo -e "${GREEN}✅ Load test completed!${NC}"
}

# Analyze results
analyze_results() {
    echo -e "${BLUE}📈 Analyzing load test results...${NC}"
    
    # Create analysis script
    cat > "$RESULTS_DIR/analyze_results.js" << 'EOF'
const fs = require('fs');
const path = require('path');

function analyzeResults(resultsFile) {
    if (!fs.existsSync(resultsFile)) {
        console.log('❌ Results file not found:', resultsFile);
        return;
    }
    
    const results = JSON.parse(fs.readFileSync(resultsFile, 'utf8'));
    
    console.log('\n🎯 CYBERSHIELD LOAD TEST ANALYSIS');
    console.log('==================================');
    
    // Overall statistics
    if (results.aggregate) {
        const stats = results.aggregate;
        console.log('\n📊 OVERALL PERFORMANCE:');
        console.log(`Total requests: ${stats.counters['http.requests'] || 0}`);
        console.log(`Successful responses: ${stats.counters['http.codes.200'] || 0}`);
        console.log(`Failed requests: ${stats.counters['http.codes.500'] || 0}`);
        console.log(`Success rate: ${((stats.counters['http.codes.200'] || 0) / (stats.counters['http.requests'] || 1) * 100).toFixed(2)}%`);
        
        if (stats.histograms && stats.histograms['http.response_time']) {
            const rt = stats.histograms['http.response_time'];
            console.log('\n⚡ RESPONSE TIMES:');
            console.log(`Average: ${rt.mean?.toFixed(2) || 'N/A'}ms`);
            console.log(`Median (p50): ${rt.median?.toFixed(2) || 'N/A'}ms`);
            console.log(`95th percentile: ${rt.p95?.toFixed(2) || 'N/A'}ms`);
            console.log(`99th percentile: ${rt.p99?.toFixed(2) || 'N/A'}ms`);
            console.log(`Max: ${rt.max?.toFixed(2) || 'N/A'}ms`);
        }
        
        if (stats.rates) {
            console.log('\n🚀 THROUGHPUT:');
            console.log(`Requests per second: ${stats.rates['http.request_rate']?.toFixed(2) || 'N/A'}`);
        }
    }
    
    // Performance targets validation
    console.log('\n🎯 ENTERPRISE TARGETS VALIDATION:');
    
    const targets = {
        'p95_response_time': { threshold: 100, unit: 'ms', description: '95th percentile response time' },
        'p99_response_time': { threshold: 500, unit: 'ms', description: '99th percentile response time' },
        'success_rate': { threshold: 95, unit: '%', description: 'Success rate' },
        'max_rps': { threshold: 1000000, unit: 'RPS', description: 'Peak requests per second' }
    };
    
    const p95 = results.aggregate?.histograms?.['http.response_time']?.p95 || 0;
    const p99 = results.aggregate?.histograms?.['http.response_time']?.p99 || 0;
    const successRate = ((results.aggregate?.counters?.['http.codes.200'] || 0) / 
                        (results.aggregate?.counters?.['http.requests'] || 1)) * 100;
    const maxRps = results.aggregate?.rates?.['http.request_rate'] || 0;
    
    const results_check = [
        { name: 'p95_response_time', value: p95, passed: p95 <= targets.p95_response_time.threshold },
        { name: 'p99_response_time', value: p99, passed: p99 <= targets.p99_response_time.threshold },
        { name: 'success_rate', value: successRate, passed: successRate >= targets.success_rate.threshold },
        { name: 'max_rps', value: maxRps, passed: maxRps >= targets.max_rps.threshold }
    ];
    
    results_check.forEach(check => {
        const status = check.passed ? '✅ PASS' : '❌ FAIL';
        const target = targets[check.name];
        console.log(`${status} ${target.description}: ${check.value.toFixed(2)}${target.unit} (target: ${target.threshold}${target.unit})`);
    });
    
    const overallPass = results_check.every(check => check.passed);
    console.log(`\n🏆 OVERALL RESULT: ${overallPass ? '✅ ENTERPRISE READY' : '❌ NEEDS OPTIMIZATION'}`);
    
    if (overallPass) {
        console.log('\n🎉 CyberShield-IronCore meets enterprise performance requirements!');
        console.log('🚀 Ready for $1B acquisition target scaling!');
    } else {
        console.log('\n⚠️  Performance optimization required for enterprise deployment.');
        console.log('💡 Consider: scaling infrastructure, optimizing code, caching strategies.');
    }
}

// Run analysis
const resultsFile = process.argv[2];
if (resultsFile) {
    analyzeResults(resultsFile);
} else {
    console.log('Usage: node analyze_results.js <results.json>');
}
EOF
    
    # Run analysis
    node "$RESULTS_DIR/analyze_results.js" "$RESULTS_DIR/artillery_results_$TIMESTAMP.json"
}

# Generate summary report
generate_summary() {
    echo -e "\n${BLUE}📋 Generating test summary...${NC}"
    
    SUMMARY_FILE="$RESULTS_DIR/load_test_summary_$TIMESTAMP.md"
    
    cat > "$SUMMARY_FILE" << EOF
# CyberShield-IronCore Load Test Summary

**Test Date:** $(date)
**Test Duration:** $(date -d@$(($(date +%s) - START_TIME)) -u +%H:%M:%S)
**Target:** 1M requests/second capability validation

## Test Configuration

- **Artillery Version:** $(artillery version)
- **Test Phases:** 6 phases (warm-up to 1M RPS)
- **Target Endpoint:** http://localhost:8000
- **Test Scenarios:** 5 different API endpoints

## Files Generated

- Configuration: \`artillery_$TIMESTAMP.yml\`
- Results JSON: \`artillery_results_$TIMESTAMP.json\`
- HTML Report: \`artillery_report_$TIMESTAMP.html\`
- System Metrics: \`system_metrics_$TIMESTAMP.log\`
- Test Output: \`artillery_output_$TIMESTAMP.log\`

## Enterprise Readiness Assessment

This load test validates CyberShield-IronCore's capability to handle enterprise-scale traffic volumes, targeting:

- **Performance:** <100ms p95 response time
- **Reliability:** >95% success rate  
- **Scalability:** 1M+ requests/second peak capacity
- **Stability:** Sustained high load without degradation

## Next Steps

1. Review HTML report for detailed metrics
2. Analyze system metrics for resource utilization
3. Optimize bottlenecks identified during testing
4. Validate results in production-like environment

---

*Generated by CyberShield-IronCore Load Testing Suite*
*Enterprise-grade performance validation for \$1B acquisition readiness*
EOF

    echo -e "${GREEN}✅ Summary generated: $SUMMARY_FILE${NC}"
}

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}🧹 Cleaning up...${NC}"
    
    # Stop monitoring
    if [ ! -z "$MONITOR_PID" ]; then
        kill $MONITOR_PID 2>/dev/null || true
        echo -e "${GREEN}✅ Monitoring stopped${NC}"
    fi
    
    # Stop backend if we started it
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null || true
        echo -e "${GREEN}✅ Backend stopped${NC}"
    fi
    
    echo -e "${BLUE}📁 Test results saved in: $RESULTS_DIR${NC}"
    echo -e "${BLUE}🌐 Open HTML report: $RESULTS_DIR/artillery_report_$TIMESTAMP.html${NC}"
}

# Main execution
main() {
    START_TIME=$(date +%s)
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    # Run test sequence
    check_prerequisites
    start_monitoring
    run_load_test
    analyze_results
    generate_summary
    
    echo -e "\n${GREEN}🎉 Load testing completed successfully!${NC}"
    echo -e "${BLUE}📊 Results available in: $RESULTS_DIR${NC}"
    echo -e "${BLUE}📈 HTML Report: artillery_report_$TIMESTAMP.html${NC}"
}

# Execute main function
main "$@"