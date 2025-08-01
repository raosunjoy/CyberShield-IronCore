# CLAUDE.md - CyberShield-IronCore Project Context

## Project Overview

**CyberShield-IronCore** is an enterprise-grade AI-powered Cyber Risk Management Platform designed for Fortune 500 companies, banks, and hospitals. Target: $1B-$2B acquisition by Palo Alto Networks.

**Timeline**: 6-8 weeks development
**Revenue Target**: $6M ARR Year 1, scaling to $50M
**Key Differentiator**: Iron Man-inspired UI with JARVIS-like AI assistant

## Critical Documents Location

- **PRD.md**: Complete Product Requirements Document
- **PRE-PROJECT-SETTINGS.md**: Development standards and quality gates

## NON-NEGOTIABLE Development Standards

### Quality Gates - MUST PASS BEFORE NEXT TASK

```bash
# Pre-Development Checks
npm run build          # Production build must succeed
npm run type-check     # Zero TypeScript errors
npm run lint           # Zero lint errors/warnings
npm run test           # 100% test pass rate
npm run test:coverage  # 100% test coverage
npm run security:audit # No high/critical vulnerabilities
```

### Code Quality Rules

- **TDD Process**: Write failing test first, then minimal code to pass
- **Function Size**: Maximum 75 lines per function
- **TypeScript**: Strict mode, no `any` types, 100% type coverage
- **Testing**: Unit + Integration + E2E tests for all features
- **Documentation**: JSDoc comments for all public functions

### Task Completion Checklist

✅ All tests pass (100% coverage)  
✅ Zero TypeScript errors  
✅ Zero lint errors/warnings  
✅ Production build successful  
✅ Security audit clean  
✅ Functions under 75 lines  
✅ Documentation updated  
✅ Self-review completed

## Tech Stack

### Backend (Python)

- **Framework**: FastAPI (async, enterprise-grade)
- **Database**: AWS RDS (PostgreSQL) + Redis caching
- **Message Queue**: AWS MSK (Kafka) for 1M+ events/sec
- **AI/ML**: TensorFlow + Hugging Face BERT
- **Auth**: OAuth 2.0 + Okta integration

### Frontend (TypeScript/React)

- **Framework**: Next.js with TypeScript strict mode
- **UI**: Shadcn/ui components (Iron Man theme)
- **State**: React Query + Zustand
- **GraphQL**: Apollo Client
- **Testing**: Jest + Testing Library + Playwright

### Infrastructure (AWS)

- **Container**: EKS (Kubernetes) multi-region
- **CDN**: Cloudflare + AWS Global Accelerator
- **Monitoring**: CloudWatch + PagerDuty
- **Security**: AWS KMS encryption, WAF, Security Groups

## Key Features Implementation Priority

### Phase 1: Foundation (Weeks 1-2)

1. FastAPI + gRPC microservices
2. OAuth 2.0 with Okta
3. AWS RDS + Redis setup
4. Multi-region infrastructure

### Phase 2: AI Engine (Weeks 3-4)

1. TensorFlow anomaly detection model
2. Kafka real-time log processing
3. VirusTotal + MITRE ATT&CK integration
4. Risk scoring algorithm (0-100 scale)

### Phase 3: Frontend + Integrations (Weeks 5-6)

1. React dashboard with Iron Man UI
2. JARVIS-like AI assistant (xAI Grok API)
3. ServiceNow/Splunk connectors
4. Real-time threat visualization

### Phase 4: Testing + Deployment (Weeks 7-8)

1. Load testing (1M requests/sec)
2. Security penetration testing
3. Multi-region production deployment
4. SLA monitoring setup (99.99% uptime)

## Enterprise Requirements

### Performance Targets

- **API Response**: <100ms (95th percentile)
- **Event Processing**: 1M+ events/second
- **Uptime**: 99.99% SLA
- **Scalability**: 10 to 10,000+ concurrent users

### Security & Compliance

- **Encryption**: AES-256 at rest, TLS 1.3 in transit
- **Compliance**: SOC 2, GDPR, HIPAA ready
- **Authentication**: Multi-factor with Okta
- **Audit**: Tamper-proof logs in S3

### Integration Capabilities

- **SIEM**: Splunk, IBM QRadar
- **SOAR**: Palo Alto Prisma AIRS
- **Endpoint**: CrowdStrike API
- **ITSM**: ServiceNow workflows
- **Communication**: PagerDuty, Slack, Twilio

## Development Commands

### Daily Workflow

```bash
# Start development session
npm run build && npm run type-check && npm run lint && npm run test

# After making changes
npm run test:watch        # TDD development
npm run test:coverage     # Verify 100% coverage
npm run build            # Ensure production readiness

# Database changes
npx prisma generate      # After schema updates
npx prisma db:push       # Sync schema
npm run test:db          # Test database integration

# Pre-commit verification
npm run precommit        # Runs all quality gates
```

### Testing Commands

```bash
npm run test             # Unit tests
npm run test:watch       # TDD mode
npm run test:coverage    # Coverage report
npm run test:e2e         # End-to-end tests
npm run test:db          # Database tests
```

## Architecture Decisions

### Single Points of Failure (SPOF) Mitigation

- **VirusTotal**: AlienVault OTX backup + 48h Redis cache
- **Database**: Multi-AZ RDS with read replicas
- **CDN**: Cloudflare primary, AWS Global Accelerator fallback
- **Auth**: Okta primary, AWS Cognito fallback
- **Messaging**: Multi-AZ Kafka with dead letter queues

### Cost Optimization

- **Monthly Budget**: $1,960 (optimized from $4,510)
- **Savings**: Drop AWS Shield Advanced, use Cloudflare DDoS
- **Efficiency**: AWS Savings Plans for 20% cost reduction

## Business Context

### Acquisition Strategy

- **Target**: Palo Alto Networks acquisition
- **Timing**: Post-CyberArk ($25B) and Protect AI ($700M)
- **Valuation**: 15-20x ARR multiple = $1B-$2B
- **Strategic Fit**: Fills Prisma AIRS supply chain security gaps

### Competitive Advantage

- **AI-First**: Native ML vs. rule-based competitors
- **Time-to-Value**: 10x faster deployment than traditional SIEM
- **Integration**: Seamless Palo Alto ecosystem compatibility
- **Cost**: 50% TCO reduction vs. existing solutions

## Common Pitfalls to Avoid

### Development Anti-Patterns

❌ Skipping tests to move faster  
❌ Using `any` types in TypeScript  
❌ Functions longer than 75 lines  
❌ Missing error handling  
❌ Hardcoded secrets in code  
❌ Skipping production build verification  
❌ Moving to next task without 100% quality gates

### Enterprise Development Reminders

✅ Always validate inputs server-side  
✅ Log all security events for audit  
✅ Implement proper error boundaries  
✅ Use environment variables for configuration  
✅ Test failure scenarios explicitly  
✅ Document all public APIs  
✅ Consider multi-tenant data isolation

## Emergency Procedures

### Build Failures

1. Check TypeScript errors: `npm run type-check`
2. Fix lint issues: `npm run lint:fix`
3. Verify test coverage: `npm run test:coverage`
4. Clear node_modules and reinstall if needed

### Database Issues

1. Verify Prisma schema sync: `npx prisma generate`
2. Check database connection: `npm run test:db`
3. Review migration history: `npx prisma migrate status`

### Production Deployment

1. Full quality gate pass: `npm run precommit`
2. Security audit clean: `npm run security:audit`
3. Performance test: Load test with expected traffic
4. Rollback plan: Document rollback procedures

## Session Reminders

### Every Session Start

1. Review PRD.md for current requirements
2. Check PRE-PROJECT-SETTINGS.md for quality standards
3. Run quality gates before starting new work
4. Update this CLAUDE.md if project scope changes

### Before Task Completion

1. Complete task completion checklist
2. Update documentation if needed
3. Verify all quality gates pass
4. Self-review code changes

### Conversation Compaction

This CLAUDE.md contains all essential context for CyberShield-IronCore development. Reference PRD.md and PRE-PROJECT-SETTINGS.md for complete specifications.

---

**Remember**: We're building enterprise software for Fortune 500 acquisition. Quality is non-negotiable.
