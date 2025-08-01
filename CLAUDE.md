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

### Infrastructure (AWS) - ✅ COMPLETE

- **Container**: EKS (Kubernetes) multi-AZ with auto-scaling
- **Database**: PostgreSQL RDS Multi-AZ + Redis ElastiCache
- **Networking**: Multi-AZ VPC (10.0.0.0/16) with private/public subnets
- **Security**: KMS encryption, VPC Flow Logs, Secrets Manager
- **Monitoring**: CloudWatch dashboards, SNS alerts, Performance Insights
- **IaC**: Terraform (3,500+ lines) with comprehensive documentation

## Key Features Implementation Priority

### Phase 1: Foundation ✅ COMPLETE (Week 1)

1. ✅ Project structure & quality gates
2. ✅ Enterprise tooling configuration
3. ✅ CI/CD pipeline with GitHub Actions
4. ✅ 100% test coverage enforcement

### Phase 2: Backend Development ✅ COMPLETE (Week 2)

1. ✅ FastAPI + gRPC microservices
2. ✅ Async SQLAlchemy database models
3. ✅ Enterprise configuration management
4. ✅ Structured logging with audit trails

### Phase 3: AWS Infrastructure ✅ COMPLETE (Week 3)

1. ✅ Multi-AZ VPC with enterprise networking
2. ✅ EKS Kubernetes cluster with auto-scaling
3. ✅ PostgreSQL RDS Multi-AZ + Redis ElastiCache
4. ✅ CloudWatch monitoring with JARVIS-style alerts
5. ✅ KMS encryption for all data
6. ✅ Terraform IaC with comprehensive documentation

### Phase 4: Authentication & Frontend (Week 4) - 🚧 IN PROGRESS

1. 🚧 OAuth 2.0 + Okta integration
2. ✅ Next.js frontend with Iron Man JARVIS theme (Base implementation complete)
3. 🚧 UX Enhancement Layer - CyberShield Excellence Initiative
4. 🚧 Kubernetes deployment manifests
5. 🚧 Application integration with infrastructure

#### Phase 4.1: UX Enhancement Priorities - 🎯 IRON MAN LEVEL UX

**HIGH PRIORITY (Week 4 Focus):**

- ✅ **Explainability Layer**: Add inline "Explain" buttons for AI threat decisions with conversational breakdown
- ✅ **JARVIS Command Interface**: Natural language query panel for admins (voice/text commands)
- ✅ **Mobile Executive Dashboard**: Responsive design for C-level mobile access and alerts

**MEDIUM PRIORITY (Week 5 Integration):**

- 📋 **Interactive Audit Trails**: Clickable threat timelines showing progression and decisions
- 📋 **Guided Onboarding Tours**: Interactive feature previews and product walkthroughs
- 📋 **AI Decision Flow Visualization**: Show how AI reaches threat assessments

**UX INSPIRATION BENCHMARKS:**

- **CrowdStrike**: High-contrast dashboards, instant navigation
- **Abnormal Security**: Animated product walkthroughs, real-time events
- **Axonius**: Inline product demos, clean interactions
- **Recorded Future**: Minimalist power, data-focused design

### Phase 5: AI Engine & Intelligence ✅ COMPLETE (Week 5)

1. ✅ TensorFlow anomaly detection model
2. ✅ Kafka real-time log processing
3. ✅ VirusTotal + MITRE ATT&CK integration
4. ✅ Risk scoring algorithm (0-100 scale)

### Phase 6: Frontend + Testing (Week 6) - 📋 PENDING

1. 📋 Real-time threat visualization
2. 📋 JARVIS-like AI assistant integration
3. 📋 Load testing (1M requests/sec)
4. 📋 Security penetration testing

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

### Phase 3 Infrastructure Achievements - ⚡ IRON MAN LEVEL!

**🛡️ ENTERPRISE-GRADE AWS INFRASTRUCTURE DEPLOYED:**

#### Core Infrastructure Components

- **Multi-AZ VPC**: 10.0.0.0/16 with enterprise networking and 99.99% availability
- **EKS Kubernetes**: Auto-scaling clusters (t3.large → c5.2xlarge nodes)
- **PostgreSQL RDS**: Multi-AZ with read replicas, performance insights, encryption
- **Redis ElastiCache**: High-availability caching with auth tokens and failover
- **CloudWatch Suite**: JARVIS-level monitoring with intelligent alerting
- **KMS Encryption**: Customer-managed keys with automatic rotation
- **Secrets Manager**: Secure credential storage with cross-region replication
- **VPC Flow Logs**: Complete network traffic monitoring for compliance

#### Security & Compliance Arsenal

- **Zero-Trust Architecture**: Network segmentation with security groups
- **SOC 2/GDPR/HIPAA Ready**: Comprehensive audit trails and compliance
- **Real-Time Alerting**: SNS topics with threat detection metrics
- **GuardDuty Integration**: AWS native threat detection capability
- **Performance Insights**: Database and application monitoring

#### Infrastructure as Code

- **Terraform Files**: 3,500+ lines of production-ready infrastructure
- **Environment Support**: Development ($50/month) → Production ($500/month)
- **Auto-Scaling**: Dynamic scaling for 10 → 10,000+ concurrent users
- **Cost Optimization**: Spot instances, intelligent storage, resource tagging

### Current Development Status

**✅ COMPLETED PHASES:**

- Phase 1: Foundation & Quality Gates (Week 1)
- Phase 2: FastAPI Backend Development (Week 2)
- Phase 3: AWS Infrastructure Domination (Week 3)
- Phase 4: OAuth 2.0 + Iron Man Frontend UX (Week 4)
- Phase 5: AI Engine & Intelligence (Week 5)

**🚧 CURRENT PHASE:**

- Phase 6: Frontend + Testing (Week 6)

### Conversation Compaction

This CLAUDE.md contains all essential context for CyberShield-IronCore development. Reference PRD.md and PRE-PROJECT-SETTINGS.md for complete specifications.

**AWS Infrastructure**: Terraform code at `infrastructure/terraform/` with comprehensive documentation

---

**Remember**: We're building enterprise software for Fortune 500 acquisition. Quality is non-negotiable.

**🛡️ Infrastructure Status**: FULLY OPERATIONAL - Ready for application deployment! ⚡

## UX Enhancement Implementation Guide

### Current Frontend Status - ✅ SOLID FOUNDATION

**Completed Iron Man Aesthetic:**

- ✅ Dark terminal theme (#000000 + #00FF41 Matrix green)
- ✅ Real-time threat monitoring dashboard
- ✅ Live event streams with timestamps
- ✅ Animated risk indicators and glitch effects
- ✅ Professional cybersecurity layout
- ✅ Arc Reactor styling and JARVIS branding

**✅ COMPLETED UX ENHANCEMENTS (December 2024):**

- ✅ **Full Cyber War Room at /cyber route** - Complete terminal aesthetic dashboard
- ✅ **Explainability Layer** - "⚡ WHY FLAGGED?" buttons on all threat cards
- ✅ **JARVIS Command Interface** - Fixed bottom-right panel with quick commands
- ✅ **Mobile Responsive Design** - Flexible grid layout for all screen sizes
- ✅ **Real-time Risk Scoring** - Live updating threat levels with color coding
- ✅ **Interactive Threat Cards** - Dynamic styling based on severity levels
- ✅ **Live Event Streams** - Real-time log updates with proper formatting
- ✅ **Professional Layout** - Fixed overlapping issues, proper spacing

### Priority UX Enhancements - 🎯 IMPLEMENTATION DETAILS

#### 1. Explainability Layer (HIGH PRIORITY)

```typescript
// Add to each threat card
<button
  className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
  onClick={() => explainThreat(threat.id)}
>
  🧠 Why flagged?
</button>

// Modal/panel showing AI reasoning
interface ThreatExplanation {
  reasoning: string;
  confidence: number;
  mitigationSteps: string[];
  riskFactors: string[];
}
```

#### 2. JARVIS Command Interface (HIGH PRIORITY)

```typescript
// Natural language query component
<div className="fixed bottom-4 right-4 w-96">
  <input
    className="w-full bg-black border border-green-400 text-green-400 p-3 font-mono"
    placeholder="Ask JARVIS: 'Show critical threats from last hour'"
    onKeyPress={handleJarvisCommand}
  />
</div>

// Voice command integration
const useVoiceCommands = () => {
  // WebSpeech API integration
  // Command parsing and execution
}
```

#### 3. Mobile Executive Dashboard (HIGH PRIORITY)

```css
/* Responsive breakpoints for C-level mobile access */
@media (max-width: 768px) {
  .cyber-dashboard {
    grid-template-columns: 1fr;
    gap: 0.5rem;
  }

  .threat-card {
    padding: 0.75rem;
    font-size: 0.875rem;
  }
}
```

#### 4. Interactive Audit Trails (MEDIUM PRIORITY)

```typescript
// Timeline component for threat progression
interface ThreatTimeline {
  events: Array<{
    timestamp: Date;
    action: string;
    actor: 'AI' | 'Human' | 'System';
    details: string;
  }>;
}
```

### Implementation Schedule

**Week 4 (Current):**

- Day 1-2: Explainability layer implementation
- Day 3-4: JARVIS command interface
- Day 5: Mobile responsiveness

**Week 5 (Integration):**

- Audit trails and onboarding tours
- Performance optimization
- User testing and refinement
