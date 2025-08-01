# CyberShield-IronCore: Pre-Project Settings & Development Standards

## Overview

This document establishes the non-negotiable development standards and quality gates for CyberShield-IronCore. These requirements ensure enterprise-grade code quality, maintainability, and production readiness throughout the 6-8 week development cycle.

## Core Development Philosophy

**Zero Compromise Quality**: Every task must meet 100% of the criteria below before moving to the next task. No exceptions.

**Production-First Mindset**: Develop as if every commit goes directly to production for Fortune 500 clients.

## Non-Negotiable Quality Gates

### 1. Test-Driven Development (TDD) Process

#### TDD Workflow - MANDATORY

```bash
# Step 1: Write failing test first
npm run test:watch

# Step 2: Write minimal code to pass test
npm run test

# Step 3: Refactor while keeping tests green
npm run test

# Step 4: Verify full test suite
npm run test:coverage
```

#### Testing Requirements

- **100% Test Coverage**: No code ships without corresponding tests
- **100% Test Pass Rate**: All tests must pass before task completion
- **Test Types Required**:
  - Unit tests for all functions/methods
  - Integration tests for API endpoints
  - End-to-end tests for critical user flows
  - Security tests for authentication/authorization

#### Testing Stack

```json
{
  "jest": "^29.0.0",
  "testing-library/react": "^13.0.0",
  "testing-library/jest-dom": "^5.16.0",
  "supertest": "^6.3.0",
  "playwright": "^1.40.0"
}
```

### 2. Code Quality Standards

#### TypeScript Requirements

- **Zero TypeScript Errors**: `npm run type-check` must pass with 0 errors
- **Strict Mode Enabled**: TypeScript strict mode mandatory
- **Type Coverage**: 100% type coverage, no `any` types allowed
- **Interface Definitions**: All API responses and data structures must be typed

#### ESLint Requirements

- **Zero Lint Errors**: `npm run lint` must pass with 0 errors/warnings
- **Zero Lint Warnings**: Warnings are treated as errors
- **Custom Rules**:
  - Max function length: 75 lines
  - Max cyclomatic complexity: 10
  - No console.log in production code
  - Enforce consistent naming conventions

#### Function Size Limit

- **Maximum 75 Lines**: No function/method can exceed 75 lines
- **Single Responsibility**: Each function does one thing well
- **Extract Complex Logic**: Break down complex functions into smaller, testable units

### 3. Build Validation Requirements

#### Pre-Development Checklist

```bash
# Run before starting any new feature
npm run build          # Verify production build works
npm run type-check     # Check TypeScript compilation
npm run lint           # Catch style/syntax issues
npm run test           # Ensure existing tests pass
npm run security:audit # Check for security vulnerabilities
```

#### Component Development Standards

- **Import Validation**: All imports must resolve in both dev and production
- **Shadcn/UI Components**: Create missing components immediately when referenced
- **File Existence Check**: Verify actual files exist, not just TypeScript declarations

#### Database Schema Synchronization

```bash
# After any schema changes
npx prisma generate    # Update Prisma client
npx prisma db:push     # Sync schema with database
npm run test:db        # Run database integration tests
```

### 4. Required NPM Scripts

#### Package.json Scripts Configuration

```json
{
  "scripts": {
    "dev": "next dev",
    "build": "next build && tsc --noEmit",
    "start": "next start",
    "lint": "eslint . --ext .ts,.tsx --max-warnings 0",
    "lint:fix": "eslint . --ext .ts,.tsx --fix",
    "type-check": "tsc --noEmit --incremental",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage --watchAll=false",
    "test:e2e": "playwright test",
    "test:db": "jest --testPathPattern=database",
    "security:audit": "npm audit --audit-level moderate",
    "db:generate": "prisma generate",
    "db:push": "prisma db push",
    "db:migrate": "prisma migrate dev",
    "precommit": "npm run lint && npm run type-check && npm run test && npm run build"
  }
}
```

### 5. Pre-Commit Quality Gates

#### Git Hooks Configuration

```bash
# .husky/pre-commit
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

# Non-negotiable checks
npm run lint
npm run type-check
npm run test
npm run build

# Security checks
npm run security:audit

# Test coverage check
npm run test:coverage -- --coverageThreshold='{"global":{"branches":100,"functions":100,"lines":100,"statements":100}}'
```

#### Commit Standards

- **Conventional Commits**: Use conventional commit format
- **Atomic Commits**: One logical change per commit
- **Descriptive Messages**: Clear description of what and why

### 6. Development Environment Setup

#### Required Tools

```bash
# Node.js version management
nvm install 18.17.0
nvm use 18.17.0

# Package manager
npm install -g pnpm@8.10.0

# Global tools
npm install -g @typescript-eslint/cli
npm install -g prisma
npm install -g playwright
```

#### VS Code Configuration

```json
// .vscode/settings.json
{
  "typescript.preferences.strictNullChecks": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true,
    "source.organizeImports": true
  },
  "editor.formatOnSave": true,
  "files.trimTrailingWhitespace": true,
  "jest.autoRun": "watch"
}
```

### 7. Production-Ready Development Standards

#### Build Verification

- **Production Build Test**: `npm run build` must succeed locally
- **Type Safety**: All types must be explicitly defined
- **Performance Checks**: Lighthouse score >90 for critical pages
- **Bundle Analysis**: Check bundle size with `npm run analyze`

#### Security Standards

- **No Secrets in Code**: Use environment variables for all secrets
- **Input Validation**: Validate all user inputs server-side
- **Authentication**: Implement proper OAuth 2.0 + Okta integration
- **HTTPS Only**: All communications encrypted in transit

### 8. Database Development Standards

#### Prisma Schema Requirements

```prisma
// Always include these fields
model BaseModel {
  id        String   @id @default(cuid())
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
```

#### Migration Process

```bash
# Schema changes workflow
1. Update schema.prisma
2. npx prisma migrate dev --name descriptive_name
3. npx prisma generate
4. Update TypeScript types
5. Write migration tests
6. Run full test suite
```

### 9. API Development Standards

#### FastAPI Requirements

```python
# All endpoints must include:
- Type hints for all parameters
- Pydantic models for request/response
- Error handling with proper HTTP status codes
- Authentication/authorization checks
- Input validation
- Logging for audit trails

# Example endpoint structure
@app.post("/api/threats", response_model=ThreatResponse)
async def create_threat(
    threat: ThreatCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> ThreatResponse:
    # Implementation with full error handling
    pass
```

#### API Testing Requirements

```python
# Test file structure for each endpoint
class TestThreatEndpoints:
    async def test_create_threat_success(self):
        """Test successful threat creation"""
        pass

    async def test_create_threat_unauthorized(self):
        """Test unauthorized access"""
        pass

    async def test_create_threat_invalid_data(self):
        """Test invalid input validation"""
        pass
```

### 10. Frontend Development Standards

#### React Component Requirements

```typescript
// Component structure template
interface ComponentProps {
  // All props must be typed
}

export const Component: React.FC<ComponentProps> = ({ prop1, prop2 }) => {
  // Hooks at the top
  const [state, setState] = useState<StateType>(initialState);

  // Event handlers
  const handleEvent = useCallback(() => {
    // Implementation
  }, [dependencies]);

  // Render with proper error boundaries
  return (
    <ErrorBoundary>
      {/* Component JSX */}
    </ErrorBoundary>
  );
};

// Default export with display name
Component.displayName = 'Component';
export default Component;
```

#### Component Testing Template

```typescript
describe('Component', () => {
  it('renders correctly with required props', () => {
    render(<Component {...requiredProps} />);
    expect(screen.getByRole('...'));
  });

  it('handles user interactions correctly', async () => {
    const user = userEvent.setup();
    render(<Component {...props} />);
    // Test user interactions
  });

  it('handles error states gracefully', () => {
    // Test error scenarios
  });
});
```

### 11. Task Completion Checklist

#### Before Moving to Next Task - NON-NEGOTIABLE

```bash
# 1. Code Quality
✅ npm run lint (0 errors, 0 warnings)
✅ npm run type-check (0 TypeScript errors)
✅ All functions < 75 lines

# 2. Testing
✅ npm run test (100% pass rate)
✅ npm run test:coverage (100% coverage)
✅ npm run test:e2e (all E2E tests pass)

# 3. Build Validation
✅ npm run build (successful production build)
✅ npm run security:audit (no high/critical vulnerabilities)

# 4. Code Review
✅ Self-review completed
✅ Documentation updated
✅ Comments added for complex logic

# 5. Git Workflow
✅ Atomic commits with clear messages
✅ Branch up to date with main
✅ Pre-commit hooks pass
```

### 12. Continuous Integration Pipeline

#### GitHub Actions Workflow

```yaml
# .github/workflows/ci.yml
name: CI Pipeline

on: [push, pull_request]

jobs:
  quality-gates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18.17.0'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Lint check
        run: npm run lint

      - name: Type check
        run: npm run type-check

      - name: Run tests
        run: npm run test:coverage

      - name: Build verification
        run: npm run build

      - name: Security audit
        run: npm audit --audit-level moderate

      - name: E2E tests
        run: npm run test:e2e
```

### 13. Performance Standards

#### Frontend Performance

- **Core Web Vitals**: LCP <2.5s, FID <100ms, CLS <0.1
- **Bundle Size**: Main bundle <250KB gzipped
- **React Performance**: No unnecessary re-renders
- **Image Optimization**: All images optimized and lazy-loaded

#### Backend Performance

- **API Response Time**: <100ms for 95th percentile
- **Database Queries**: N+1 query prevention
- **Caching Strategy**: Redis caching for frequent queries
- **Rate Limiting**: Implement proper rate limiting

### 14. Security Development Standards

#### Authentication & Authorization

```typescript
// Security middleware example
export const requireAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) throw new Error('No token provided');

    const decoded = await verifyJWT(token);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized' });
  }
};
```

#### Input Validation

```typescript
// Zod schema validation
const ThreatCreateSchema = z.object({
  type: z.enum(['malware', 'phishing', 'ddos']),
  severity: z.number().min(1).max(10),
  description: z.string().min(10).max(1000),
  indicators: z.array(z.string().url()).max(100),
});
```

### 15. Documentation Requirements

#### Code Documentation

- **JSDoc Comments**: All public functions documented
- **README Updates**: Keep README current with setup instructions
- **API Documentation**: OpenAPI/Swagger specs for all endpoints
- **Architecture Decisions**: Document all significant technical decisions

#### Example Documentation

````typescript
/**
 * Calculates risk score based on threat indicators
 * @param indicators - Array of threat indicators
 * @param weights - Weighting factors for each indicator type
 * @returns Promise<RiskScore> - Calculated risk score (0-100)
 * @throws {ValidationError} When indicators array is empty
 * @example
 * ```typescript
 * const score = await calculateRiskScore(indicators, weights);
 * console.log(`Risk level: ${score.level}`);
 * ```
 */
export async function calculateRiskScore(
  indicators: ThreatIndicator[],
  weights: WeightingFactors
): Promise<RiskScore> {
  // Implementation
}
````

---

## Enforcement

These standards are **NON-NEGOTIABLE**. Any deviation requires explicit approval and documented justification. The automated tooling will enforce these standards, and manual verification is required before task completion.

**Remember**: We're building enterprise software for Fortune 500 companies. Quality cannot be compromised.
