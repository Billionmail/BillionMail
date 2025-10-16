# BillionMail Pull Request Template

## PR Title Format
`<type>(<scope>): <description>`  
**Examples**:
- `fix(smtp): handle connection timeout during bulk send`
- `feat(campaign-ui): add A/B testing template selector`

### Type Guidelines
```
fix      : Bug fixes (e.g., `fix(auth): prevent login loop`)  
feat     : New features (e.g., `feat(analytics): add real-time dashboard`)  
build    : Build system changes (Docker/dependencies)  
ci       : CI/CD workflows (GitHub Actions)  
docs     : Documentation updates  
style    : Code formatting (non-functional changes)  
refactor : Code restructuring (no functionality change)  
perf     : Performance improvements  
test     : Test-related changes  
chore    : Maintenance/tooling changes  
```

**Rules**:
- **Scope**: Specify module (e.g., `smtp`) or layer (e.g., `frontend`)
- **Description**:
    - Use **present tense verbs** (e.g., `add` not `added`)
    - No ending punctuation, max 76 chars

---

## Linked Issues
Add one of these at the PR description's start:
- `Fixes #1234` → Complete resolution
- `Updates #1234` → Partial fix/related update

---

## Branch Management
### Frontend Specific
- **Target Branch**: `dev-frontend` (All frontend PRs must use this)
- **Naming Convention**:
```bash
# Feature development
feat/[description]  # e.g., feat/ab-test-ui
# Bug fixes
fix/[issue-id]-[desc]  # e.g., fix/4567-template-render
```

### Backend/Core
- **Target Branch**: `main`
- **Naming Convention**:
```bash
# Mail engine
smtp/[feature]  # e.g., smtp/rate-limit
# Infrastructure
infra/[change]  # e.g., infra/redis-cluster
```

---

## PR Description Template
```markdown
### Purpose  
<!-- Why this change is needed (reference project goals) -->

### Implementation  
<!-- Key code/architecture changes, especially for SMTP/Rspamd -->

### Testing  
- [ ] Unit tests passed (`npm test`/`go test`)  
- [ ] Manual steps:  
~~~bash
# Example: Test bulk send
bm send --campaign test --list 1000
~~~
- [ ] Impact analysis (e.g., template compatibility/sending rate)

### Additional Context
<!-- Screenshots, performance metrics, or related docs -->
```

---

## Automation Integration
1. **Commit Validation**:  
   Use `husky` + `commitlint` to enforce conventions:  
```javascript
// commitlint.config.js
module.exports = { extends: ['@commitlint/config-conventional'] };
```

2. **PR Title Check**:  
   Add GitHub Action to validate PR titles:
```yaml
# .github/workflows/pr-check.yml
uses: amannn/action-semantic-pull-request@v5
```

> **Tip**: For mail-sending logic changes, verify SPF/DKIM signing
```

### Key Features
- **Frontend Isolation**: Explicit `dev-frontend` branch for frontend changes  
- **Modular Scopes**: Clear module boundaries (e.g., `smtp`, `analytics`) for automated changelogs  
- **Compliance Ready**: GDPR/SPF checks emphasized for critical components  

This template can be saved to `.github/PULL_REQUEST_TEMPLATE.md` for automatic application.