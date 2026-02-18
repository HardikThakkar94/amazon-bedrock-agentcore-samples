# Visa MCP Server Documentation Index

Complete documentation set for the Visa MCP server migration and integration.

## Quick Navigation

### For Developers
- **Primary Resource**: [Visa MCP Tools Reference](visa-mcp-tools-reference.md)
- **Integration Help**: [Visa MCP Integration Guide](visa-mcp-integration-guide.md#integration-with-agentcore)
- **Testing**: [Visa MCP Integration Guide - Testing Section](visa-mcp-integration-guide.md#testing-the-mcp-server)

### For DevOps/Infrastructure Engineers
- **Primary Resource**: [Visa MCP Integration Guide](visa-mcp-integration-guide.md)
- **Deployment Steps**: [CDK Deployment](visa-mcp-integration-guide.md#cdk-deployment)
- **Troubleshooting**: [Integration Guide - Troubleshooting](visa-mcp-integration-guide.md#troubleshooting)
- **Monitoring**: [Monitoring & Logging](visa-mcp-integration-guide.md#monitoring--logging)

### For Architects/Technical Leads
- **Primary Resource**: [Visa Flask to MCP Migration](visa-flask-to-mcp-migration.md)
- **Architecture Decisions**: [Key Architectural Decisions](visa-flask-to-mcp-migration.md#key-architectural-decisions)
- **Migration Plan**: [Migration Checklist](visa-flask-to-mcp-migration.md#migration-checklist)

### For Support/Operations
- **Troubleshooting Guide**: [Integration Guide - Troubleshooting](visa-mcp-integration-guide.md#troubleshooting)
- **Health Checks**: [Testing the MCP Server](visa-mcp-integration-guide.md#testing-the-mcp-server)
- **Monitoring Setup**: [Monitoring & Logging](visa-mcp-integration-guide.md#monitoring--logging)

---

## Documentation Overview

### 1. Visa MCP Tools Reference (32 KB, 968 lines)

**File**: `visa-mcp-tools-reference.md`

Complete technical reference for all 10 Visa payment tools.

#### Contents:
- **Tools (10 total)**:
  1. `visa_get_secure_token` - OAuth token retrieval
  2. `visa_onboard_card` - Card enrollment and provisioning
  3. `visa_device_attestation` - Device security verification
  4. `visa_device_binding` - FIDO/passkey binding
  5. `visa_step_up` - OTP step-up authentication
  6. `visa_validate_otp` - OTP validation
  7. `visa_complete_passkey` - FIDO response parsing
  8. `visa_vic_enroll_card` - VIC enrollment
  9. `visa_vic_initiate_purchase` - Payment mandate creation
  10. `visa_vic_payment_credentials` - Cryptogram retrieval

- **For Each Tool**:
  - Purpose and use case
  - Parameter reference table
  - Return value structure
  - Error cases
  - Example usage
  - Important notes

- **Additional Sections**:
  - Error handling patterns with retry strategies
  - Browser data strategy explanation
  - Rate limiting and quotas
  - Testing procedures
  - Security considerations
  - Complete 7-step payment flow example
  - Test credentials reference

#### Quick Links:
- [visa_get_secure_token](visa-mcp-tools-reference.md#tool-1-visa_get_secure_token)
- [visa_onboard_card](visa-mcp-tools-reference.md#tool-2-visa_onboard_card)
- [visa_device_attestation](visa-mcp-tools-reference.md#tool-3-visa_device_attestation)
- [Error Handling Patterns](visa-mcp-tools-reference.md#error-handling-patterns)
- [Complete Flow Example](visa-mcp-tools-reference.md#complete-flow-example)

---

### 2. Visa MCP Integration Guide (28 KB, 1,110 lines)

**File**: `visa-mcp-integration-guide.md`

Complete deployment and integration guide for production environments.

#### Contents:
- **Architecture**:
  - System components diagram
  - Security layers
  - Data flow

- **Setup**:
  - AWS prerequisites and IAM
  - Secrets Manager configuration (all 7 secrets)
  - CDK deployment step-by-step
  - Server configuration
  - Docker image setup

- **Testing & Validation**:
  - Health checks
  - Tool discovery
  - Integration testing examples
  - Visa sandbox testing

- **Integration with Agents**:
  - Tool calling patterns
  - Error handling
  - Response parsing
  - Safe wrapper functions
  - Rate limiting examples

- **Operations**:
  - CloudWatch monitoring
  - Alarms and alerts
  - Logging and debugging
  - Performance metrics

- **Troubleshooting (7 scenarios)**:
  1. Secrets Manager access denied
  2. Invalid secure token
  3. Card onboarding failures
  4. Device attestation issues
  5. OTP validation failures
  6. VIC enrollment errors
  7. Payment credential issues

- **Advanced Topics**:
  - Performance tuning
  - Security best practices
  - Disaster recovery
  - Rollback procedures

#### Quick Links:
- [Architecture](visa-mcp-integration-guide.md#architecture)
- [Secrets Manager Setup](visa-mcp-integration-guide.md#secrets-manager-setup)
- [CDK Deployment](visa-mcp-integration-guide.md#cdk-deployment)
- [Testing](visa-mcp-integration-guide.md#testing-the-mcp-server)
- [Integration with AgentCore](visa-mcp-integration-guide.md#integration-with-agentcore)
- [Troubleshooting](visa-mcp-integration-guide.md#troubleshooting)

---

### 3. Visa Flask to MCP Migration (24 KB, 937 lines)

**File**: `visa-flask-to-mcp-migration.md`

Migration documentation explaining changes and architectural decisions.

#### Contents:
- **Executive Summary**:
  - What changed
  - Why the migration happened
  - Key metrics

- **What Was Preserved** (~2,072 lines unchanged):
  - `visa/flow.py` (1,580 lines)
  - `visa/helpers.py` (313 lines)
  - `visa/secure_token.py` (179 lines)

- **What Changed**:
  - Server architecture (Flask → MCP)
  - Tool wrapping layer
  - Parameter handling
  - Response format
  - Secrets management
  - Deployment approach

- **Architectural Decisions** (4 total):
  1. Secrets Manager vs SSM Parameter Store
  2. Browser data strategy for server-side calls
  3. Tool composition vs single-call tools
  4. Error handling pattern (no exceptions from tools)

- **Migration Details**:
  - Complete tool mapping table (11 Flask endpoints → 10 MCP tools)
  - Code organization comparison
  - File-by-file breakdown
  - 6-phase migration checklist

- **Verification & Validation**:
  - Functional equivalence tests
  - Performance comparison
  - Migration verification procedures

- **Risk Management**:
  - Rollback plan (3 steps)
  - Rollback timing
  - Data preservation

- **Lessons Learned**:
  - What worked well
  - Challenges addressed
  - Recommendations for future work

#### Quick Links:
- [Executive Summary](visa-flask-to-mcp-migration.md#executive-summary)
- [What Was Preserved](visa-flask-to-mcp-migration.md#what-was-preserved)
- [What Changed](visa-flask-to-mcp-migration.md#what-changed)
- [Architectural Decisions](visa-flask-to-mcp-migration.md#key-architectural-decisions)
- [Tool Mapping Table](visa-flask-to-mcp-migration.md#tool-1-secure-token-retrieval)
- [Rollback Plan](visa-flask-to-mcp-migration.md#rollback-plan)

---

## Statistics

### Documentation Size
- **Total**: 84 KB
- **Reference Document**: 32 KB
- **Integration Guide**: 28 KB
- **Migration Document**: 24 KB

### Content Volume
- **Total Lines**: 3,015
- **Total Sections**: 47
- **Total Code Examples**: 230
- **Bash Commands**: 92
- **Python Code**: 85
- **Configuration Examples**: 34
- **Other**: 19

### Coverage
- **Tools Documented**: 10/10 (100%)
- **Common Issues Addressed**: 7
- **Troubleshooting Scenarios**: 7+
- **Tables Included**: 15+
- **Architecture Diagrams**: 1

---

## Common Tasks & Resources

### I want to integrate Visa tools with my agent
1. Read: [Visa MCP Tools Reference - Overview](visa-mcp-tools-reference.md#overview)
2. Review: [Visa MCP Tools Reference - Complete Flow Example](visa-mcp-tools-reference.md#complete-flow-example)
3. Check: [Visa MCP Integration Guide - Integration with AgentCore](visa-mcp-integration-guide.md#integration-with-agentcore)

### I need to deploy the Visa MCP server
1. Start: [Visa MCP Integration Guide - Prerequisites](visa-mcp-integration-guide.md#prerequisites)
2. Follow: [Visa MCP Integration Guide - Secrets Manager Setup](visa-mcp-integration-guide.md#secrets-manager-setup)
3. Deploy: [Visa MCP Integration Guide - CDK Deployment](visa-mcp-integration-guide.md#cdk-deployment)
4. Verify: [Visa MCP Integration Guide - Testing the MCP Server](visa-mcp-integration-guide.md#testing-the-mcp-server)

### I'm having a problem with the Visa server
1. Check: [Visa MCP Integration Guide - Troubleshooting](visa-mcp-integration-guide.md#troubleshooting)
2. If not found: [Visa MCP Integration Guide - Debug Logging](visa-mcp-integration-guide.md#debug-logging)
3. Still stuck: Check CloudWatch logs or contact support with the relevant section from the guide

### I want to understand the architecture
1. Read: [Visa Flask to MCP Migration - Executive Summary](visa-flask-to-mcp-migration.md#executive-summary)
2. Study: [Visa Flask to MCP Migration - Key Architectural Decisions](visa-flask-to-mcp-migration.md#key-architectural-decisions)
3. Review: [Visa MCP Integration Guide - Architecture](visa-mcp-integration-guide.md#architecture)

### I need to understand what changed
1. Start: [Visa Flask to MCP Migration - What Was Preserved](visa-flask-to-mcp-migration.md#what-was-preserved)
2. Review: [Visa Flask to MCP Migration - What Changed](visa-flask-to-mcp-migration.md#what-changed)
3. Check: [Visa Flask to MCP Migration - Complete Tool Mapping](visa-flask-to-mcp-migration.md#appendix-full-tool-mapping)

### I want to test a specific tool
1. Read: [Visa MCP Tools Reference - Tool Documentation](visa-mcp-tools-reference.md) (search for tool name)
2. Copy: Example code from tool documentation
3. Verify: [Visa MCP Integration Guide - Integration Testing](visa-mcp-integration-guide.md#integration-testing)

---

## Tool Quick Reference

### Tokenization & Onboarding
- [visa_get_secure_token](visa-mcp-tools-reference.md#tool-1-visa_get_secure_token) - Get OAuth token
- [visa_onboard_card](visa-mcp-tools-reference.md#tool-2-visa_onboard_card) - Enroll and provision card

### Device Security
- [visa_device_attestation](visa-mcp-tools-reference.md#tool-3-visa_device_attestation) - Verify device
- [visa_device_binding](visa-mcp-tools-reference.md#tool-4-visa_device_binding) - Bind device for passkeys
- [visa_step_up](visa-mcp-tools-reference.md#tool-5-visa_step_up) - Initiate step-up auth
- [visa_validate_otp](visa-mcp-tools-reference.md#tool-6-visa_validate_otp) - Validate OTP

### FIDO/Passkey
- [visa_complete_passkey](visa-mcp-tools-reference.md#tool-7-visa_complete_passkey) - Parse FIDO response

### VIC Payment Flow
- [visa_vic_enroll_card](visa-mcp-tools-reference.md#tool-8-visa_vic_enroll_card) - Enroll with VIC
- [visa_vic_initiate_purchase](visa-mcp-tools-reference.md#tool-9-visa_vic_initiate_purchase) - Create payment mandate
- [visa_vic_payment_credentials](visa-mcp-tools-reference.md#tool-10-visa_vic_payment_credentials) - Get cryptogram

---

## Key Concepts Explained

### Browser Data Strategy
See: [Visa MCP Tools Reference - Browser Data Strategy](visa-mcp-tools-reference.md#browser-data-strategy)
Also: [Visa Flask to MCP Migration - Browser Data Strategy](visa-flask-to-mcp-migration.md#decision-2-browser-data-strategy)

### Error Handling
See: [Visa MCP Tools Reference - Error Handling Patterns](visa-mcp-tools-reference.md#error-handling-patterns)
Code: Retry strategies and error classification

### Secrets Management
See: [Visa MCP Integration Guide - Secrets Manager Setup](visa-mcp-integration-guide.md#secrets-manager-setup)
Why: [Visa Flask to MCP Migration - Secrets Manager vs SSM](visa-flask-to-mcp-migration.md#decision-1-secrets-manager-vs-ssm-parameter-store)

### Complete Payment Flow
See: [Visa MCP Tools Reference - Complete Flow Example](visa-mcp-tools-reference.md#complete-flow-example)
7-step process combining multiple tools

### Rate Limiting
See: [Visa MCP Tools Reference - Rate Limiting & Quotas](visa-mcp-tools-reference.md#rate-limiting--quotas)
Typical Visa limits and recommended implementation

---

## AWS Setup Reference

### Secrets to Create
All stored under `visa/` path in AWS Secrets Manager:
1. `visa/api-key` - VTS API key
2. `visa/shared-secret` - VTS HMAC secret
3. `visa/encryption-api-key` - Encryption API key
4. `visa/encryption-shared-secret` - Encryption secret
5. `visa/server-mle-cert` - VIC server certificate (PEM)
6. `visa/mle-private-cert` - VIC private key (PEM)
7. `visa/vic_key_id` - VIC key identifier

See: [Visa MCP Integration Guide - Secrets Manager Setup](visa-mcp-integration-guide.md#secrets-manager-setup)

### CDK Deployment
Commands:
```bash
cdk bootstrap aws://ACCOUNT_ID/us-east-1
npm install
npm run build
cdk diff
cdk deploy VisaStack
```

See: [Visa MCP Integration Guide - CDK Deployment](visa-mcp-integration-guide.md#cdk-deployment)

### IAM Permissions
Template provided in: [Visa MCP Integration Guide - Required IAM Permissions](visa-mcp-integration-guide.md#required-iam-permissions)

---

## Testing Resources

### Local Testing
- [Visa MCP Integration Guide - Local Testing](visa-mcp-integration-guide.md#local-testing)

### Integration Testing
- [Visa MCP Integration Guide - Integration Testing](visa-mcp-integration-guide.md#integration-testing)

### Health Check
- [Visa MCP Integration Guide - Health Check](visa-mcp-integration-guide.md#health-check)

### Test Credentials
- [Visa MCP Tools Reference - Visa Test Credentials](visa-mcp-tools-reference.md#visa-test-credentials)

---

## Troubleshooting Guide

### By Error Type

#### Secrets Manager Issues
- [Issue 1: Secrets Manager Access Denied](visa-mcp-integration-guide.md#issue-1-secrets-manager-access-denied)

#### Token Issues
- [Issue 2: Invalid Secure Token](visa-mcp-integration-guide.md#issue-2-invalid-secure-token)

#### Card Onboarding Issues
- [Issue 3: Card Onboarding Fails](visa-mcp-integration-guide.md#issue-3-card-onboarding-fails)

#### Device Attestation Issues
- [Issue 4: Device Attestation Returns Empty Identifier](visa-mcp-integration-guide.md#issue-4-device-attestation-returns-empty-identifier)

#### OTP Issues
- [Issue 5: OTP Validation Fails](visa-mcp-integration-guide.md#issue-5-otp-validation-fails)

#### VIC Issues
- [Issue 6: VIC Enrollment Fails](visa-mcp-integration-guide.md#issue-6-vic-enrollment-fails)

#### Credential Issues
- [Issue 7: Payment Credentials Returns Invalid JWT](visa-mcp-integration-guide.md#issue-7-payment-credentials-returns-invalid-jwt)

---

## Support & Resources

### Internal Documentation
- [Visa MCP Tools Reference](visa-mcp-tools-reference.md) - Complete tool reference
- [Visa MCP Integration Guide](visa-mcp-integration-guide.md) - Deployment guide
- [Visa Flask to MCP Migration](visa-flask-to-mcp-migration.md) - Migration notes

### External Documentation
- [Visa Developer Portal](https://developer.visa.com/) - Official Visa docs
- [MCP Protocol Specification](https://modelcontextprotocol.io/) - MCP standard
- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/) - AWS docs
- [AWS CDK](https://docs.aws.amazon.com/cdk/) - Infrastructure as Code

### Contacts
- Technical Lead: [Name]
- DevOps: [Name]
- Visa Integration: [Name]

---

## Document Metadata

| Attribute | Value |
|-----------|-------|
| Created | 2026-02-06 |
| Last Updated | 2026-02-06 |
| Status | Production Ready |
| Version | 1.0 |
| Authors | AWS Solutions Architecture |
| Review Status | Complete |

---

## Document Version History

### v1.0 (2026-02-06)
- Initial documentation set
- 3 comprehensive documents
- 3,015 lines total
- 230 code examples
- All 10 tools documented
- 7 troubleshooting scenarios
- Migration documentation complete

---

## How to Use This Index

1. **If you're looking for something specific**: Use Ctrl+F to search this page
2. **If you know what you need**: Use the Quick Navigation section at the top
3. **If you're new**: Start with the "Common Tasks & Resources" section
4. **If you're deploying**: Go to the DevOps section in Quick Navigation
5. **If you're integrating**: Go to the Developers section in Quick Navigation

---

## Contributing to Documentation

If you find issues or need clarifications:
1. Check all three documents for existing information
2. Review the Troubleshooting sections
3. Check CloudWatch logs for runtime issues
4. Contact the technical lead with specific questions

---

**End of Index**

For more information, start with the document matching your role in the Quick Navigation section above.
