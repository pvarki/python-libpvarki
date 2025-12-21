# libpvarki.auditlogging

`libpvarki` module for providing structured audit logging compliant with organizational requirements.

## Structure

```
auditlogging/
├── README.md
├── src/
│   └── libpvarki/
│       └── auditlogging/
│           ├── __init__.py      # Public API, AUDIT level setup
│           ├── context.py       # ContextVars for async-safe request context
│           ├── middleware.py    # FastAPI AuditMiddleware
│           ├── helpers.py       # audit_log() and convenience functions
│           ├── propagation.py   # Service-to-service header propagation
│           └── py.typed         # PEP 561 marker
└── tests/
    └── test_auditlogging.py
```

## Installation

Copy the `auditlogging/` directory into `libpvarki/src/libpvarki/`:

```bash
cp -r src/libpvarki/auditlogging /path/to/python-libpvarki/src/libpvarki/
cp tests/test_auditlogging.py /path/to/python-libpvarki/tests/
```

### Prerequisites

Requires libadvian with MR #15 for native AUDIT level. Until merged:

```toml
# pyproject.toml
[tool.poetry.dependencies]
libadvian = { git = "https://gitlab.com/advian-oss/python-libadvian.git", branch = "log_levels" }
```

The module includes a fallback that adds AUDIT level if libadvian doesn't have it yet.

## Integration with Existing Stack

```
libadvian.logging        ← MR #15 adds AUDIT level
       ↓
libpvarki.logging        ← ECS formatting via ecs-logging
       ↓
libpvarki.auditlogging   ← THIS MODULE
       ↓
rmapi / takrmapi / ocsprest / products
```

## Quick Start

### 1. Initialize in FastAPI app

```python
from fastapi import FastAPI
from libpvarki.auditlogging import init_audit, AuditMiddleware
import logging

app = FastAPI()
app.add_middleware(AuditMiddleware)

@app.on_event("startup")
async def startup():
    init_audit(logging.INFO)
```

### 2. Log audit events

```python
import logging
from libpvarki.auditlogging import audit_log

LOGGER = logging.getLogger(__name__)

LOGGER.audit(
    "Certificate issued for user",
    extra=audit_log(
        category="iam",
        action="cert_issue",
        outcome="success",
        target_user="NORPPA11",
        target_resource="DEADBEEF",  # cert serial
    )
)
```

### 3. Propagate context to downstream services

```python
from libpvarki.mtlshelp.session import get_session
from libpvarki.auditlogging import get_propagation_headers

session = await get_session(client_cert, client_key, ca_cert)
headers = get_propagation_headers()  # Includes X-Initiator-* headers
await session.post(url, json=data, headers=headers)
```

## Request Flow

```
User (NORPPA11) ─mTLS─► nginx ───► rmapi ───► takrmapi
                         │           │            │
                         │           │            └── Sees X-Initiator-User: NORPPA11
                         │           └── Extracts from X-ClientCert-DN
                         └── Sets X-ClientCert-DN: CN=NORPPA11
```

## Header Conventions

### nginx → service (direct mTLS)

```
X-Request-ID: <trace-id>
X-Real-IP: <client-ip>
X-ClientCert-DN: CN=<callsign>,O=PVARKI,C=FI
X-ClientCert-Serial: <cert-serial>
```

### service → service (propagation)

```
X-Request-ID: <trace-id>
X-Initiator-User: <callsign>
X-Initiator-IP: <client-ip>
X-Initiator-Role: <role>
X-Initiator-Cert-Serial: <cert-serial>
```

## nginx Configuration

```nginx
# In your nginx server block
proxy_set_header X-Request-ID $request_id;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-ClientCert-DN $ssl_client_s_dn;
proxy_set_header X-ClientCert-Serial $ssl_client_serial;
```

## Event Categories

| Category | Use For |
|----------|---------|
| `authentication` | Login, logout, OTP exchange, JWT validation |
| `authorization` | Permission checks, access denied |
| `iam` | Enrollment, cert issuance, revocation |
| `configuration` | Settings changes, admin actions |
| `session` | JWT creation, refresh, expiry |
| `intrusion_detection` | Failed attempts, anomalies |

## Convenience Functions

```python
from libpvarki.auditlogging import (
    audit_authentication,  # category="authentication"
    audit_iam,             # category="iam"
    audit_authorization,   # category="authorization"
    audit_configuration,   # category="configuration"
    audit_session,         # category="session"
    audit_anomaly,         # category="intrusion_detection", outcome="failure"
)

# Examples
LOGGER.audit("Login successful", extra=audit_authentication("login", outcome="success"))
LOGGER.audit("Cert issued", extra=audit_iam("cert_issue", target_user="NORPPA11"))
LOGGER.audit("Brute force detected", extra=audit_anomaly("brute_force", error_message="5 failed attempts"))
```

## ECS Output Example

With `LOG_CONSOLE_FORMATTER=ecs` (default), output is ECS-compliant JSON:

```json
{
  "@timestamp": "2025-12-21T00:00:00.000Z",
  "ecs.version": "1.6.0",
  "log.level": "AUDIT",
  "log.logger": "rasenmaeher_api.routes.token",
  "message": "OTP exchange successful for NORPPA11",
  "event.category": "authentication",
  "event.action": "otp_exchange",
  "event.outcome": "success",
  "source.ip": "203.0.113.50",
  "source.user.name": "NORPPA11",
  "tls.client.x509.serial_number": "DEADBEEF",
  "user.target.name": "NORPPA11",
  "trace.id": "abc-123-def-456",
  "service.name": "rmapi",
  "service.version": "1.6.4"
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_CONSOLE_FORMATTER` | `ecs` | `ecs` for JSON, `local` for human-readable |
| `SERVICE_NAME` | hostname | Service name in logs |
| `RELEASE_TAG` | `unknown` | Service version in logs |

## Testing

```bash
cd python-libpvarki
pytest tests/test_auditlogging.py -v
```

## Migration from init_logging

Replace `init_logging` with `init_audit` to enable AUDIT level:

```python
# Before
from libpvarki.logging import init_logging
init_logging(logging.INFO)

# After
from libpvarki.auditlogging import init_audit
init_audit(logging.INFO)
```

Or continue using `init_logging` - the AUDIT level is registered on module import.
