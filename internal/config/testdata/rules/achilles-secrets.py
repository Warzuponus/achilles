# Tests for configs/rules/achilles-secrets.yaml (opengrep --test). Never run.
# Every value below is invented and grants access to nothing.
# "ruleid: X" says the next line must be reported by rule X; "ok: X" says it must not.
import os

# ruleid: achilles.generic.credentials-in-url
DATABASE_URL = "postgres://app:Zq8vLp2xWn4RtYs7@db.internal.example:5432/app"
# ruleid: achilles.generic.credentials-in-url
BROKER = "amqp://svc:Kp7Wm1Rt5Yb6Nc0H@mq.example.net/vhost"
# ok: achilles.generic.credentials-in-url
TEMPLATE_URL = "postgres://app:${DB_PASSWORD}@db:5432/app"
# ok: achilles.generic.credentials-in-url
DOC_URL = "postgres://user:password@localhost/db"
# ok: achilles.generic.credentials-in-url
NO_PASSWORD = "https://github.com/example/repo.git"
# ok: achilles.generic.credentials-in-url
FROM_ENV = os.environ["DATABASE_URL"]
# ok: achilles.generic.credentials-in-url
COMPOSE_DSN = "postgres://${POSTGRES_USER:-app}:${POSTGRES_PASSWORD:-dev-only}@postgres:5432/app"
# ok: achilles.generic.credentials-in-url
TEST_DSN = "postgres://postgres:test@localhost:5432/testdb?sslmode=disable"
# ok: achilles.generic.credentials-in-url
LOOPBACK = "redis://cache:Zq8vLp2xWn4RtYs7@127.0.0.1:6379/0"
# ruleid: achilles.generic.credentials-in-url
NOT_LOCAL = "redis://cache:Zq8vLp2xWn4RtYs7@localhost.attacker.example:6379/0"

# ruleid: achilles.generic.hardcoded-secret
STRIPE_SECRET_KEY = "sk_demo_9f3Kd82LmQx7Vb41ZhTr6WnA0cPe5YjU"
# ruleid: achilles.generic.hardcoded-secret
INTERNAL_API_TOKEN = "a8Fq2Lz9Xv3Kp7Wm1Rt5Yb6Nc0Hd4Sj8"
config = {
    # ruleid: achilles.generic.hardcoded-secret
    "client_secret": "Wn4RtYs7Zq8vLp2xKd82LmQx",
}
# ruleid: achilles.generic.hardcoded-secret
JWT_SECRET = "changeme-super-secret-signing-key-2024"
# ok: achilles.generic.hardcoded-secret
API_KEY = os.environ.get("API_KEY")
# ok: achilles.generic.hardcoded-secret
API_KEY_PLACEHOLDER = "your-api-key-here"
# ok: achilles.generic.hardcoded-secret
SECRET_NAME = "prod/payments/stripe-secret-key"
# ok: achilles.generic.hardcoded-secret
TOKEN_HEADER = "X-Internal-Authorization-Token"
# ok: achilles.generic.hardcoded-secret
password = "short"
# ok: achilles.generic.hardcoded-secret
ClassHardcodedSecret = "hardcoded-secret"
# ok: achilles.generic.hardcoded-secret
EnvMaxTokens = "ACHILLES_LLM_MAX_TOKENS"
# ruleid: achilles.generic.hardcoded-secret
AWS_SECRET_ACCESS_KEY = "AKIAQ3EGVZ7KDEXAMPL3"
# ruleid: achilles.generic.hardcoded-secret
DB_PASSWORD = "correcthorsebatterystaple"
