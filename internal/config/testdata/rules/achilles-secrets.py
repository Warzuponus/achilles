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
