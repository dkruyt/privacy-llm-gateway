"""Rule-id-only sensitive-content detectors (filled in at build step 3)."""

PERSONAL_RULES = ("email", "phone_intl", "phone_nl", "iban", "credit_card", "nl_bsn", "private_ip")
CREDENTIAL_RULES = (
    "pem_private_key", "aws_access_key", "github_token", "openai_style_key", "slack_token",
    "google_api_key", "stripe_key", "jwt", "bearer_token", "credential_assignment",
    "url_with_credentials",
)
ORG_RULES = ("internal_domain", "confidential_marker")
MANIPULATION_RULES = ("classifier_manipulation",)
ALL_STATIC_RULES = PERSONAL_RULES + CREDENTIAL_RULES + ORG_RULES + MANIPULATION_RULES


def detect_secrets_plugin_names() -> set[str]:
    return set()
