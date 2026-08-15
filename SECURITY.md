# Security

Report suspected vulnerabilities privately to the repository owner. Do not open a public issue containing credentials, customer data, exploit details, or audit records.

The application validates and sanitizes external input, verifies Firebase tokens server-side, rate-limits intake operations, validates Ollama structured output, fails closed when required configuration is absent, and redacts sensitive values from audit events. AI output is untrusted and cannot authorize external actions.

Keep `.env.local`, Firebase service-account files, signing keys, customer data, and JSONL audit logs outside Git. Use least-privilege workload identity or securely mounted credentials in production. Rotate any credential suspected of exposure.
