# Contributing

Thank you for helping make LLM Multiaccount Proxy safer and easier to operate.

Before starting a large change, open an issue describing the operator outcome,
the observable acceptance criteria, and the security impact. Keep provider
peculiarities in adapters and keep shared routing behavior provider-neutral.

Every behavior change should include a test that was observed failing before
the implementation. Pull requests should explain the RED and GREEN evidence,
threat-model impact, documentation impact, and any compatibility decision.

Use fake credentials and synthetic account identifiers in tests and examples.
Do not paste production configuration, traffic, tokens, certificates, or
database files into an issue or pull request.

