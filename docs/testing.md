# Testing And QA

The Auth package includes a package-local PHPUnit suite.

## Run Tests

From this package:

```bash
vendor/bin/phpunit
```

From the monorepo root on Windows:

```bash
vendor\bin\phpunit.bat -c package\auth\phpunit.xml.dist
```

## Coverage Areas

The unit suite covers:

- Credential normalization, factories, array input, attributes, and invalid payloads.
- Identity normalization, roles, direct and effective permissions, attributes, immutability, and serialization.
- Authentication statuses and labels.
- Authentication results, details, security contexts, error results, and exception conversion.
- Authentication state login/logout, result application, session snapshots, invalid session payloads, and security context behavior.
- Authenticator driver registration, mapping, default driver selection, named driver selection, expected driver failures, unsupported credentials, and unexpected driver exception wrapping.
- Contract implementations and exception factory messages.

## Test Fixtures

Fixtures live in `tests/Fixtures` and avoid external services. They model in-memory drivers, throwing drivers, identity providers, and a minimal session implementation.

Driver packages should add their own integration tests for database, LDAP, token, or external service behavior.
