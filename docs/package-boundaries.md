# Package Boundaries

CommonPHP Auth should stay small, predictable, and centered on proving identity.

## In Scope

- Credential value objects.
- Identity value objects.
- Authentication result objects.
- Login state snapshots.
- Driver contracts and a driver-backed authenticator.
- Authentication-specific exceptions.

## Out Of Scope

- Password hashing policy. Use `comphp/security`.
- Authorization policies and access decisions. Use `comphp/security`.
- Session lifecycle management. Use `comphp/session`.
- HTTP request parsing, cookies, redirects, and login forms. Use HTTP/web packages.
- Database, LDAP, token, or external service persistence. Use driver packages.
- UI rendering and validation messages. Use UI and validation packages.

## Driver Boundary

Core Auth does not know where users live. A driver translates a credential into an `AuthenticationResult`:

```php
public function authenticate(CredentialInterface $credentials): AuthenticationResult;
```

Drivers can return expected failure results for invalid credentials and unknown identities. Infrastructure failures may throw and will be wrapped by `AuthenticationDriverException` when invoked through `Authenticator`.

## State Boundary

`AuthenticationState` stores a session-safe snapshot of the identity. It does not start, save, invalidate, or regenerate sessions. Those operations are owned by `comphp/session`.
