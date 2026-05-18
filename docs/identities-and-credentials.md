# Identities And Credentials

`Credentials` represent what a caller presented. `Identity` represents who was proven.

## Credentials

Credentials always have a normalized identifier and may have a secret:

```php
$credentials = Credentials::password(' ada ', 'secret');

$credentials->identifier(); // "ada"
$credentials->secret();     // "secret"
```

Array input is intentionally practical:

```php
Credentials::from(['username' => 'ada', 'password' => 'secret']);
Credentials::from(['email' => 'ada@example.com', 'token' => 'api-token']);
Credentials::from(['login' => 'service-account']);
```

Attributes carry request-local authentication details such as guard names, IP addresses, or token metadata. They should not be used for long-term user profile data.

## Identities

An identity has a stable identifier, optional display name, attributes, roles, and direct permissions:

```php
$identity = new Identity(
    'user-123',
    'Ada Lovelace',
    ['tenant' => 'example'],
    ['admin'],
    ['reports.read'],
);
```

Role permissions and direct permissions are both considered by `hasPermission()`:

```php
$identity->hasPermission('reports.read');
```

Use `directPermissions()` when persisting or inspecting only permissions granted directly to the identity.

## Immutability

`Identity` and `Credentials` are immutable. Methods such as `withAttribute()`, `withRole()`, and `withoutSecret()` return new instances.

```php
$safeCredentials = $credentials->withoutSecret();
```

This keeps authentication values easy to inspect and safe to pass between layers.
