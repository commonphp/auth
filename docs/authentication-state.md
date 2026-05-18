# Authentication State

`AuthenticationState` tracks the current identity and exposes the `SecurityContextInterface` read methods used by `comphp/security`.

## Guest State

```php
$state = AuthenticationState::guest();

$state->isGuest();          // true
$state->isAuthenticated();  // false
```

## Authenticated State

```php
$state = AuthenticationState::authenticated($identity, [
    'guard' => 'web',
]);

$state->identity();
$state->authenticatedAt();
$state->hasRole('admin');
$state->hasPermission('reports.read');
```

State attributes are layered over identity attributes. This lets a login flow attach request-specific details without changing the identity object.

## Applying Results

```php
$state->apply($result);
```

Authenticated results log in the returned identity. Guest results log out. Failure results leave the current state unchanged.

## Session Snapshots

Auth state can save a session-safe array into a `SessionInterface`:

```php
$state->saveToSession($session);

$state = AuthenticationState::fromSession($session);
```

The state object does not start or save the session lifecycle. Callers should use `comphp/session` for that.
