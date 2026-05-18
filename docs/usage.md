# Usage

Auth is organized around four small pieces:

- `Credentials` describes what a caller presented.
- `AuthenticationDriverInterface` checks credentials against one source.
- `AuthenticationResult` describes the outcome.
- `AuthenticationState` stores the current identity.

## Manual Login

When a trusted layer already has an identity, it can log in directly:

```php
<?php

use CommonPHP\Authentication\AuthenticationState;
use CommonPHP\Authentication\Identity;

$state = AuthenticationState::guest();

$state->login(new Identity(
    'user-123',
    'Ada Lovelace',
    ['tenant' => 'example'],
    ['admin'],
    ['reports.read'],
));
```

## Driver Login

Drivers are registered once and mapped by name. The default driver is used when no name is passed to `authenticate()`.

```php
$authenticator
    ->registerDriver(App\Auth\DatabaseAuthenticationDriver::class)
    ->mapDriver('users', App\Auth\DatabaseAuthenticationDriver::class, [
        'connectionName' => 'default',
    ], default: true);

$result = $authenticator->authenticate(Credentials::password('ada', 'secret'));
```

## Multiple Guards

Use named drivers for separate credential sources:

```php
$authenticator
    ->registerDriver(App\Auth\UserPasswordDriver::class)
    ->registerDriver(App\Auth\ApiTokenDriver::class)
    ->mapDriver('web', App\Auth\UserPasswordDriver::class, default: true)
    ->mapDriver('api', App\Auth\ApiTokenDriver::class);

$web = $authenticator->authenticate($passwordCredentials, 'web');
$api = $authenticator->authenticate($tokenCredentials, 'api');
```

## Authorization Context

Successful identities can be converted into `comphp/security` contexts:

```php
$context = $authenticator->securityContext();

if ($context->hasPermission('reports.read')) {
    // Continue into an authorization-aware layer.
}
```

Auth only carries roles and permissions from identities. Policy decisions still belong to `comphp/security`.
