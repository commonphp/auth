# Getting Started

CommonPHP Auth authenticates a credential payload through a driver and returns an `AuthenticationResult`. Successful results update an `AuthenticationState`; expected login failures stay in result objects.

## Install

```bash
composer require comphp/auth
```

In this monorepo, the package is also available through the workspace path repository and the root Composer autoloader.

## Create Credentials

```php
<?php

declare(strict_types=1);

use CommonPHP\Authentication\Credentials;

$credentials = Credentials::password('ada@example.com', 'correct horse battery staple', [
    'ip' => '127.0.0.1',
]);
```

`Credentials::from()` also accepts common array keys:

```php
$credentials = Credentials::from([
    'email' => 'ada@example.com',
    'password' => 'secret',
    'attributes' => ['guard' => 'web'],
]);
```

## Authenticate

```php
<?php

use CommonPHP\Authentication\Authenticator;

$auth = new Authenticator();
$auth
    ->registerDriver(App\Auth\DatabaseAuthenticationDriver::class)
    ->mapDriver('database', App\Auth\DatabaseAuthenticationDriver::class, default: true);

$result = $auth->authenticate([
    'identifier' => 'ada@example.com',
    'password' => 'secret',
]);

if (!$result->isAuthenticated()) {
    return $result->message();
}

$identity = $auth->identity();
```

## Expected Failure Flow

Authentication failures such as invalid passwords or unknown identities should usually remain normal control flow:

```php
if ($result->status()->isCredentialFailure()) {
    return 'Check your credentials and try again.';
}
```

Use `throwIfFailed()` when the calling layer prefers package exceptions.
