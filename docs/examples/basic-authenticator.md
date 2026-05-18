# Basic Authenticator

```php
<?php

declare(strict_types=1);

use CommonPHP\Authentication\Authenticator;
use CommonPHP\Authentication\Credentials;

$authenticator = new Authenticator();
$authenticator
    ->registerDriver(App\Auth\DatabaseAuthenticationDriver::class)
    ->mapDriver('database', App\Auth\DatabaseAuthenticationDriver::class, default: true);

$result = $authenticator->authenticate(
    Credentials::password('ada@example.com', 'secret'),
);

if (!$result->isAuthenticated()) {
    return $result->message();
}

$identity = $authenticator->identity();
$context = $authenticator->securityContext();
```

`AuthenticationResult` is the safest value to return to an application layer. It carries status, message, details, and the identity on success.
