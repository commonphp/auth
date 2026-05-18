# Session State

```php
<?php

declare(strict_types=1);

use CommonPHP\Authentication\AuthenticationState;
use CommonPHP\Session\SessionManager;

$session = SessionManager::native();
$session->start();

$state = AuthenticationState::fromSession($session);

if ($result->isAuthenticated() && $result->identity() !== null) {
    $state->login($result->identity(), ['guard' => 'web']);
    $state->saveToSession($session);
    $session->save();
}
```

Auth stores only a simple state snapshot. Session startup, persistence, invalidation, and id regeneration remain session package responsibilities.
