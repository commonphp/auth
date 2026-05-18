# Custom Driver

```php
<?php

declare(strict_types=1);

namespace App\Auth;

use CommonPHP\Authentication\AuthenticationResult;
use CommonPHP\Authentication\Contracts\AbstractAuthenticationDriver;
use CommonPHP\Authentication\Contracts\CredentialInterface;
use CommonPHP\Authentication\Identity;

final class ArrayAuthenticationDriver extends AbstractAuthenticationDriver
{
    /**
     * @param array<string, string> $passwords
     */
    public function __construct(private array $passwords)
    {
    }

    public function supports(CredentialInterface $credentials): bool
    {
        return $credentials->hasSecret();
    }

    public function authenticate(CredentialInterface $credentials): AuthenticationResult
    {
        $identifier = $credentials->identifier();

        if (!array_key_exists($identifier, $this->passwords)) {
            return $this->identityNotFound($identifier);
        }

        if ($this->passwords[$identifier] !== $credentials->secret()) {
            return $this->invalidCredentials();
        }

        return $this->authenticated(new Identity($identifier));
    }
}
```

Real drivers should use a password hasher from `comphp/security` or the platform password APIs instead of comparing plain text secrets.
