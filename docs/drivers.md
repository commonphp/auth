# Drivers

Authentication drivers adapt a storage or identity source to Auth's small core contract.

## Contract

```php
use CommonPHP\Authentication\AuthenticationResult;
use CommonPHP\Authentication\Contracts\CredentialInterface;
use CommonPHP\Authentication\Contracts\AuthenticationDriverInterface;

final class DatabaseAuthenticationDriver implements AuthenticationDriverInterface
{
    public function getName(): string
    {
        return self::class;
    }

    public function supports(CredentialInterface $credentials): bool
    {
        return $credentials->hasSecret();
    }

    public function authenticate(CredentialInterface $credentials): AuthenticationResult
    {
        // Lookup user, verify secret, return a result.
    }
}
```

Most drivers should extend `AbstractAuthenticationDriver` for default `getName()`, default `supports()`, and helper methods.

## Registering Drivers

```php
$authenticator
    ->registerDriver(DatabaseAuthenticationDriver::class)
    ->mapDriver('database', DatabaseAuthenticationDriver::class, default: true);
```

The runtime driver container builds driver instances. Constructor options are passed through `mapDriver()`.

## Return Results For Expected Outcomes

Drivers should return result objects for normal authentication outcomes:

```php
return AuthenticationResult::invalidCredentials();
return AuthenticationResult::identityNotFound($credentials->identifier());
return AuthenticationResult::authenticated($identity);
```

Throw when infrastructure fails or the driver cannot continue. `Authenticator` wraps unexpected throwables in `AuthenticationDriverException`.
