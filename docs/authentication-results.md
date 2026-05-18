# Authentication Results

`AuthenticationResult` is the normal return value for authentication attempts.

## Successful Results

```php
$result = AuthenticationResult::authenticated($identity, 'Welcome.', [
    'driver' => 'database',
]);

$result->isAuthenticated(); // true
$result->identity();        // IdentityInterface
```

Successful results can produce a `SecurityContext` for authorization-aware code:

```php
$context = $result->securityContext();
```

## Expected Failures

Invalid credentials and unknown identities are expected outcomes:

```php
AuthenticationResult::invalidCredentials();
AuthenticationResult::identityNotFound('ada@example.com');
```

Use status checks in login flows:

```php
if ($result->status()->isCredentialFailure()) {
    return 'Invalid login.';
}
```

## Other Statuses

The package also models locked identities, expired credentials, generic failures, guest state, and infrastructure errors:

```php
AuthenticationResult::locked();
AuthenticationResult::expired();
AuthenticationResult::failed('Provider rejected the attempt.');
AuthenticationResult::error($throwable);
```

## Exceptions On Demand

Most callers should use result objects. If a layer needs exceptions, call:

```php
$result->throwIfFailed();
```

Credential failures become `InvalidCredentialsException` or `IdentityNotFoundException`; other failures become `AuthenticationException`.
