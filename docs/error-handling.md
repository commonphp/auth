# Error Handling

Auth separates expected login failures from exceptional failures.

## Expected Failures

These should usually return `AuthenticationResult` objects:

- Unknown identity.
- Invalid password or token.
- Locked identity.
- Expired credential.
- Provider rejected credentials.

```php
$result = $authenticator->authenticate($credentials);

if ($result->isFailure()) {
    return $result->message();
}
```

## Exceptions

Exceptions are used for invalid setup, invalid state, malformed payloads, or infrastructure failures:

- `AuthenticationException`
- `AuthenticationDriverException`
- `AuthenticationStateException`
- `IdentityNotFoundException`
- `InvalidCredentialsException`

`Authenticator` converts driver-thrown `InvalidCredentialsException` and `IdentityNotFoundException` into result objects. Unexpected driver errors are wrapped as `AuthenticationDriverException`.

## Throwing From Results

Call `throwIfFailed()` when exception-based control flow is desired:

```php
$result->throwIfFailed();
```

This keeps lower-level authentication code result-oriented while allowing higher-level application code to opt into exceptions.
