# CommonPHP Auth Documentation

CommonPHP Auth is the authentication package for CommonPHP applications and plain PHP projects. It provides credential and identity value objects, result-oriented authentication flow, login state helpers, and driver contracts for database, LDAP, API token, or custom authentication sources.

Auth proves identity. It intentionally does not own authorization policies, password hashing, sessions, HTTP requests, routing, or persistence. Those concerns stay in `comphp/security`, `comphp/session`, HTTP/web packages, and driver packages.

## Start Here

- [Getting started](getting-started.md)
- [Usage](usage.md)
- [Package boundaries](package-boundaries.md)

## Authentication Concepts

- [Identities and credentials](identities-and-credentials.md)
- [Authentication results](authentication-results.md)
- [Authentication state](authentication-state.md)
- [Drivers](drivers.md)
- [Error handling](error-handling.md)

## Examples

- [Examples index](examples/index.md)
- [Basic authenticator](examples/basic-authenticator.md)
- [Session state](examples/session-state.md)
- [Custom driver](examples/custom-driver.md)

## Development

- [Testing and QA](testing.md)

## Public API Map

Entry points:

- `CommonPHP\Authentication\Authenticator`
- `CommonPHP\Authentication\AuthenticationState`

Value and result objects:

- `CommonPHP\Authentication\Credentials`
- `CommonPHP\Authentication\Identity`
- `CommonPHP\Authentication\AuthenticationResult`
- `CommonPHP\Authentication\Enums\AuthenticationStatus`

Contracts:

- `CommonPHP\Authentication\Contracts\AuthenticatorInterface`
- `CommonPHP\Authentication\Contracts\AuthenticationDriverInterface`
- `CommonPHP\Authentication\Contracts\AbstractAuthenticationDriver`
- `CommonPHP\Authentication\Contracts\CredentialInterface`
- `CommonPHP\Authentication\Contracts\IdentityInterface`
- `CommonPHP\Authentication\Contracts\IdentityProviderInterface`

Exceptions:

- `CommonPHP\Authentication\Exceptions\AuthenticationException`
- `CommonPHP\Authentication\Exceptions\AuthenticationDriverException`
- `CommonPHP\Authentication\Exceptions\AuthenticationStateException`
- `CommonPHP\Authentication\Exceptions\IdentityNotFoundException`
- `CommonPHP\Authentication\Exceptions\InvalidCredentialsException`
