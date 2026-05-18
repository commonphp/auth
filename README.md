# CommonPHP Auth

CommonPHP Auth provides authentication-focused contracts and services for CommonPHP applications. It defines the pieces needed to identify users, authenticate credentials, and connect authentication sources through driver-based implementations.

The package is focused on proving identity while allowing authorization, sessions, HTTP login flows, and storage drivers to remain separate or optional integrations.

## Requirements

- PHP `^8.5`
- `comphp/runtime:^0.3`

## Installation

Once this package is available through your Composer repositories, install it with:

```bash
composer require comphp/auth
```

## Usage

```php
<?php

// TODO: Write usage
```

## Package Notes

This package should focus on authentication flows, authentication drivers, identity providers, and login state. Authorization and broader protection concerns belong in `comphp/security`.

## Error Handling

Authentication failures should be represented with package-specific exceptions or result objects rather than generic runtime failures.

## Documentation

- [Documentation index](docs/index.md)
- [Usage](docs/usage.md)
- [Testing](TESTING.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

## License

MIT. See [LICENSE.md](LICENSE.md).
