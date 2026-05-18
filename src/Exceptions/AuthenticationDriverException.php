<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Exceptions;

use Throwable;

class AuthenticationDriverException extends AuthenticationException
{
    public static function forOperation(string $operation, ?string $driverName, Throwable $previous): self
    {
        $driver = $driverName === null ? 'authentication driver' : sprintf('authentication driver "%s"', $driverName);

        return new self(
            sprintf('Unable to %s with %s: %s', $operation, $driver, $previous->getMessage()),
            previous: $previous,
        );
    }

    public static function unsupportedCredentials(string $driverName): self
    {
        return new self(sprintf('Authentication driver "%s" does not support the provided credentials.', $driverName));
    }

    public static function invalidResult(string $driverName): self
    {
        return new self(sprintf('Authentication driver "%s" returned an invalid authentication result.', $driverName));
    }
}
