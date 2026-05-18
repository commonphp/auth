<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Exceptions;

use Throwable;

class InvalidCredentialsException extends AuthenticationException
{
    public static function forIdentifier(?string $identifier = null, ?Throwable $previous = null): self
    {
        $message = $identifier === null
            ? 'Invalid credentials.'
            : sprintf('Invalid credentials for "%s".', $identifier);

        return new self($message, previous: $previous);
    }
}
