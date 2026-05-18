<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Exceptions;

use RuntimeException;
use Throwable;

class AuthenticationException extends RuntimeException
{
    public static function invalidIdentifier(string $identifier, string $reason): self
    {
        return new self(sprintf('Invalid authentication identifier "%s": %s', $identifier, $reason));
    }

    public static function invalidAttributeKey(string $key): self
    {
        return new self(sprintf('Invalid authentication attribute key "%s": keys cannot be empty.', $key));
    }

    public static function invalidCredentialsShape(string $reason, ?Throwable $previous = null): self
    {
        return new self('Invalid credential payload: ' . $reason, previous: $previous);
    }
}
