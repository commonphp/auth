<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Exceptions;

class AuthenticationStateException extends AuthenticationException
{
    public static function missingIdentity(): self
    {
        return new self('Authenticated state requires an identity.');
    }

    public static function invalidSessionData(string $key): self
    {
        return new self(sprintf('Session value "%s" does not contain a valid authentication state.', $key));
    }
}
