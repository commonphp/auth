<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Exceptions;

class IdentityNotFoundException extends AuthenticationException
{
    public static function forIdentifier(string $identifier): self
    {
        return new self(sprintf('Identity "%s" was not found.', $identifier));
    }
}
