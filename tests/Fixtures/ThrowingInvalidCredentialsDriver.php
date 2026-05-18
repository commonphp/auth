<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Tests\Fixtures;

use CommonPHP\Authentication\AuthenticationResult;
use CommonPHP\Authentication\Contracts\AbstractAuthenticationDriver;
use CommonPHP\Authentication\Contracts\CredentialInterface;
use CommonPHP\Authentication\Exceptions\InvalidCredentialsException;

final class ThrowingInvalidCredentialsDriver extends AbstractAuthenticationDriver
{
    public function authenticate(CredentialInterface $credentials): AuthenticationResult
    {
        throw InvalidCredentialsException::forIdentifier($credentials->identifier());
    }
}
