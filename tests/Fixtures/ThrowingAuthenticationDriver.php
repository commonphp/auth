<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Tests\Fixtures;

use CommonPHP\Authentication\AuthenticationResult;
use CommonPHP\Authentication\Contracts\AbstractAuthenticationDriver;
use CommonPHP\Authentication\Contracts\CredentialInterface;
use RuntimeException;

final class ThrowingAuthenticationDriver extends AbstractAuthenticationDriver
{
    public function authenticate(CredentialInterface $credentials): AuthenticationResult
    {
        throw new RuntimeException('Driver exploded.');
    }
}
