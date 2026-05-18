<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Contracts;

use CommonPHP\Authentication\AuthenticationResult;
use CommonPHP\Runtime\Contracts\DriverInterface;

interface AuthenticationDriverInterface extends DriverInterface
{
    public function supports(CredentialInterface $credentials): bool;

    public function authenticate(CredentialInterface $credentials): AuthenticationResult;
}
