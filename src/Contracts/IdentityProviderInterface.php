<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Contracts;

interface IdentityProviderInterface
{
    public function findIdentity(string $identifier): ?IdentityInterface;
}
