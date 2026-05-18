<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Tests\Fixtures;

use CommonPHP\Authentication\Contracts\IdentityInterface;
use CommonPHP\Authentication\Contracts\IdentityProviderInterface;

final class ArrayIdentityProvider implements IdentityProviderInterface
{
    /**
     * @param array<string, IdentityInterface> $identities
     */
    public function __construct(private array $identities = [])
    {
    }

    public function add(IdentityInterface $identity): self
    {
        $this->identities[$identity->identifier()] = $identity;

        return $this;
    }

    public function findIdentity(string $identifier): ?IdentityInterface
    {
        return $this->identities[$identifier] ?? null;
    }
}
