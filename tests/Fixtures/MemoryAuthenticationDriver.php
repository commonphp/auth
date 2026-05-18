<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Tests\Fixtures;

use CommonPHP\Authentication\AuthenticationResult;
use CommonPHP\Authentication\Contracts\AbstractAuthenticationDriver;
use CommonPHP\Authentication\Contracts\CredentialInterface;
use CommonPHP\Authentication\Contracts\IdentityInterface;
use CommonPHP\Authentication\Identity;

final class MemoryAuthenticationDriver extends AbstractAuthenticationDriver
{
    public int $attempts = 0;

    public ?CredentialInterface $lastCredentials = null;

    /**
     * @param array<string, IdentityInterface> $identities
     */
    public function __construct(
        private string $name = 'memory',
        private array $identities = [],
        private string $expectedSecret = 'secret',
    ) {
        if ($this->identities === []) {
            $this->identities['ada'] = new Identity(
                'ada',
                'Ada Lovelace',
                ['tenant' => 'example'],
                ['admin'],
                ['reports.read'],
            );
        }
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function supports(CredentialInterface $credentials): bool
    {
        return !$credentials->hasAttribute('unsupported');
    }

    public function authenticate(CredentialInterface $credentials): AuthenticationResult
    {
        $this->attempts++;
        $this->lastCredentials = $credentials;

        if (!isset($this->identities[$credentials->identifier()])) {
            return AuthenticationResult::identityNotFound($credentials->identifier());
        }

        if ($credentials->secret() !== $this->expectedSecret) {
            return AuthenticationResult::invalidCredentials('Invalid memory credentials.');
        }

        return AuthenticationResult::authenticated(
            $this->identities[$credentials->identifier()],
            'Authenticated by memory.',
            ['driver' => $this->name],
        );
    }
}
