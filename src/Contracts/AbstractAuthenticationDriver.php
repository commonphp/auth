<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Contracts;

use CommonPHP\Authentication\AuthenticationResult;
use Throwable;

abstract class AbstractAuthenticationDriver implements AuthenticationDriverInterface
{
    public function getName(): string
    {
        return static::class;
    }

    public function supports(CredentialInterface $credentials): bool
    {
        return true;
    }

    /**
     * @param array<string, mixed> $details
     */
    protected function authenticated(
        IdentityInterface $identity,
        ?string $message = null,
        array $details = [],
    ): AuthenticationResult {
        return AuthenticationResult::authenticated($identity, $message, $details);
    }

    /**
     * @param array<string, mixed> $details
     */
    protected function invalidCredentials(?string $message = null, array $details = []): AuthenticationResult
    {
        return AuthenticationResult::invalidCredentials($message, $details);
    }

    /**
     * @param array<string, mixed> $details
     */
    protected function identityNotFound(string $identifier, array $details = []): AuthenticationResult
    {
        return AuthenticationResult::identityNotFound($identifier, $details);
    }

    /**
     * @param array<string, mixed> $details
     */
    protected function failed(?string $message = null, array $details = []): AuthenticationResult
    {
        return AuthenticationResult::failed($message, $details);
    }

    /**
     * @param array<string, mixed> $details
     */
    protected function error(Throwable $throwable, ?string $message = null, array $details = []): AuthenticationResult
    {
        return AuthenticationResult::error($throwable, $message, $details);
    }
}
