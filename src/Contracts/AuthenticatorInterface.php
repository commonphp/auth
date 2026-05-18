<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Contracts;

use CommonPHP\Authentication\AuthenticationResult;
use CommonPHP\Authentication\AuthenticationState;
use CommonPHP\Security\SecurityContext;

interface AuthenticatorInterface
{
    /**
     * @param class-string<AuthenticationDriverInterface> $driverClass
     * @param array<string, mixed> $defaultOptions
     */
    public function registerDriver(string $driverClass, array $defaultOptions = []): static;

    /**
     * @param class-string<AuthenticationDriverInterface> $driverClass
     * @param array<string, mixed> $options
     */
    public function mapDriver(string $name, string $driverClass, array $options = [], bool $default = false): static;

    public function useDefaultDriver(string $name): static;

    /**
     * @param array<string, mixed>|CredentialInterface $credentials
     */
    public function authenticate(CredentialInterface|array $credentials, ?string $driverName = null): AuthenticationResult;

    /**
     * @param array<string, mixed>|CredentialInterface $credentials
     */
    public function attempt(CredentialInterface|array $credentials, ?string $driverName = null): bool;

    /**
     * @param array<string, mixed> $attributes
     */
    public function login(IdentityInterface $identity, array $attributes = []): static;

    public function logout(): static;

    public function state(): AuthenticationState;

    public function identity(): ?IdentityInterface;

    public function isAuthenticated(): bool;

    public function securityContext(): SecurityContext;
}
