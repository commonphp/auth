<?php

declare(strict_types=1);

namespace CommonPHP\Authentication;

use CommonPHP\Authentication\Contracts\IdentityInterface;
use CommonPHP\Authentication\Enums\AuthenticationStatus;
use CommonPHP\Authentication\Exceptions\AuthenticationException;
use CommonPHP\Authentication\Exceptions\AuthenticationStateException;
use CommonPHP\Authentication\Exceptions\IdentityNotFoundException;
use CommonPHP\Authentication\Exceptions\InvalidCredentialsException;
use CommonPHP\Security\SecurityContext;
use Throwable;

final readonly class AuthenticationResult
{
    /**
     * @param array<string, mixed> $details
     */
    public function __construct(
        private AuthenticationStatus $status,
        private ?IdentityInterface $identity = null,
        private ?string $message = null,
        private array $details = [],
        private ?Throwable $throwable = null,
    ) {
        if ($this->status->isAuthenticated() && $this->identity === null) {
            throw AuthenticationStateException::missingIdentity();
        }
    }

    /**
     * @param array<string, mixed> $details
     */
    public static function authenticated(
        IdentityInterface $identity,
        ?string $message = null,
        array $details = [],
    ): self {
        return new self(AuthenticationStatus::Authenticated, $identity, $message, $details);
    }

    /**
     * @param array<string, mixed> $details
     */
    public static function guest(?string $message = null, array $details = []): self
    {
        return new self(AuthenticationStatus::Guest, message: $message, details: $details);
    }

    /**
     * @param array<string, mixed> $details
     */
    public static function failed(?string $message = null, array $details = []): self
    {
        return new self(AuthenticationStatus::Failed, message: $message ?? 'Authentication failed.', details: $details);
    }

    /**
     * @param array<string, mixed> $details
     */
    public static function invalidCredentials(?string $message = null, array $details = [], ?Throwable $throwable = null): self
    {
        return new self(
            AuthenticationStatus::InvalidCredentials,
            message: $message ?? 'Invalid credentials.',
            details: $details,
            throwable: $throwable,
        );
    }

    /**
     * @param array<string, mixed> $details
     */
    public static function identityNotFound(string $identifier, array $details = [], ?Throwable $throwable = null): self
    {
        $details['identifier'] ??= $identifier;

        return new self(
            AuthenticationStatus::IdentityNotFound,
            message: sprintf('Identity "%s" was not found.', $identifier),
            details: $details,
            throwable: $throwable,
        );
    }

    /**
     * @param array<string, mixed> $details
     */
    public static function locked(?string $message = null, array $details = []): self
    {
        return new self(AuthenticationStatus::Locked, message: $message ?? 'Identity is locked.', details: $details);
    }

    /**
     * @param array<string, mixed> $details
     */
    public static function expired(?string $message = null, array $details = []): self
    {
        return new self(AuthenticationStatus::Expired, message: $message ?? 'Credentials are expired.', details: $details);
    }

    /**
     * @param array<string, mixed> $details
     */
    public static function error(Throwable $throwable, ?string $message = null, array $details = []): self
    {
        return new self(
            AuthenticationStatus::Error,
            message: $message ?? $throwable->getMessage(),
            details: $details,
            throwable: $throwable,
        );
    }

    public function status(): AuthenticationStatus
    {
        return $this->status;
    }

    public function identity(): ?IdentityInterface
    {
        return $this->identity;
    }

    public function message(): ?string
    {
        return $this->message;
    }

    public function detail(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->details) ? $this->details[$key] : $default;
    }

    public function hasDetail(string $key): bool
    {
        return array_key_exists($key, $this->details);
    }

    /**
     * @return array<string, mixed>
     */
    public function details(): array
    {
        return $this->details;
    }

    public function throwable(): ?Throwable
    {
        return $this->throwable;
    }

    public function isAuthenticated(): bool
    {
        return $this->status->isAuthenticated();
    }

    public function isFailure(): bool
    {
        return $this->status->isFailure();
    }

    public function withDetail(string $key, mixed $value): self
    {
        $details = $this->details;
        $details[$key] = $value;

        return new self($this->status, $this->identity, $this->message, $details, $this->throwable);
    }

    public function withoutDetail(string $key): self
    {
        $details = $this->details;
        unset($details[$key]);

        return new self($this->status, $this->identity, $this->message, $details, $this->throwable);
    }

    public function securityContext(): SecurityContext
    {
        if (!$this->isAuthenticated() || $this->identity === null) {
            return SecurityContext::guest();
        }

        return SecurityContext::forIdentity(
            $this->identity,
            $this->identity->roles(),
            $this->identity->directPermissions(),
            $this->identity->attributes(),
        );
    }

    public function throwIfFailed(): void
    {
        if (!$this->isFailure()) {
            return;
        }

        $message = $this->message ?? $this->status->label();

        throw match ($this->status) {
            AuthenticationStatus::InvalidCredentials => new InvalidCredentialsException(
                $message,
                previous: $this->throwable,
            ),
            AuthenticationStatus::IdentityNotFound => new IdentityNotFoundException(
                $message,
                previous: $this->throwable,
            ),
            default => new AuthenticationException($message, previous: $this->throwable),
        };
    }
}
