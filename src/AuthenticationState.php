<?php

declare(strict_types=1);

namespace CommonPHP\Authentication;

use CommonPHP\Authentication\Contracts\IdentityInterface;
use CommonPHP\Authentication\Exceptions\AuthenticationStateException;
use CommonPHP\Security\Contracts\SecurityContextInterface;
use CommonPHP\Security\Permission;
use CommonPHP\Security\Role;
use CommonPHP\Security\SecurityContext;
use CommonPHP\Session\Contracts\SessionInterface;
use DateTimeImmutable;
use Throwable;

final class AuthenticationState implements SecurityContextInterface
{
    public const SESSION_KEY = '_auth.state';

    private ?IdentityInterface $identity;

    private ?DateTimeImmutable $authenticatedAt;

    /**
     * @var array<string, mixed>
     */
    private array $attributes;

    /**
     * @param array<string, mixed> $attributes
     */
    public function __construct(
        ?IdentityInterface $identity = null,
        ?DateTimeImmutable $authenticatedAt = null,
        array $attributes = [],
    ) {
        if ($identity === null && $authenticatedAt !== null) {
            throw AuthenticationStateException::missingIdentity();
        }

        $this->identity = $identity;
        $this->authenticatedAt = $identity === null ? null : ($authenticatedAt ?? new DateTimeImmutable());
        $this->attributes = $attributes;
    }

    public static function guest(): self
    {
        return new self();
    }

    /**
     * @param array<string, mixed> $attributes
     */
    public static function authenticated(
        IdentityInterface $identity,
        array $attributes = [],
        ?DateTimeImmutable $authenticatedAt = null,
    ): self {
        return new self($identity, $authenticatedAt, $attributes);
    }

    public static function fromResult(AuthenticationResult $result): self
    {
        return $result->isAuthenticated() && $result->identity() !== null
            ? self::authenticated($result->identity())
            : self::guest();
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $authenticated = (bool) ($data['authenticated'] ?? false);

        if (!$authenticated) {
            return self::guest();
        }

        $identityData = $data['identity'] ?? null;

        if (!is_array($identityData)) {
            throw AuthenticationStateException::invalidSessionData(self::SESSION_KEY);
        }

        $identifier = $identityData['id'] ?? $identityData['identifier'] ?? null;

        if (!is_string($identifier) && !is_int($identifier)) {
            throw AuthenticationStateException::invalidSessionData(self::SESSION_KEY);
        }

        $attributes = $identityData['attributes'] ?? [];
        $roles = $identityData['roles'] ?? [];
        $permissions = $identityData['permissions'] ?? [];

        if (!is_array($attributes) || !is_array($roles) || !is_array($permissions)) {
            throw AuthenticationStateException::invalidSessionData(self::SESSION_KEY);
        }

        $authenticatedAt = null;
        $authenticatedAtValue = $data['authenticated_at'] ?? null;

        if (is_string($authenticatedAtValue) && $authenticatedAtValue !== '') {
            try {
                $authenticatedAt = new DateTimeImmutable($authenticatedAtValue);
            } catch (Throwable) {
                throw AuthenticationStateException::invalidSessionData(self::SESSION_KEY);
            }
        }

        $stateAttributes = $data['attributes'] ?? [];

        if (!is_array($stateAttributes)) {
            throw AuthenticationStateException::invalidSessionData(self::SESSION_KEY);
        }

        try {
            $identity = new Identity(
                $identifier,
                is_string($identityData['name'] ?? null) ? $identityData['name'] : null,
                $attributes,
                $roles,
                $permissions,
            );
        } catch (Throwable) {
            throw AuthenticationStateException::invalidSessionData(self::SESSION_KEY);
        }

        return self::authenticated($identity, $stateAttributes, $authenticatedAt);
    }

    public static function fromSession(SessionInterface $session, string $key = self::SESSION_KEY): self
    {
        $value = $session->get($key);

        if ($value === null) {
            return self::guest();
        }

        if ($value instanceof self) {
            return $value;
        }

        if (is_array($value)) {
            try {
                return self::fromArray($value);
            } catch (AuthenticationStateException) {
                throw AuthenticationStateException::invalidSessionData($key);
            }
        }

        throw AuthenticationStateException::invalidSessionData($key);
    }

    /**
     * @param array<string, mixed> $attributes
     */
    public function login(IdentityInterface $identity, array $attributes = []): static
    {
        $this->identity = $identity;
        $this->authenticatedAt = new DateTimeImmutable();
        $this->attributes = $attributes;

        return $this;
    }

    public function logout(): static
    {
        $this->identity = null;
        $this->authenticatedAt = null;
        $this->attributes = [];

        return $this;
    }

    public function apply(AuthenticationResult $result): static
    {
        if ($result->isAuthenticated() && $result->identity() !== null) {
            return $this->login($result->identity());
        }

        if ($result->status()->isGuest()) {
            return $this->logout();
        }

        return $this;
    }

    public function identity(): ?IdentityInterface
    {
        return $this->identity;
    }

    public function user(): ?IdentityInterface
    {
        return $this->identity;
    }

    public function authenticatedAt(): ?DateTimeImmutable
    {
        return $this->authenticatedAt;
    }

    public function isAuthenticated(): bool
    {
        return $this->identity !== null;
    }

    public function isGuest(): bool
    {
        return !$this->isAuthenticated();
    }

    public function roles(): array
    {
        return $this->identity?->roles() ?? [];
    }

    /**
     * @return list<string>
     */
    public function roleNames(): array
    {
        return $this->identity?->roleNames() ?? [];
    }

    public function permissions(): array
    {
        return $this->identity?->permissions() ?? [];
    }

    public function directPermissions(): array
    {
        return $this->identity?->directPermissions() ?? [];
    }

    public function hasRole(Role|string $role): bool
    {
        return $this->identity?->hasRole($role) ?? false;
    }

    public function hasPermission(Permission|string $permission): bool
    {
        return $this->identity?->hasPermission($permission) ?? false;
    }

    public function setAttribute(string $key, mixed $value): static
    {
        $this->attributes[$key] = $value;

        return $this;
    }

    public function removeAttribute(string $key): static
    {
        unset($this->attributes[$key]);

        return $this;
    }

    public function attribute(string $key, mixed $default = null): mixed
    {
        $attributes = $this->attributes();

        return array_key_exists($key, $attributes) ? $attributes[$key] : $default;
    }

    public function hasAttribute(string $key): bool
    {
        return array_key_exists($key, $this->attributes());
    }

    public function attributes(): array
    {
        return array_replace($this->identity?->attributes() ?? [], $this->attributes);
    }

    public function securityContext(): SecurityContext
    {
        if ($this->identity === null) {
            return SecurityContext::guest();
        }

        return SecurityContext::forIdentity(
            $this->identity,
            $this->roles(),
            $this->permissions(),
            $this->attributes(),
        );
    }

    public function saveToSession(SessionInterface $session, string $key = self::SESSION_KEY): static
    {
        $session->set($key, $this->toArray());

        return $this;
    }

    public function clearSession(SessionInterface $session, string $key = self::SESSION_KEY): static
    {
        $session->remove($key);

        return $this;
    }

    /**
     * @return array{
     *     authenticated: bool,
     *     authenticated_at: ?string,
     *     identity: ?array{id: string, name: ?string, attributes: array<string, mixed>, roles: list<string>, permissions: list<string>},
     *     attributes: array<string, mixed>
     * }
     */
    public function toArray(): array
    {
        return [
            'authenticated' => $this->isAuthenticated(),
            'authenticated_at' => $this->authenticatedAt?->format(DATE_ATOM),
            'identity' => $this->identity === null ? null : [
                'id' => $this->identity->id(),
                'name' => $this->identity->name(),
                'attributes' => $this->identity->attributes(),
                'roles' => $this->identity->roleNames(),
                'permissions' => $this->identity->directPermissionNames(),
            ],
            'attributes' => $this->attributes,
        ];
    }
}
