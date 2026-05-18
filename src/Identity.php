<?php

declare(strict_types=1);

namespace CommonPHP\Authentication;

use CommonPHP\Authentication\Contracts\IdentityInterface;
use CommonPHP\Authentication\Exceptions\AuthenticationException;
use CommonPHP\Security\Permission;
use CommonPHP\Security\Role;
use Stringable;

final readonly class Identity implements IdentityInterface, Stringable
{
    public const int MAX_IDENTIFIER_LENGTH = 191;

    private string $identifier;

    private ?string $name;

    /**
     * @var array<string, mixed>
     */
    private array $attributes;

    /**
     * @var array<string, Role>
     */
    private array $roles;

    /**
     * @var array<string, Permission>
     */
    private array $permissions;

    /**
     * @param iterable<Role|string> $roles
     * @param iterable<Permission|string> $permissions
     * @param array<string, mixed> $attributes
     */
    public function __construct(
        string|int|Stringable $identifier,
        ?string $name = null,
        array $attributes = [],
        iterable $roles = [],
        iterable $permissions = [],
    ) {
        $this->identifier = self::normalizeIdentifier((string) $identifier);
        $this->name = self::normalizeName($name);
        $this->attributes = self::normalizeAttributes($attributes);
        $this->roles = self::normalizeRoles($roles);
        $this->permissions = self::normalizePermissions($permissions);
    }

    public static function from(IdentityInterface|string|int|Stringable $identity): IdentityInterface
    {
        return $identity instanceof IdentityInterface ? $identity : new self($identity);
    }

    public function id(): string
    {
        return $this->identifier;
    }

    public function identifier(): string
    {
        return $this->identifier;
    }

    public function name(): ?string
    {
        return $this->name;
    }

    public function displayName(): string
    {
        return $this->name ?? $this->identifier;
    }

    public function hasRole(Role|string $role): bool
    {
        return isset($this->roles[Role::from($role)->name()]);
    }

    public function roles(): array
    {
        return array_map(static fn (Role $role): Role => clone $role, array_values($this->roles));
    }

    public function roleNames(): array
    {
        return array_keys($this->roles);
    }

    public function hasPermission(Permission|string $permission): bool
    {
        $permission = Permission::from($permission);

        if (isset($this->permissions[$permission->value()])) {
            return true;
        }

        foreach ($this->roles as $role) {
            if ($role->hasPermission($permission)) {
                return true;
            }
        }

        return false;
    }

    public function permissions(): array
    {
        $permissions = $this->permissions;

        foreach ($this->roles as $role) {
            foreach ($role->permissions() as $permission) {
                $permissions[$permission->value()] = $permission;
            }
        }

        return array_values($permissions);
    }

    public function directPermissions(): array
    {
        return array_values($this->permissions);
    }

    public function permissionNames(): array
    {
        return array_map(static fn (Permission $permission): string => $permission->value(), $this->permissions());
    }

    public function directPermissionNames(): array
    {
        return array_keys($this->permissions);
    }

    public function attribute(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->attributes) ? $this->attributes[$key] : $default;
    }

    public function hasAttribute(string $key): bool
    {
        return array_key_exists($key, $this->attributes);
    }

    public function attributes(): array
    {
        return $this->attributes;
    }

    public function withAttribute(string $key, mixed $value): self
    {
        $attributes = $this->attributes;
        $attributes[self::normalizeAttributeKey($key)] = $value;

        return new self($this->identifier, $this->name, $attributes, $this->roles, $this->permissions);
    }

    public function withoutAttribute(string $key): self
    {
        $attributes = $this->attributes;
        unset($attributes[$key]);

        return new self($this->identifier, $this->name, $attributes, $this->roles, $this->permissions);
    }

    public function withRole(Role|string $role, Role|string ...$roles): self
    {
        $normalized = $this->roles;

        foreach ([$role, ...$roles] as $entry) {
            $next = Role::from($entry);
            $normalized[$next->name()] = clone $next;
        }

        return new self($this->identifier, $this->name, $this->attributes, $normalized, $this->permissions);
    }

    public function withoutRole(Role|string $role): self
    {
        $roles = $this->roles;
        unset($roles[Role::from($role)->name()]);

        return new self($this->identifier, $this->name, $this->attributes, $roles, $this->permissions);
    }

    public function withPermission(Permission|string $permission, Permission|string ...$permissions): self
    {
        $normalized = $this->permissions;

        foreach ([$permission, ...$permissions] as $entry) {
            $next = Permission::from($entry);
            $normalized[$next->value()] = $next;
        }

        return new self($this->identifier, $this->name, $this->attributes, $this->roles, $normalized);
    }

    public function withoutPermission(Permission|string $permission): self
    {
        $permissions = $this->permissions;
        unset($permissions[Permission::from($permission)->value()]);

        return new self($this->identifier, $this->name, $this->attributes, $this->roles, $permissions);
    }

    /**
     * @return array{
     *     id: string,
     *     name: ?string,
     *     attributes: array<string, mixed>,
     *     roles: list<string>,
     *     permissions: list<string>
     * }
     */
    public function toArray(): array
    {
        return [
            'id' => $this->identifier,
            'name' => $this->name,
            'attributes' => $this->attributes,
            'roles' => $this->roleNames(),
            'permissions' => $this->directPermissionNames(),
        ];
    }

    public function __toString(): string
    {
        return $this->identifier;
    }

    private static function normalizeIdentifier(string $identifier): string
    {
        $identifier = trim($identifier);

        if ($identifier === '') {
            throw AuthenticationException::invalidIdentifier($identifier, 'identities cannot use an empty identifier.');
        }

        if (strlen($identifier) > self::MAX_IDENTIFIER_LENGTH) {
            throw AuthenticationException::invalidIdentifier(
                $identifier,
                'identifiers cannot be longer than ' . self::MAX_IDENTIFIER_LENGTH . ' bytes.',
            );
        }

        return $identifier;
    }

    private static function normalizeName(?string $name): ?string
    {
        if ($name === null) {
            return null;
        }

        $name = trim($name);

        return $name === '' ? null : $name;
    }

    /**
     * @param array<string, mixed> $attributes
     * @return array<string, mixed>
     */
    private static function normalizeAttributes(array $attributes): array
    {
        $normalized = [];

        foreach ($attributes as $key => $value) {
            if (!is_string($key)) {
                throw AuthenticationException::invalidCredentialsShape('identity attribute keys must be strings.');
            }

            $normalized[self::normalizeAttributeKey($key)] = $value;
        }

        return $normalized;
    }

    private static function normalizeAttributeKey(string $key): string
    {
        $key = trim($key);

        if ($key === '') {
            throw AuthenticationException::invalidAttributeKey($key);
        }

        return $key;
    }

    /**
     * @param iterable<Role|string> $roles
     * @return array<string, Role>
     */
    private static function normalizeRoles(iterable $roles): array
    {
        $normalized = [];

        foreach ($roles as $role) {
            $next = Role::from($role);
            $normalized[$next->name()] = clone $next;
        }

        return $normalized;
    }

    /**
     * @param iterable<Permission|string> $permissions
     * @return array<string, Permission>
     */
    private static function normalizePermissions(iterable $permissions): array
    {
        $normalized = [];

        foreach ($permissions as $permission) {
            $next = Permission::from($permission);
            $normalized[$next->value()] = $next;
        }

        return $normalized;
    }
}
