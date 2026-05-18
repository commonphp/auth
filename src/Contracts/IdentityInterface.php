<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Contracts;

use CommonPHP\Security\Permission;
use CommonPHP\Security\Role;

interface IdentityInterface
{
    public function id(): string;

    public function identifier(): string;

    public function name(): ?string;

    public function displayName(): string;

    public function hasRole(Role|string $role): bool;

    /**
     * @return list<Role>
     */
    public function roles(): array;

    /**
     * @return list<string>
     */
    public function roleNames(): array;

    public function hasPermission(Permission|string $permission): bool;

    /**
     * @return list<Permission>
     */
    public function permissions(): array;

    /**
     * @return list<Permission>
     */
    public function directPermissions(): array;

    /**
     * @return list<string>
     */
    public function permissionNames(): array;

    /**
     * @return list<string>
     */
    public function directPermissionNames(): array;

    public function attribute(string $key, mixed $default = null): mixed;

    public function hasAttribute(string $key): bool;

    /**
     * @return array<string, mixed>
     */
    public function attributes(): array;
}
