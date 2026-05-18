<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Contracts;

interface CredentialInterface
{
    public function identifier(): string;

    public function secret(): ?string;

    public function hasSecret(): bool;

    public function attribute(string $key, mixed $default = null): mixed;

    public function hasAttribute(string $key): bool;

    /**
     * @return array<string, mixed>
     */
    public function attributes(): array;
}
