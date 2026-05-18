<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Tests\Fixtures;

use BadMethodCallException;
use CommonPHP\Session\Contracts\FlashBagInterface;
use CommonPHP\Session\Contracts\SessionBagInterface;
use CommonPHP\Session\Contracts\SessionInterface;
use CommonPHP\Session\Enums\SessionStatus;

final class ArraySession implements SessionInterface
{
    /**
     * @param array<string, mixed> $values
     */
    public function __construct(
        private array $values = [],
        private bool $started = true,
        private string $id = 'array-session',
        private string $name = 'ARRAYSESSID',
    ) {
    }

    public function start(): static
    {
        $this->started = true;

        return $this;
    }

    public function save(): static
    {
        $this->started = false;

        return $this;
    }

    public function invalidate(): static
    {
        $this->values = [];
        $this->started = false;

        return $this;
    }

    public function regenerateId(bool $deleteOldSession = true): string
    {
        $this->id .= '-regenerated';

        return $this->id;
    }

    public function status(): SessionStatus
    {
        return $this->started ? SessionStatus::Active : SessionStatus::None;
    }

    public function isStarted(): bool
    {
        return $this->started;
    }

    public function id(): string
    {
        return $this->id;
    }

    public function setId(string $id): static
    {
        $this->id = $id;

        return $this;
    }

    public function name(): string
    {
        return $this->name;
    }

    public function setName(string $name): static
    {
        $this->name = $name;

        return $this;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->values) ? $this->values[$key] : $default;
    }

    public function set(string $key, mixed $value): static
    {
        $this->values[$key] = $value;

        return $this;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->values);
    }

    public function remove(string $key, mixed $default = null): mixed
    {
        if (!array_key_exists($key, $this->values)) {
            return $default;
        }

        $value = $this->values[$key];
        unset($this->values[$key]);

        return $value;
    }

    public function pull(string $key, mixed $default = null): mixed
    {
        return $this->remove($key, $default);
    }

    public function replace(array $values): static
    {
        $this->values = $values;

        return $this;
    }

    public function all(): array
    {
        return $this->values;
    }

    public function clear(): static
    {
        $this->values = [];

        return $this;
    }

    public function bag(?string $name = null): SessionBagInterface
    {
        throw new BadMethodCallException('ArraySession fixture does not provide bags.');
    }

    public function flash(string $namespace = '_flash'): FlashBagInterface
    {
        throw new BadMethodCallException('ArraySession fixture does not provide flash bags.');
    }
}
