<?php

declare(strict_types=1);

namespace CommonPHP\Authentication;

use CommonPHP\Authentication\Contracts\CredentialInterface;
use CommonPHP\Authentication\Exceptions\AuthenticationException;
use Stringable;

final readonly class Credentials implements CredentialInterface, Stringable
{
    public const int MAX_IDENTIFIER_LENGTH = 191;

    private string $identifier;

    private ?string $secret;

    /**
     * @var array<string, mixed>
     */
    private array $attributes;

    /**
     * @param array<string, mixed> $attributes
     */
    public function __construct(string|int|Stringable $identifier, string|Stringable|null $secret = null, array $attributes = [])
    {
        $this->identifier = self::normalizeIdentifier((string) $identifier);
        $this->secret = $secret === null ? null : (string) $secret;
        $this->attributes = self::normalizeAttributes($attributes);
    }

    /**
     * @param array<string, mixed>|CredentialInterface $credentials
     */
    public static function from(CredentialInterface|array $credentials): CredentialInterface
    {
        if ($credentials instanceof CredentialInterface) {
            return $credentials;
        }

        $identifier = $credentials['identifier']
            ?? $credentials['username']
            ?? $credentials['email']
            ?? $credentials['login']
            ?? null;

        if (!is_string($identifier) && !is_int($identifier) && !$identifier instanceof Stringable) {
            throw AuthenticationException::invalidCredentialsShape(
                'expected an identifier, username, email, or login value.',
            );
        }

        $secret = $credentials['secret']
            ?? $credentials['password']
            ?? $credentials['token']
            ?? null;

        if ($secret !== null && !is_string($secret) && !$secret instanceof Stringable) {
            throw AuthenticationException::invalidCredentialsShape('expected secret, password, or token to be a string.');
        }

        $attributes = $credentials['attributes'] ?? [];

        if (!is_array($attributes)) {
            throw AuthenticationException::invalidCredentialsShape('attributes must be an array.');
        }

        return new self($identifier, $secret, $attributes);
    }

    /**
     * @param array<string, mixed> $attributes
     */
    public static function password(string|int|Stringable $identifier, string|Stringable $password, array $attributes = []): self
    {
        return new self($identifier, $password, $attributes);
    }

    /**
     * @param array<string, mixed> $attributes
     */
    public static function token(string|Stringable $token, string|int|Stringable|null $identifier = null, array $attributes = []): self
    {
        $attributes['token'] = (string) $token;

        return new self($identifier ?? (string) $token, (string) $token, $attributes);
    }

    public function identifier(): string
    {
        return $this->identifier;
    }

    public function secret(): ?string
    {
        return $this->secret;
    }

    public function hasSecret(): bool
    {
        return $this->secret !== null;
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
        $key = self::normalizeAttributeKey($key);
        $attributes = $this->attributes;
        $attributes[$key] = $value;

        return new self($this->identifier, $this->secret, $attributes);
    }

    public function withoutAttribute(string $key): self
    {
        $attributes = $this->attributes;
        unset($attributes[$key]);

        return new self($this->identifier, $this->secret, $attributes);
    }

    public function withoutSecret(): self
    {
        return new self($this->identifier, null, $this->attributes);
    }

    public function __toString(): string
    {
        return $this->identifier;
    }

    private static function normalizeIdentifier(string $identifier): string
    {
        $identifier = trim($identifier);

        if ($identifier === '') {
            throw AuthenticationException::invalidIdentifier($identifier, 'identifiers cannot be empty.');
        }

        if (strlen($identifier) > self::MAX_IDENTIFIER_LENGTH) {
            throw AuthenticationException::invalidIdentifier(
                $identifier,
                'identifiers cannot be longer than ' . self::MAX_IDENTIFIER_LENGTH . ' bytes.',
            );
        }

        return $identifier;
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
                throw AuthenticationException::invalidCredentialsShape('attribute keys must be strings.');
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
}
