<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Enums;

enum AuthenticationStatus: string
{
    case Guest = 'guest';
    case Authenticated = 'authenticated';
    case Failed = 'failed';
    case InvalidCredentials = 'invalid_credentials';
    case IdentityNotFound = 'identity_not_found';
    case Locked = 'locked';
    case Expired = 'expired';
    case Error = 'error';

    public function isAuthenticated(): bool
    {
        return $this === self::Authenticated;
    }

    public function isGuest(): bool
    {
        return $this === self::Guest;
    }

    public function isFailure(): bool
    {
        return match ($this) {
            self::Authenticated, self::Guest => false,
            default => true,
        };
    }

    public function isCredentialFailure(): bool
    {
        return $this === self::InvalidCredentials || $this === self::IdentityNotFound;
    }

    public function label(): string
    {
        return match ($this) {
            self::Guest => 'Guest',
            self::Authenticated => 'Authenticated',
            self::Failed => 'Failed',
            self::InvalidCredentials => 'Invalid credentials',
            self::IdentityNotFound => 'Identity not found',
            self::Locked => 'Locked',
            self::Expired => 'Expired',
            self::Error => 'Error',
        };
    }
}
