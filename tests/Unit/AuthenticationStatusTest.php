<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Tests\Unit;

use CommonPHP\Authentication\Enums\AuthenticationStatus;
use PHPUnit\Framework\TestCase;

final class AuthenticationStatusTest extends TestCase
{
    public function testStatusesReportTheirMeaning(): void
    {
        self::assertTrue(AuthenticationStatus::Authenticated->isAuthenticated());
        self::assertFalse(AuthenticationStatus::Guest->isAuthenticated());
        self::assertTrue(AuthenticationStatus::Guest->isGuest());
        self::assertFalse(AuthenticationStatus::Authenticated->isGuest());

        foreach (
            [
                AuthenticationStatus::Failed,
                AuthenticationStatus::InvalidCredentials,
                AuthenticationStatus::IdentityNotFound,
                AuthenticationStatus::Locked,
                AuthenticationStatus::Expired,
                AuthenticationStatus::Error,
            ] as $status
        ) {
            self::assertTrue($status->isFailure());
        }

        self::assertFalse(AuthenticationStatus::Guest->isFailure());
        self::assertFalse(AuthenticationStatus::Authenticated->isFailure());
        self::assertTrue(AuthenticationStatus::InvalidCredentials->isCredentialFailure());
        self::assertTrue(AuthenticationStatus::IdentityNotFound->isCredentialFailure());
        self::assertFalse(AuthenticationStatus::Failed->isCredentialFailure());
    }

    public function testStatusesExposeStableLabels(): void
    {
        self::assertSame('Guest', AuthenticationStatus::Guest->label());
        self::assertSame('Authenticated', AuthenticationStatus::Authenticated->label());
        self::assertSame('Failed', AuthenticationStatus::Failed->label());
        self::assertSame('Invalid credentials', AuthenticationStatus::InvalidCredentials->label());
        self::assertSame('Identity not found', AuthenticationStatus::IdentityNotFound->label());
        self::assertSame('Locked', AuthenticationStatus::Locked->label());
        self::assertSame('Expired', AuthenticationStatus::Expired->label());
        self::assertSame('Error', AuthenticationStatus::Error->label());
    }
}
