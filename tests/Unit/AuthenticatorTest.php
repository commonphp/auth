<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Tests\Unit;

use CommonPHP\Authentication\AuthenticationResult;
use CommonPHP\Authentication\AuthenticationState;
use CommonPHP\Authentication\Authenticator;
use CommonPHP\Authentication\Contracts\AuthenticatorInterface;
use CommonPHP\Authentication\Credentials;
use CommonPHP\Authentication\Enums\AuthenticationStatus;
use CommonPHP\Authentication\Exceptions\AuthenticationDriverException;
use CommonPHP\Authentication\Identity;
use CommonPHP\Authentication\Tests\Fixtures\MemoryAuthenticationDriver;
use CommonPHP\Authentication\Tests\Fixtures\ThrowingAuthenticationDriver;
use CommonPHP\Authentication\Tests\Fixtures\ThrowingIdentityNotFoundDriver;
use CommonPHP\Authentication\Tests\Fixtures\ThrowingInvalidCredentialsDriver;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class AuthenticatorTest extends TestCase
{
    public function testItAuthenticatesWithTheDefaultMappedDriverAndUpdatesState(): void
    {
        $authenticator = new Authenticator();

        self::assertInstanceOf(AuthenticatorInterface::class, $authenticator);
        self::assertTrue($authenticator->state()->isGuest());

        $result = $authenticator
            ->registerDriver(MemoryAuthenticationDriver::class)
            ->mapDriver('memory', MemoryAuthenticationDriver::class, ['name' => 'primary'], true)
            ->authenticate(Credentials::password('ada', 'secret'));

        self::assertTrue($result->isAuthenticated());
        self::assertSame('ada', $result->identity()?->id());
        self::assertSame('primary', $result->detail('driver'));
        self::assertTrue($authenticator->isAuthenticated());
        self::assertSame('ada', $authenticator->identity()?->id());
        self::assertTrue($authenticator->securityContext()->hasRole('admin'));
    }

    public function testItAcceptsArrayCredentialsAndCanUseNamedDrivers(): void
    {
        $authenticator = new Authenticator();
        $authenticator
            ->registerDriver(MemoryAuthenticationDriver::class)
            ->mapDriver('first', MemoryAuthenticationDriver::class, ['expectedSecret' => 'first'])
            ->mapDriver('second', MemoryAuthenticationDriver::class, ['expectedSecret' => 'second']);

        $first = $authenticator->authenticate(['identifier' => 'ada', 'password' => 'first'], 'first');
        $second = $authenticator->authenticate(['identifier' => 'ada', 'password' => 'second'], 'second');

        self::assertTrue($first->isAuthenticated());
        self::assertTrue($second->isAuthenticated());
    }

    public function testAttemptReturnsBooleanAndFailedAttemptsDoNotLogin(): void
    {
        $authenticator = new Authenticator();
        $authenticator
            ->registerDriver(MemoryAuthenticationDriver::class)
            ->mapDriver('memory', MemoryAuthenticationDriver::class, default: true);

        self::assertFalse($authenticator->attempt(['identifier' => 'ada', 'password' => 'wrong']));
        self::assertFalse($authenticator->isAuthenticated());

        self::assertTrue($authenticator->attempt(['identifier' => 'ada', 'password' => 'secret']));
        self::assertTrue($authenticator->isAuthenticated());
    }

    public function testIdentityNotFoundReturnsAResultWithoutLoggingIn(): void
    {
        $authenticator = new Authenticator();
        $result = $authenticator
            ->registerDriver(MemoryAuthenticationDriver::class)
            ->mapDriver('memory', MemoryAuthenticationDriver::class, default: true)
            ->authenticate(['identifier' => 'missing', 'password' => 'secret']);

        self::assertSame(AuthenticationStatus::IdentityNotFound, $result->status());
        self::assertFalse($authenticator->isAuthenticated());
        self::assertSame('missing', $result->detail('identifier'));
    }

    public function testDriversCanThrowExpectedCredentialExceptionsAsResults(): void
    {
        $invalid = new Authenticator();
        $invalid
            ->registerDriver(ThrowingInvalidCredentialsDriver::class)
            ->mapDriver('throwing', ThrowingInvalidCredentialsDriver::class, default: true);

        $invalidResult = $invalid->authenticate(['identifier' => 'ada', 'password' => 'bad']);

        self::assertSame(AuthenticationStatus::InvalidCredentials, $invalidResult->status());
        self::assertFalse($invalid->isAuthenticated());

        $missing = new Authenticator();
        $missing
            ->registerDriver(ThrowingIdentityNotFoundDriver::class)
            ->mapDriver('throwing', ThrowingIdentityNotFoundDriver::class, default: true);

        $missingResult = $missing->authenticate(['identifier' => 'ada', 'password' => 'bad']);

        self::assertSame(AuthenticationStatus::IdentityNotFound, $missingResult->status());
        self::assertSame('ada', $missingResult->detail('identifier'));
    }

    public function testUnsupportedCredentialsThrowDriverException(): void
    {
        $authenticator = new Authenticator();
        $authenticator
            ->registerDriver(MemoryAuthenticationDriver::class)
            ->mapDriver('memory', MemoryAuthenticationDriver::class, default: true);

        $this->expectException(AuthenticationDriverException::class);
        $this->expectExceptionMessage('does not support');

        $authenticator->authenticate(new Credentials('ada', 'secret', ['unsupported' => true]));
    }

    public function testUnexpectedDriverErrorsAreWrapped(): void
    {
        $authenticator = new Authenticator();
        $authenticator
            ->registerDriver(ThrowingAuthenticationDriver::class)
            ->mapDriver('throwing', ThrowingAuthenticationDriver::class, default: true);

        try {
            $authenticator->authenticate(['identifier' => 'ada', 'password' => 'secret']);
            self::fail('Expected driver exception.');
        } catch (AuthenticationDriverException $exception) {
            self::assertInstanceOf(RuntimeException::class, $exception->getPrevious());
            self::assertStringContainsString('Unable to authenticate', $exception->getMessage());
        }
    }

    public function testMissingDefaultDriverIsWrapped(): void
    {
        $authenticator = new Authenticator();

        $this->expectException(AuthenticationDriverException::class);
        $this->expectExceptionMessage('Unable to authenticate');

        $authenticator->authenticate(['identifier' => 'ada', 'password' => 'secret']);
    }

    public function testManualLoginAndLogoutUpdateState(): void
    {
        $state = AuthenticationState::guest();
        $authenticator = new Authenticator($state);
        $identity = new Identity('ada', roles: ['admin']);

        self::assertSame($authenticator, $authenticator->login($identity, ['guard' => 'manual']));
        self::assertSame($state, $authenticator->state());
        self::assertTrue($authenticator->isAuthenticated());
        self::assertSame('ada', $authenticator->identity()?->id());
        self::assertSame('manual', $authenticator->state()->attribute('guard'));
        self::assertTrue($authenticator->securityContext()->hasRole('admin'));

        self::assertSame($authenticator, $authenticator->logout());
        self::assertTrue($authenticator->state()->isGuest());
    }

    public function testUseDefaultDriverSwitchesMappedDriver(): void
    {
        $authenticator = new Authenticator();
        $authenticator
            ->registerDriver(MemoryAuthenticationDriver::class)
            ->mapDriver('first', MemoryAuthenticationDriver::class, ['expectedSecret' => 'first'])
            ->mapDriver('second', MemoryAuthenticationDriver::class, ['expectedSecret' => 'second'])
            ->useDefaultDriver('second');

        $result = $authenticator->authenticate(['identifier' => 'ada', 'password' => 'second']);

        self::assertTrue($result->isAuthenticated());
    }
}
