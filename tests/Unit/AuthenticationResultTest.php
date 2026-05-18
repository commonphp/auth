<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Tests\Unit;

use CommonPHP\Authentication\AuthenticationResult;
use CommonPHP\Authentication\Enums\AuthenticationStatus;
use CommonPHP\Authentication\Exceptions\AuthenticationException;
use CommonPHP\Authentication\Exceptions\AuthenticationStateException;
use CommonPHP\Authentication\Exceptions\IdentityNotFoundException;
use CommonPHP\Authentication\Exceptions\InvalidCredentialsException;
use CommonPHP\Authentication\Identity;
use CommonPHP\Security\SecurityContext;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class AuthenticationResultTest extends TestCase
{
    public function testAuthenticatedResultCarriesIdentityDetailsAndSecurityContext(): void
    {
        $identity = new Identity('ada', 'Ada', ['tenant' => 'example'], ['admin'], ['reports.read']);
        $result = AuthenticationResult::authenticated($identity, 'Welcome.', ['driver' => 'memory']);
        $context = $result->securityContext();

        self::assertSame(AuthenticationStatus::Authenticated, $result->status());
        self::assertSame($identity, $result->identity());
        self::assertSame('Welcome.', $result->message());
        self::assertSame('memory', $result->detail('driver'));
        self::assertSame('fallback', $result->detail('missing', 'fallback'));
        self::assertTrue($result->hasDetail('driver'));
        self::assertSame(['driver' => 'memory'], $result->details());
        self::assertNull($result->throwable());
        self::assertTrue($result->isAuthenticated());
        self::assertFalse($result->isFailure());
        self::assertInstanceOf(SecurityContext::class, $context);
        self::assertTrue($context->isAuthenticated());
        self::assertSame($identity, $context->identity());
        self::assertTrue($context->hasRole('admin'));
        self::assertTrue($context->hasPermission('reports.read'));
    }

    public function testGuestAndFailedFactoriesExposeExpectedStatuses(): void
    {
        $guest = AuthenticationResult::guest('Signed out.');
        $failed = AuthenticationResult::failed(details: ['reason' => 'unknown']);
        $locked = AuthenticationResult::locked();
        $expired = AuthenticationResult::expired();

        self::assertSame(AuthenticationStatus::Guest, $guest->status());
        self::assertSame('Signed out.', $guest->message());
        self::assertFalse($guest->isAuthenticated());
        self::assertFalse($guest->isFailure());
        self::assertTrue($guest->securityContext()->isGuest());

        self::assertSame(AuthenticationStatus::Failed, $failed->status());
        self::assertSame('Authentication failed.', $failed->message());
        self::assertSame('unknown', $failed->detail('reason'));
        self::assertSame(AuthenticationStatus::Locked, $locked->status());
        self::assertSame('Identity is locked.', $locked->message());
        self::assertSame(AuthenticationStatus::Expired, $expired->status());
        self::assertSame('Credentials are expired.', $expired->message());
    }

    public function testCredentialFailureFactoriesPreserveMessagesAndThrowables(): void
    {
        $previous = new RuntimeException('No user table.');
        $invalid = AuthenticationResult::invalidCredentials('Bad password.', ['field' => 'password'], $previous);
        $missing = AuthenticationResult::identityNotFound('ada', throwable: $previous);

        self::assertSame(AuthenticationStatus::InvalidCredentials, $invalid->status());
        self::assertSame('Bad password.', $invalid->message());
        self::assertSame('password', $invalid->detail('field'));
        self::assertSame($previous, $invalid->throwable());

        self::assertSame(AuthenticationStatus::IdentityNotFound, $missing->status());
        self::assertSame('Identity "ada" was not found.', $missing->message());
        self::assertSame('ada', $missing->detail('identifier'));
        self::assertSame($previous, $missing->throwable());
    }

    public function testErrorFactoryCarriesThrowable(): void
    {
        $previous = new RuntimeException('Database down.');
        $result = AuthenticationResult::error($previous, details: ['driver' => 'sql']);

        self::assertSame(AuthenticationStatus::Error, $result->status());
        self::assertSame('Database down.', $result->message());
        self::assertSame('sql', $result->detail('driver'));
        self::assertSame($previous, $result->throwable());
    }

    public function testWithAndWithoutDetailReturnNewResults(): void
    {
        $result = AuthenticationResult::failed(details: ['first' => true]);
        $withDetail = $result->withDetail('second', true);
        $withoutDetail = $withDetail->withoutDetail('first');

        self::assertNotSame($result, $withDetail);
        self::assertSame(['first' => true], $result->details());
        self::assertSame(['first' => true, 'second' => true], $withDetail->details());
        self::assertSame(['second' => true], $withoutDetail->details());
    }

    public function testAuthenticatedStatusRequiresIdentity(): void
    {
        $this->expectException(AuthenticationStateException::class);

        new AuthenticationResult(AuthenticationStatus::Authenticated);
    }

    public function testThrowIfFailedMapsFailuresToUsefulExceptions(): void
    {
        AuthenticationResult::authenticated(new Identity('ada'))->throwIfFailed();
        AuthenticationResult::guest()->throwIfFailed();

        try {
            AuthenticationResult::invalidCredentials('Bad password.')->throwIfFailed();
            self::fail('Expected invalid credentials exception.');
        } catch (InvalidCredentialsException $exception) {
            self::assertSame('Bad password.', $exception->getMessage());
        }

        try {
            AuthenticationResult::identityNotFound('missing')->throwIfFailed();
            self::fail('Expected identity not found exception.');
        } catch (IdentityNotFoundException $exception) {
            self::assertStringContainsString('missing', $exception->getMessage());
        }

        try {
            AuthenticationResult::failed('No provider accepted credentials.')->throwIfFailed();
            self::fail('Expected authentication exception.');
        } catch (AuthenticationException $exception) {
            self::assertSame('No provider accepted credentials.', $exception->getMessage());
        }
    }
}
