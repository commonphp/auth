<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Tests\Unit;

use CommonPHP\Authentication\AuthenticationResult;
use CommonPHP\Authentication\AuthenticationState;
use CommonPHP\Authentication\Exceptions\AuthenticationStateException;
use CommonPHP\Authentication\Identity;
use CommonPHP\Authentication\Tests\Fixtures\ArraySession;
use CommonPHP\Security\Role;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class AuthenticationStateTest extends TestCase
{
    public function testGuestStateExposesGuestSecurityContext(): void
    {
        $state = AuthenticationState::guest();

        self::assertFalse($state->isAuthenticated());
        self::assertTrue($state->isGuest());
        self::assertNull($state->identity());
        self::assertNull($state->user());
        self::assertNull($state->authenticatedAt());
        self::assertSame([], $state->roles());
        self::assertSame([], $state->roleNames());
        self::assertSame([], $state->permissions());
        self::assertSame([], $state->directPermissions());
        self::assertFalse($state->hasRole('admin'));
        self::assertFalse($state->hasPermission('reports.read'));
        self::assertSame('fallback', $state->attribute('missing', 'fallback'));
        self::assertFalse($state->hasAttribute('tenant'));
        self::assertTrue($state->securityContext()->isGuest());
    }

    public function testAuthenticatedStateExposesIdentityAndMergedAttributes(): void
    {
        $role = new Role('admin', ['reports.write']);
        $identity = new Identity('ada', 'Ada', ['tenant' => 'identity'], [$role], ['reports.read']);
        $state = AuthenticationState::authenticated($identity, ['tenant' => 'state', 'guard' => 'web']);

        self::assertTrue($state->isAuthenticated());
        self::assertFalse($state->isGuest());
        self::assertSame($identity, $state->identity());
        self::assertSame($identity, $state->user());
        self::assertInstanceOf(DateTimeImmutable::class, $state->authenticatedAt());
        self::assertTrue($state->hasRole('admin'));
        self::assertSame(['admin'], $state->roleNames());
        self::assertTrue($state->hasPermission('reports.read'));
        self::assertTrue($state->hasPermission('reports.write'));
        self::assertSame(['reports.read'], array_map(static fn ($permission): string => $permission->value(), $state->directPermissions()));
        self::assertSame('state', $state->attribute('tenant'));
        self::assertSame('web', $state->attribute('guard'));
        self::assertSame(['tenant' => 'state', 'guard' => 'web'], $state->attributes());
        self::assertTrue($state->securityContext()->hasPermission('reports.write'));
    }

    public function testItCanLoginLogoutAndMutateStateAttributes(): void
    {
        $state = AuthenticationState::guest();
        $identity = new Identity('ada');

        self::assertSame($state, $state->login($identity, ['guard' => 'web']));
        self::assertTrue($state->isAuthenticated());
        self::assertSame('web', $state->attribute('guard'));
        self::assertSame($state, $state->setAttribute('ip', '127.0.0.1'));
        self::assertSame('127.0.0.1', $state->attribute('ip'));
        self::assertSame($state, $state->removeAttribute('guard'));
        self::assertFalse($state->hasAttribute('guard'));
        self::assertSame($state, $state->logout());
        self::assertTrue($state->isGuest());
        self::assertSame([], $state->attributes());
    }

    public function testItAppliesAuthenticationResults(): void
    {
        $state = AuthenticationState::guest();
        $identity = new Identity('ada');

        self::assertSame($state, $state->apply(AuthenticationResult::authenticated($identity)));
        self::assertSame($identity, $state->identity());

        self::assertSame($state, $state->apply(AuthenticationResult::failed()));
        self::assertSame($identity, $state->identity());

        self::assertSame($state, $state->apply(AuthenticationResult::guest()));
        self::assertTrue($state->isGuest());
    }

    public function testItSerializesAndRestoresSessionSafeArrays(): void
    {
        $authenticatedAt = new DateTimeImmutable('2026-01-02T03:04:05+00:00');
        $identity = new Identity('ada', 'Ada', ['tenant' => 'example'], [new Role('admin', ['reports.write'])], ['reports.read']);
        $state = AuthenticationState::authenticated($identity, ['guard' => 'web'], $authenticatedAt);
        $payload = $state->toArray();
        $restored = AuthenticationState::fromArray($payload);

        self::assertSame(
            [
                'authenticated' => true,
                'authenticated_at' => '2026-01-02T03:04:05+00:00',
                'identity' => [
                    'id' => 'ada',
                    'name' => 'Ada',
                    'attributes' => ['tenant' => 'example'],
                    'roles' => ['admin'],
                    'permissions' => ['reports.read'],
                ],
                'attributes' => ['guard' => 'web'],
            ],
            $payload,
        );
        self::assertSame('ada', $restored->identity()?->id());
        self::assertSame('Ada', $restored->identity()?->name());
        self::assertTrue($restored->hasRole('admin'));
        self::assertTrue($restored->hasPermission('reports.read'));
        self::assertSame('web', $restored->attribute('guard'));
        self::assertSame('2026-01-02T03:04:05+00:00', $restored->authenticatedAt()?->format(DATE_ATOM));
    }

    public function testGuestArrayRestoresToGuestState(): void
    {
        $state = AuthenticationState::fromArray(['authenticated' => false]);

        self::assertTrue($state->isGuest());
    }

    public function testItPersistsToAndLoadsFromSession(): void
    {
        $session = new ArraySession();
        $state = AuthenticationState::authenticated(new Identity('ada'), ['guard' => 'web']);

        self::assertSame($state, $state->saveToSession($session));
        self::assertTrue($session->has(AuthenticationState::SESSION_KEY));

        $loaded = AuthenticationState::fromSession($session);

        self::assertSame('ada', $loaded->identity()?->id());
        self::assertSame('web', $loaded->attribute('guard'));
        self::assertSame($state, $state->clearSession($session));
        self::assertFalse($session->has(AuthenticationState::SESSION_KEY));
        self::assertTrue(AuthenticationState::fromSession($session)->isGuest());
    }

    public function testFromSessionAcceptsExistingStateInstances(): void
    {
        $state = AuthenticationState::authenticated(new Identity('ada'));
        $session = new ArraySession([AuthenticationState::SESSION_KEY => $state]);

        self::assertSame($state, AuthenticationState::fromSession($session));
    }

    public function testItRejectsInvalidAuthenticatedStateAndStoredData(): void
    {
        $this->expectException(AuthenticationStateException::class);

        new AuthenticationState(authenticatedAt: new DateTimeImmutable());
    }

    public function testItRejectsInvalidSessionPayloads(): void
    {
        foreach (
            [
                ['authenticated' => true],
                ['authenticated' => true, 'identity' => []],
                ['authenticated' => true, 'identity' => ['id' => 'ada', 'attributes' => 'bad']],
                ['authenticated' => true, 'identity' => ['id' => 'ada'], 'attributes' => 'bad'],
                ['authenticated' => true, 'identity' => ['id' => 'ada'], 'authenticated_at' => 'not a date'],
                ['authenticated' => true, 'identity' => ['id' => 'ada', 'roles' => [10]]],
            ] as $payload
        ) {
            try {
                AuthenticationState::fromArray($payload);
                self::fail('Expected invalid session data exception.');
            } catch (AuthenticationStateException $exception) {
                self::assertStringContainsString(AuthenticationState::SESSION_KEY, $exception->getMessage());
            }
        }

        $session = new ArraySession([AuthenticationState::SESSION_KEY => 'bad']);

        $this->expectException(AuthenticationStateException::class);
        AuthenticationState::fromSession($session);
    }
}
