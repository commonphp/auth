<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Tests\Unit;

use CommonPHP\Authentication\Contracts\AuthenticationDriverInterface;
use CommonPHP\Authentication\Contracts\CredentialInterface;
use CommonPHP\Authentication\Contracts\IdentityInterface;
use CommonPHP\Authentication\Contracts\IdentityProviderInterface;
use CommonPHP\Authentication\Credentials;
use CommonPHP\Authentication\Enums\AuthenticationStatus;
use CommonPHP\Authentication\Exceptions\AuthenticationDriverException;
use CommonPHP\Authentication\Exceptions\AuthenticationException;
use CommonPHP\Authentication\Exceptions\AuthenticationStateException;
use CommonPHP\Authentication\Exceptions\IdentityNotFoundException;
use CommonPHP\Authentication\Exceptions\InvalidCredentialsException;
use CommonPHP\Authentication\Identity;
use CommonPHP\Authentication\Tests\Fixtures\ArrayIdentityProvider;
use CommonPHP\Authentication\Tests\Fixtures\ExposedAuthenticationDriver;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ContractsAndExceptionsTest extends TestCase
{
    public function testConcreteValuesImplementTheirContracts(): void
    {
        self::assertInstanceOf(CredentialInterface::class, new Credentials('ada'));
        self::assertInstanceOf(IdentityInterface::class, new Identity('ada'));
    }

    public function testIdentityProviderContractFindsKnownIdentities(): void
    {
        $identity = new Identity('ada');
        $provider = new ArrayIdentityProvider();

        self::assertInstanceOf(IdentityProviderInterface::class, $provider);
        self::assertSame($provider, $provider->add($identity));
        self::assertSame($identity, $provider->findIdentity('ada'));
        self::assertNull($provider->findIdentity('missing'));
    }

    public function testAbstractAuthenticationDriverProvidesDefaultsAndHelpers(): void
    {
        $driver = new ExposedAuthenticationDriver();

        self::assertInstanceOf(AuthenticationDriverInterface::class, $driver);
        self::assertSame(ExposedAuthenticationDriver::class, $driver->getName());
        self::assertTrue($driver->supports(new Credentials('ada')));

        $authenticated = $driver->exposeAuthenticated();
        $invalid = $driver->exposeInvalidCredentials();
        $missing = $driver->exposeIdentityNotFound();
        $failed = $driver->exposeFailed();
        $error = $driver->exposeError();

        self::assertTrue($authenticated->isAuthenticated());
        self::assertSame('exposed', $authenticated->identity()?->id());
        self::assertSame('exposed', $authenticated->detail('driver'));
        self::assertSame(AuthenticationStatus::InvalidCredentials, $invalid->status());
        self::assertSame('Nope.', $invalid->message());
        self::assertSame(1, $invalid->detail('attempt'));
        self::assertSame(AuthenticationStatus::IdentityNotFound, $missing->status());
        self::assertSame('missing', $missing->detail('identifier'));
        self::assertSame(AuthenticationStatus::Failed, $failed->status());
        self::assertSame('fixture', $failed->detail('reason'));
        self::assertSame(AuthenticationStatus::Error, $error->status());
        self::assertInstanceOf(RuntimeException::class, $error->throwable());
    }

    public function testExceptionFactoriesProduceActionableMessagesAndPreviousExceptions(): void
    {
        $previous = new RuntimeException('SQL failed.');

        $invalidIdentifier = AuthenticationException::invalidIdentifier('', 'empty');
        $invalidAttribute = AuthenticationException::invalidAttributeKey('');
        $invalidShape = AuthenticationException::invalidCredentialsShape('missing identifier', $previous);
        $driverOperation = AuthenticationDriverException::forOperation('authenticate', 'memory', $previous);
        $unsupported = AuthenticationDriverException::unsupportedCredentials('memory');
        $invalidResult = AuthenticationDriverException::invalidResult('memory');
        $missingIdentity = AuthenticationStateException::missingIdentity();
        $invalidState = AuthenticationStateException::invalidSessionData('_auth');
        $notFound = IdentityNotFoundException::forIdentifier('ada');
        $badCredentials = InvalidCredentialsException::forIdentifier('ada', $previous);

        self::assertStringContainsString('Invalid authentication identifier', $invalidIdentifier->getMessage());
        self::assertStringContainsString('attribute key', $invalidAttribute->getMessage());
        self::assertSame($previous, $invalidShape->getPrevious());
        self::assertStringContainsString('Unable to authenticate', $driverOperation->getMessage());
        self::assertSame($previous, $driverOperation->getPrevious());
        self::assertStringContainsString('does not support', $unsupported->getMessage());
        self::assertStringContainsString('invalid authentication result', $invalidResult->getMessage());
        self::assertStringContainsString('requires an identity', $missingIdentity->getMessage());
        self::assertStringContainsString('_auth', $invalidState->getMessage());
        self::assertStringContainsString('ada', $notFound->getMessage());
        self::assertStringContainsString('ada', $badCredentials->getMessage());
        self::assertSame($previous, $badCredentials->getPrevious());
    }
}
