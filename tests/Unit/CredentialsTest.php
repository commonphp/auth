<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Tests\Unit;

use CommonPHP\Authentication\Contracts\CredentialInterface;
use CommonPHP\Authentication\Credentials;
use CommonPHP\Authentication\Exceptions\AuthenticationException;
use PHPUnit\Framework\TestCase;
use Stringable;

final class CredentialsTest extends TestCase
{
    public function testItNormalizesIdentifierSecretAndAttributes(): void
    {
        $identifier = new class implements Stringable {
            public function __toString(): string
            {
                return ' ada@example.com ';
            }
        };

        $secret = new class implements Stringable {
            public function __toString(): string
            {
                return 'secret';
            }
        };

        $credentials = new Credentials($identifier, $secret, [' ip ' => '127.0.0.1']);

        self::assertInstanceOf(CredentialInterface::class, $credentials);
        self::assertSame('ada@example.com', $credentials->identifier());
        self::assertSame('secret', $credentials->secret());
        self::assertTrue($credentials->hasSecret());
        self::assertSame('127.0.0.1', $credentials->attribute('ip'));
        self::assertSame('fallback', $credentials->attribute('missing', 'fallback'));
        self::assertTrue($credentials->hasAttribute('ip'));
        self::assertSame(['ip' => '127.0.0.1'], $credentials->attributes());
        self::assertSame('ada@example.com', (string) $credentials);
    }

    public function testFactoriesCreatePasswordAndTokenCredentials(): void
    {
        $password = Credentials::password(42, 'open-sesame', ['remember' => true]);

        self::assertSame('42', $password->identifier());
        self::assertSame('open-sesame', $password->secret());
        self::assertTrue($password->attribute('remember'));

        $token = Credentials::token('api-token', attributes: ['guard' => 'api']);

        self::assertSame('api-token', $token->identifier());
        self::assertSame('api-token', $token->secret());
        self::assertSame('api-token', $token->attribute('token'));
        self::assertSame('api', $token->attribute('guard'));

        $namedToken = Credentials::token('api-token', 'service-account');

        self::assertSame('service-account', $namedToken->identifier());
        self::assertSame('api-token', $namedToken->secret());
    }

    public function testItBuildsFromCommonArrayShapes(): void
    {
        $fromIdentifier = Credentials::from([
            'identifier' => 'ada',
            'secret' => 'secret',
            'attributes' => ['guard' => 'web'],
        ]);
        $fromUsername = Credentials::from(['username' => 'grace', 'password' => 'compiler']);
        $fromEmail = Credentials::from(['email' => 'katherine@example.com', 'token' => 'math']);
        $fromLogin = Credentials::from(['login' => 'margaret']);

        self::assertInstanceOf(CredentialInterface::class, $fromIdentifier);
        self::assertSame('ada', $fromIdentifier->identifier());
        self::assertSame('secret', $fromIdentifier->secret());
        self::assertSame('web', $fromIdentifier->attribute('guard'));
        self::assertSame('grace', $fromUsername->identifier());
        self::assertSame('compiler', $fromUsername->secret());
        self::assertSame('katherine@example.com', $fromEmail->identifier());
        self::assertSame('math', $fromEmail->secret());
        self::assertSame('margaret', $fromLogin->identifier());
        self::assertNull($fromLogin->secret());
        self::assertSame($fromIdentifier, Credentials::from($fromIdentifier));
    }

    public function testItReturnsNewInstancesWhenChangingAttributesOrSecret(): void
    {
        $original = new Credentials('ada', 'secret', ['tenant' => 'one']);
        $withAttribute = $original->withAttribute(' locale ', 'en');
        $withoutAttribute = $withAttribute->withoutAttribute('tenant');
        $withoutSecret = $original->withoutSecret();

        self::assertNotSame($original, $withAttribute);
        self::assertSame(['tenant' => 'one'], $original->attributes());
        self::assertSame(['tenant' => 'one', 'locale' => 'en'], $withAttribute->attributes());
        self::assertSame(['locale' => 'en'], $withoutAttribute->attributes());
        self::assertNull($withoutSecret->secret());
        self::assertFalse($withoutSecret->hasSecret());
    }

    public function testItRejectsInvalidIdentifiersAndAttributes(): void
    {
        foreach (['', '   ', str_repeat('a', Credentials::MAX_IDENTIFIER_LENGTH + 1)] as $identifier) {
            try {
                new Credentials($identifier);
                self::fail('Expected invalid identifier exception.');
            } catch (AuthenticationException $exception) {
                self::assertStringContainsString('Invalid authentication identifier', $exception->getMessage());
            }
        }

        try {
            new Credentials('ada', attributes: [' ' => 'bad']);
            self::fail('Expected invalid attribute exception.');
        } catch (AuthenticationException $exception) {
            self::assertStringContainsString('attribute key', $exception->getMessage());
        }

        try {
            new Credentials('ada', attributes: [10 => 'bad']);
            self::fail('Expected invalid attribute exception.');
        } catch (AuthenticationException $exception) {
            self::assertStringContainsString('attribute keys must be strings', $exception->getMessage());
        }
    }

    public function testItRejectsInvalidArrayPayloads(): void
    {
        foreach (
            [
                [],
                ['identifier' => []],
                ['identifier' => 'ada', 'secret' => []],
                ['identifier' => 'ada', 'attributes' => 'nope'],
            ] as $payload
        ) {
            try {
                Credentials::from($payload);
                self::fail('Expected invalid credential payload exception.');
            } catch (AuthenticationException $exception) {
                self::assertStringContainsString('Invalid credential payload', $exception->getMessage());
            }
        }
    }
}
