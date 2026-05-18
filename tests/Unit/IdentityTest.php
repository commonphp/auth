<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Tests\Unit;

use CommonPHP\Authentication\Contracts\IdentityInterface;
use CommonPHP\Authentication\Exceptions\AuthenticationException;
use CommonPHP\Authentication\Identity;
use CommonPHP\Security\Permission;
use CommonPHP\Security\Role;
use PHPUnit\Framework\TestCase;
use Stringable;

final class IdentityTest extends TestCase
{
    public function testItNormalizesAndExposesIdentityData(): void
    {
        $identifier = new class implements Stringable {
            public function __toString(): string
            {
                return ' ada ';
            }
        };

        $identity = new Identity(
            $identifier,
            ' Ada Lovelace ',
            [' tenant ' => 'example'],
            [new Role('admin', ['reports.write'])],
            ['reports.read'],
        );

        self::assertInstanceOf(IdentityInterface::class, $identity);
        self::assertSame('ada', $identity->id());
        self::assertSame('ada', $identity->identifier());
        self::assertSame('Ada Lovelace', $identity->name());
        self::assertSame('Ada Lovelace', $identity->displayName());
        self::assertSame('example', $identity->attribute('tenant'));
        self::assertSame('fallback', $identity->attribute('missing', 'fallback'));
        self::assertTrue($identity->hasAttribute('tenant'));
        self::assertTrue($identity->hasRole('admin'));
        self::assertSame(['admin'], $identity->roleNames());
        self::assertTrue($identity->hasPermission('reports.read'));
        self::assertTrue($identity->hasPermission('reports.write'));
        self::assertSame(['reports.read', 'reports.write'], $identity->permissionNames());
        self::assertSame(['reports.read'], $identity->directPermissionNames());
        self::assertSame('ada', (string) $identity);
    }

    public function testItUsesIdentifierAsDisplayNameWhenNameIsBlank(): void
    {
        $identity = new Identity(100, '   ');

        self::assertSame('100', $identity->id());
        self::assertNull($identity->name());
        self::assertSame('100', $identity->displayName());
    }

    public function testItClonesRolesOnInputAndOutput(): void
    {
        $role = new Role('editor', ['posts.update']);
        $identity = new Identity('ada', roles: [$role]);

        $role->grant('posts.delete');
        $returned = $identity->roles()[0];
        $returned->grant('posts.publish');

        self::assertTrue($identity->hasPermission('posts.update'));
        self::assertFalse($identity->hasPermission('posts.delete'));
        self::assertFalse($identity->hasPermission('posts.publish'));
    }

    public function testItReturnsNewInstancesForAttributeRoleAndPermissionChanges(): void
    {
        $identity = new Identity('ada', attributes: ['tenant' => 'one']);
        $withAttribute = $identity->withAttribute(' locale ', 'en');
        $withoutAttribute = $withAttribute->withoutAttribute('tenant');
        $withRole = $identity->withRole('admin');
        $withoutRole = $withRole->withoutRole('admin');
        $withPermission = $identity->withPermission(new Permission('reports.read'));
        $withoutPermission = $withPermission->withoutPermission('reports.read');

        self::assertNotSame($identity, $withAttribute);
        self::assertSame(['tenant' => 'one'], $identity->attributes());
        self::assertSame(['tenant' => 'one', 'locale' => 'en'], $withAttribute->attributes());
        self::assertSame(['locale' => 'en'], $withoutAttribute->attributes());
        self::assertTrue($withRole->hasRole('admin'));
        self::assertFalse($withoutRole->hasRole('admin'));
        self::assertTrue($withPermission->hasPermission('reports.read'));
        self::assertFalse($withoutPermission->hasPermission('reports.read'));
    }

    public function testItSerializesDirectIdentityDataToArray(): void
    {
        $identity = new Identity(
            'ada',
            'Ada',
            ['tenant' => 'example'],
            [new Role('admin', ['reports.write'])],
            ['reports.read'],
        );

        self::assertSame(
            [
                'id' => 'ada',
                'name' => 'Ada',
                'attributes' => ['tenant' => 'example'],
                'roles' => ['admin'],
                'permissions' => ['reports.read'],
            ],
            $identity->toArray(),
        );
    }

    public function testFromKeepsExistingIdentityInstancesAndWrapsScalars(): void
    {
        $identity = new Identity('ada');

        self::assertSame($identity, Identity::from($identity));
        self::assertSame('grace', Identity::from(' grace ')->identifier());
    }

    public function testItRejectsInvalidIdentifiersAndAttributeKeys(): void
    {
        foreach (['', '   ', str_repeat('a', Identity::MAX_IDENTIFIER_LENGTH + 1)] as $identifier) {
            try {
                new Identity($identifier);
                self::fail('Expected invalid identifier exception.');
            } catch (AuthenticationException $exception) {
                self::assertStringContainsString('Invalid authentication identifier', $exception->getMessage());
            }
        }

        try {
            new Identity('ada', attributes: [' ' => true]);
            self::fail('Expected invalid attribute key exception.');
        } catch (AuthenticationException $exception) {
            self::assertStringContainsString('attribute key', $exception->getMessage());
        }

        try {
            new Identity('ada', attributes: [1 => true]);
            self::fail('Expected invalid attribute key exception.');
        } catch (AuthenticationException $exception) {
            self::assertStringContainsString('identity attribute keys must be strings', $exception->getMessage());
        }
    }
}
