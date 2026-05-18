<?php

declare(strict_types=1);

namespace CommonPHP\Authentication\Tests\Fixtures;

use CommonPHP\Authentication\AuthenticationResult;
use CommonPHP\Authentication\Contracts\AbstractAuthenticationDriver;
use CommonPHP\Authentication\Contracts\CredentialInterface;
use CommonPHP\Authentication\Identity;
use RuntimeException;

final class ExposedAuthenticationDriver extends AbstractAuthenticationDriver
{
    public function authenticate(CredentialInterface $credentials): AuthenticationResult
    {
        return $this->authenticated(new Identity($credentials->identifier()));
    }

    public function exposeAuthenticated(): AuthenticationResult
    {
        return $this->authenticated(new Identity('exposed'), 'Welcome.', ['driver' => 'exposed']);
    }

    public function exposeInvalidCredentials(): AuthenticationResult
    {
        return $this->invalidCredentials('Nope.', ['attempt' => 1]);
    }

    public function exposeIdentityNotFound(): AuthenticationResult
    {
        return $this->identityNotFound('missing', ['source' => 'fixture']);
    }

    public function exposeFailed(): AuthenticationResult
    {
        return $this->failed('General failure.', ['reason' => 'fixture']);
    }

    public function exposeError(): AuthenticationResult
    {
        return $this->error(new RuntimeException('Exploded.'), 'Wrapped.', ['code' => 'fixture']);
    }
}
