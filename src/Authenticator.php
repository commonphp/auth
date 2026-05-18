<?php

declare(strict_types=1);

namespace CommonPHP\Authentication;

use CommonPHP\Authentication\Contracts\AuthenticationDriverInterface;
use CommonPHP\Authentication\Contracts\AuthenticatorInterface;
use CommonPHP\Authentication\Contracts\CredentialInterface;
use CommonPHP\Authentication\Contracts\IdentityInterface;
use CommonPHP\Authentication\Exceptions\AuthenticationDriverException;
use CommonPHP\Authentication\Exceptions\AuthenticationException;
use CommonPHP\Authentication\Exceptions\IdentityNotFoundException;
use CommonPHP\Authentication\Exceptions\InvalidCredentialsException;
use CommonPHP\Runtime\Contracts\DriverPoolTrait;
use CommonPHP\Security\SecurityContext;
use Throwable;

final class Authenticator implements AuthenticatorInterface
{
    use DriverPoolTrait;

    public const DEFAULT_DRIVER = 'default';

    private AuthenticationState $state;

    private string $defaultDriverName;

    public function __construct(?AuthenticationState $state = null, string $defaultDriverName = self::DEFAULT_DRIVER)
    {
        $this->enableDrivers(AuthenticationDriverInterface::class);
        $this->state = $state ?? AuthenticationState::guest();
        $this->defaultDriverName = $defaultDriverName;
    }

    public function registerDriver(string $driverClass, array $defaultOptions = []): static
    {
        return $this->addDriver($driverClass, $defaultOptions);
    }

    public function mapDriver(string $name, string $driverClass, array $options = [], bool $default = false): static
    {
        $this->useDriver($name, $driverClass, $options);

        if ($default) {
            $this->useDefaultDriver($name);
        }

        return $this;
    }

    public function useDefaultDriver(string $name): static
    {
        $this->defaultDriverName = $name;

        return $this;
    }

    public function authenticate(CredentialInterface|array $credentials, ?string $driverName = null): AuthenticationResult
    {
        $credentials = Credentials::from($credentials);
        $driverName ??= $this->defaultDriverName;

        try {
            $driver = $this->authenticationDriver($driverName);

            if (!$driver->supports($credentials)) {
                throw AuthenticationDriverException::unsupportedCredentials($driver->getName());
            }

            $result = $driver->authenticate($credentials);
        } catch (InvalidCredentialsException $exception) {
            $result = AuthenticationResult::invalidCredentials($exception->getMessage(), throwable: $exception);
        } catch (IdentityNotFoundException $exception) {
            $result = AuthenticationResult::identityNotFound($credentials->identifier(), throwable: $exception);
        } catch (AuthenticationException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw AuthenticationDriverException::forOperation('authenticate', $driverName, $throwable);
        }

        if ($result->isAuthenticated() && $result->identity() !== null) {
            $this->state->login($result->identity());
        }

        return $result;
    }

    public function attempt(CredentialInterface|array $credentials, ?string $driverName = null): bool
    {
        return $this->authenticate($credentials, $driverName)->isAuthenticated();
    }

    public function login(IdentityInterface $identity, array $attributes = []): static
    {
        $this->state->login($identity, $attributes);

        return $this;
    }

    public function logout(): static
    {
        $this->state->logout();

        return $this;
    }

    public function state(): AuthenticationState
    {
        return $this->state;
    }

    public function identity(): ?IdentityInterface
    {
        return $this->state->identity();
    }

    public function isAuthenticated(): bool
    {
        return $this->state->isAuthenticated();
    }

    public function securityContext(): SecurityContext
    {
        return $this->state->securityContext();
    }

    private function authenticationDriver(string $name): AuthenticationDriverInterface
    {
        $driver = $this->getDriver($name);

        if (!$driver instanceof AuthenticationDriverInterface) {
            throw AuthenticationDriverException::invalidResult($name);
        }

        return $driver;
    }
}
