<?php

declare(strict_types=1);

namespace CommonPHP\Authentication;

use CommonPHP\Runtime\Contracts\DriverPoolTrait;

class Authenticator
{
    use DriverPoolTrait;
}