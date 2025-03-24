<?php
declare(strict_types=1);

namespace archaeon\jwt;

use Lcobucci\JWT\Configuration;

abstract class JWTInterface
{
    /**
     *
     */
    protected array $config;

    protected Configuration $configuration;
    /**
     * make jwt string
     * @return string
     */
    abstract public function make(array $claims): string;

    /**
     * parse token
     * @param string
     * @return array
     */
    abstract public function parse(string $jwt): array;

    /** 验证token, 返回claims数组
     * @return array
     */
    abstract public function validate(string $jwt): array;
}