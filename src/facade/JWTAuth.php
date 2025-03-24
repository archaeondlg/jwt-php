<?php

namespace archaeon\jwt\facade;
/**
 * @see \archaeon\jwt\JWTAuth
 * @mixin \archaeon\jwt\JWTAuth
 * @method string make(array $claims) static
 * @method array parse(string $jwt) static
 * @method array validate(string $jwt) static
 * @method array getConfig() static
 * @method string getToken() static
 * @method void setCache(Psr16Cache $cache) static
 * @method void block(string $jwt) static
 * @method void unblock(string $jwt) static
 * @method void logout(string $jwt) static
 * @method array generate(array $cliams = []) static
 * @method array refresh() static
 */
class JWTAuth
{
    protected static $_instance = [];

    public static function instance(?string $name = '')
    {
        $name = $name ?:  (string)config('jwt.stores', 'default');
        if ( !isset(static::$_instance[$name]) ) {
            static::$_instance[$name] = new \archaeon\jwt\JWTAuth($name);
        }
        return static::$_instance[$name];
    }


    /**
     * @param $name
     * @param $arguments
     * @return mixed
     */
    public static function __callStatic($name, $arguments)
    {
        return static::instance()->{$name}(... $arguments);
    }
}