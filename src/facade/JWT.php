<?php

namespace archaeon\jwt\facade;

/**
 * @see \archaeon\jwt\JWT
 * @mixin \archaeon\jwt\JWT
 * @method string make(array $claims) static
 * @method array parse(string $jwt) static
 * @method array validate(string $jwt) static
 * @method array getConfig() static
 */
class JWT
{
    protected static $_instance = [];

    public static function instance(?string $name = '')
    {
        $name = $name ?:  (string)config('jwt.stores', 'default');
        if ( !isset(static::$_instance[$name]) ) {
            static::$_instance[$name] = new \archaeon\jwt\JWT($name);
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