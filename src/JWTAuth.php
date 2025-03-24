<?php
declare(strict_types=1);

namespace archaeon\jwt;

use Psr\SimpleCache\CacheInterface;

class JWTAuth extends JWT
{
    /**
     * @var CacheInterface
     */
    protected $cache;

    protected $jwt;

    /**
     *
     */
    public function setCache(CacheInterface $cache): void
    {
        $this->cache = $cache;
    }

    public function hashKey(string $jwt)
    {
        return md5($jwt);
    }

    public function isBlocked(string $jwt)
    {
        return $this->cache->has($this->hashKey($jwt));
    }

    public function block(string $jwt): void
    {
        $key = $this->hashKey($jwt);
        $this->cache->set($key, $jwt);
    }

    public function unblock(string $jwt): void
    {
        $this->cache->delete($this->hashKey($jwt));
    }

    public function getToken(): string
    {
        $type = $this->config['type'];
        switch ($type) {
            case 'header':
                $token = request()->header('Authorization', '');
                if (! $token) {
                    $token = request()->header('HTTP_AUTHORIZATION', '');
                    if (!$token) {
                        $token = request()->header('REDIRECT_HTTP_AUTHORIZATION', '');
                    }
                }
                $position = strripos($token, 'bearer ');
                if ($position === false) {
                    return '';
                }
                $token = substr($token, $position + 7);  // len('bearer ')
                $token = trim(strpos($token, ',') !== false ? strstr($token, ',', true) : $token);
                break;
            case 'cookie':
                $token = request()->cookie('token', '');
                break;
            case 'url':
                $token = request()->get('token');
        }
        return $token;
    }

    public function generate(array $cliams = []): array
    {
        $config = $this->getConfig();
        return [
            'token' => $this->make($cliams),
            'token_type' => $config['expires_at'],
            'expires_in' => $config['expires_at'],
            'refresh_in' => $config['refresh_ttL'],
        ];
    }

    public function refresh(string $jwt): array
    {
        $tokenObj = $this->generate($this->parse($jwt));
        $this->block($jwt);
        return $tokenObj;
    }

    public function logout(string $jwt)
    {
        return $this->block($jwt);
    }
}
