<?php
declare(strict_types=1);

namespace archaeon\jwt;

use archaeon\jwt\exception\JwtException;
use archaeon\jwt\exception\JwtExpiredException;
use archaeon\jwt\exception\JwtInvalidException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as ES256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as ES384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HS384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RS512;
use Lcobucci\JWT\UnencryptedToken;

class JWT extends JWTInterface
{
    /**
     * @var \Lcobucci\JWT\Builder
     */
    protected $builder;

    protected $publicKey;

    protected $privateKey;

    protected $signerMap = [
        'HS256' => HS256::class,
        'HS384' => HS384::class,
        'HS512' => HS512::class,
        'RS256' => RS256::class,
        'RS384' => RS384::class,
        'RS512' => RS512::class,
        'ES256' => ES256::class,
        'ES384' => ES384::class,
        'ES512' => ES512::class,
    ];

    protected $registedClaimMap = [
        'aud', 'exp', 'jti', 'iat', 'iss', 'nbf', 'sub',
    ];
    public function __construct(?string $name = 'default')
    {
        $config = config('jwt.stores.' . $name);
        $this->config = array_merge([

        ], $config);

        $iss = (string)$this->config['iss'];
        $this->builder = $this->configuration->builder()
            ->issuedBy($iss);

        $signer = (string)$this->config['signer'];
        if (! array_key_exists($signer, $this->signerMap)) {
            throw new JwtException('invalid singer: ' . $signer);
        }
        $signerObj = new $this->signerMap[$signer];
        switch ($signer) {
            case 'ES256':
            case 'ES384':
            case 'ES512':
            case 'RS256':
            case 'RS384':
            case 'RS512':
                $private_key = InMemory::file((string)$this->config['private_key']);
                $public_key = InMemory::file((string)$this->config['public_key']);
                break;
            case 'HS256':
            case 'HS384':
            case 'HS512':
                $public_key = $private_key = InMemory::base64Encoded((string)$this->config['signer_key']);
                break;
        }
        $this->configuration = Configuration::forAsymmetricSigner(
            $signerObj,
            $private_key,
            $public_key
        );
    }

    public function make(array $claims): string
    {
        $now = new \DateTimeImmutable();
        $ttl = (string)$this->config['expires_at'];
        $this->builder
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($now->add(new \DateInterval('P' . $ttl . 'S')));
        foreach ( $claims as $key => $value ) {
            $this->builder->withClaim( $key,$value );
        }
        $token = $this->builder->getToken($this->configuration->signer(), $this->configuration->signingKey());
        return $token->toString();
    }

    /**
     *
     */
    public function parse(string $jwt): array
    {
        $claims = $this->validate($jwt);
        return array_diff_key($claims, array_flip($this->registedClaimMap));
    }

    /**
     *
     */
    public function validate(string $jwt): array
    {
        $token = $this->configuration->parser()->parse($jwt);
        /**
         * @var \Lcobucci\JWT\Token\Plain $token
         */
        $claims = $token->claims()->all();
        $now = new \DateTimeImmutable();
        if (
            (! $token instanceof UnencryptedToken) ||
            ($token->headers()->get('alg') !== $this->configuration->signer()->algorithmId()) ||
            (! $this->configuration->signer()->verify($token->signature()->hash(), $token->payload(), $this->configuration->verificationKey())) ||
            (! $token->hasBeenIssuedBy($this->config['iss'])) ||
            (! $token->isMinimumTimeBefore($now))
        ) {
            throw new JwtInvalidException();
        }

        if ($token->isExpired($now)) {
            throw new JwtExpiredException();
        }
        return $claims;
    }

    public function getConfig(): array
    {
        return array_diff_key($this->config, array_flip(['signer_key', 'public_key', 'private_key']));
    }
}