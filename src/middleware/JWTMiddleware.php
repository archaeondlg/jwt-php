<?php

namespace app\middleware;

use archaeon\jwt\exception\JwtExpiredException;
use archaeon\jwt\exception\JwtInvalidException;
use archaeon\jwt\facade\JWTAuth;
use support\ErrorCode;
use Webman\MiddlewareInterface;
use Webman\Http\Response;
use Webman\Http\Request;

class JWTMiddleware implements MiddlewareInterface
{
    public function process(Request $request, callable $handler) : Response
    {
        $token = JWTAuth::getToken();
        try {
            $claims = JWTAuth::parse($token);
        } catch (JwtExpiredException) {

        } catch (JwtInvalidException) {
            // throw new
            return fail(ErrorCode::ExpiredToken);
        }
        /**
         * @var \support\Request $request
         */
        $request->setModel($claims);
        return $handler($request);
    }
}