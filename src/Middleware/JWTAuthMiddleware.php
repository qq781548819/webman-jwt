<?php


namespace Nyuwa\Jwt\Middleware;


use Nyuwa\Jwt\Exception\TokenValidException;
use Nyuwa\Jwt\JWT;
use Nyuwa\Jwt\Util\JWTUtil;
use Webman\Http\Request;
use Webman\Http\Response;
use Webman\MiddlewareInterface;

class JWTAuthMiddleware implements MiddlewareInterface
{

    /**
     * @var JWT
     */
    protected $jwt;
    /**
     * JWTAuthMiddleware constructor.
     */
    public function __construct()
    {
        $this->jwt = new JWT();
    }


    public function process(Request $request, callable $handler): Response
    {
        $isValidToken = false;
        // 根据具体业务判断逻辑走向，这里假设用户携带的token有效
        $token = $request->header('Authorization') ?? '';
        if (strlen($token) > 0) {
            $token = JWTUtil::handleToken($token);
            if ($token !== false && $this->jwt->checkToken($token)) {
                $isValidToken = true;
            }
        }
        if ($isValidToken) {
            return $handler($request);
        }

        throw new TokenValidException('Token authentication does not pass', 401);

    }
}
