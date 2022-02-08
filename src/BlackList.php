<?php


namespace Nyuwa\Jwt;


use Lcobucci\JWT\Token\Plain;
use Nyuwa\Jwt\Util\TimeUtil;
use Psr\Container\ContainerInterface;
use Psr\SimpleCache\CacheInterface;
use support\Cache;

class BlackList extends AbstractJWT
{

    public function __construct()
    {
        parent::__construct();
    }

    /**
     * 把token加入到黑名单中
     * @param Plain $token
     * @return mixed
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function addTokenBlack(Plain $token, array $config = [], $ssoSelfExp = false)
    {
        $claims = $token->claims()->all();
        $ssoSelfExp && $claims['iat']->modify('+1 second');
        if ($config['blacklist_enabled']) {
            $cacheKey = $this->getCacheKey($claims['jti']);
            Cache::set(
                $cacheKey,
                ['valid_until' => $this->getGraceTimestamp($claims, $config)],
                $this->getSecondsUntilExpired($claims, $config)
            );
        }
        return $claims;
    }

    /**
     * Get the number of seconds until the token expiry.
     *
     * @return int
     */
    protected function getSecondsUntilExpired($claims, array $config)
    {
        $exp = TimeUtil::timestamp($claims['exp']->getTimestamp());
        $iat = TimeUtil::timestamp($claims['iat']->getTimestamp());

        // get the latter of the two expiration dates and find
        // the number of minutes until the expiration date,
        // plus 1 minute to avoid overlap
        return $exp->max($iat->addSeconds($config['blacklist_cache_ttl']))->diffInSeconds();
    }

    /**
     * Get the timestamp when the blacklist comes into effect
     * This defaults to immediate (0 seconds).
     *
     * @return int
     */
    protected function getGraceTimestamp($claims, array $config)
    {
        $loginType = $config['login_type'];
        $gracePeriod = $config['blacklist_grace_period'];
        if ($loginType == 'sso') $gracePeriod = 0;
        return TimeUtil::timestamp($claims['iat']->getTimestamp())->addSeconds($gracePeriod)->getTimestamp();
    }

    /**
     * 判断token是否已经加入黑名单
     * @param $claims
     * @return bool
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function hasTokenBlack($claims, array $config = [])
    {
        $cacheKey = $this->getCacheKey($claims['jti']);
        if ($config['blacklist_enabled'] && $config['login_type'] == 'mpop') {
            $val = Cache::get($cacheKey);
            return !empty($val) && !TimeUtil::isFuture($val['valid_until']);
        }

        if ($config['blacklist_enabled'] && $config['login_type'] == 'sso') {
            $val = Cache::get($cacheKey);
            // 这里为什么要大于等于0，因为在刷新token时，缓存时间跟签发时间可能一致，详细请看刷新token方法
            if (! is_null($claims['iat']) && !empty($val['valid_until'])) {
                $isFuture = ($claims['iat']->getTimestamp() - $val['valid_until']) >= 0;
            } else {
                $isFuture = false;
            }
            // check whether the expiry + grace has past
            return !$isFuture;
        }
        return false;
    }

    /**
     * 黑名单移除token
     * @param $key  token 中的jit
     * @return bool
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function remove($key)
    {
        return Cache::delete($key);
    }

    /**
     * 移除所有的token缓存
     * @return bool
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function clear()
    {
        $cachePrefix = $this->getSceneConfig($this->getScene())['blacklist_prefix'];
        return Cache::delete("{$cachePrefix}.*");
    }

    /**
     * @param string $jti
     * @return string
     */
    private function getCacheKey(string $jti)
    {
        $config = $this->getSceneConfig($this->getScene());
        return "{$config['blacklist_prefix']}_" . $jti;
    }

    /**
     * Get the cache time limit.
     *
     * @return int
     */
    public function getCacheTTL()
    {
        return $this->getSceneConfig($this->getScene())['ttl'];
    }

}
