<?php
declare(strict_types=1);

namespace Nyuwa\Jwt;

interface JWTInterface
{
    public function setSceneConfig(string $scene = 'default', $value = null);
    public function getSceneConfig(string $scene = 'default');
    public function setScene(string $scene);
    public function getScene();
}
