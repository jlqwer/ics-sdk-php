<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInitce140fa992b22f0285dde4a5556fbe76
{
    public static $prefixLengthsPsr4 = array (
        'I' => 
        array (
            'Ics\\' => 4,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Ics\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src/ics',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInitce140fa992b22f0285dde4a5556fbe76::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInitce140fa992b22f0285dde4a5556fbe76::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInitce140fa992b22f0285dde4a5556fbe76::$classMap;

        }, null, ClassLoader::class);
    }
}
