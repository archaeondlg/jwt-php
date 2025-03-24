<?php

return [
    'stores'  => [
        'default'   => [
            'login_type'    => 'mpo', //  登录方式，sso为单点登录，mpo为多点登录
            'auto_refresh'  => false,
            'type'          => 'Header',
            'signer'        => 'HS256',
            'iss'           => 'wapi',
            'signer_key'    => 'dGhpcyUyMGlzJTIwZGxnJTI3cyUyMHdlYm1hbiUyMGFwaSUyMGZyYW1ld29yayUyQyUyMG5hbWVkJTIwd2ViYXBp', // 足够长的base64字符串
            'public_key'    => 'file://path/public.key',
            'private_key'   => 'file://path/private.key',
            'expires_at'    => 86400,
            'refresh_ttL'   => 172800,
            'leeway'        => 0,

            //是否开启黑名单，单点登录和多点登录的注销、刷新使原token失效，必须要开启黑名单
            'blacklist_enabled'      => true,
            //黑名单缓存的前缀
            'blacklist_prefix'       => 'tkbl_',
            //黑名单的宽限时间 单位为：秒，注意：如果使用单点登录，该宽限时间无效
            'blacklist_grace_period' => 0,
        ],
    ]
];