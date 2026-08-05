<?php declare(strict_types=1);
/**
 * © AR WebScapes 2025
 */

return [
    'app' => [
        'name' => 'Aiwebscapes',
        'env' => 'production',
        'base_url' => 'https://aiwebscapes.com',
        'support_email' => 'support@aiwebscapes.com',
        'owner_email' => 'admin@aiwebscapes.com',
    ],

    'db' => [
        'host' => 'localhost',
        'name' => 'your_database_name',
        'user' => 'your_database_user',
        'pass' => 'your_database_password',
        'charset' => 'utf8mb4',
    ],

    'security' => [
        'csrf_ttl_seconds' => 1800,
        'session_ttl_seconds' => 1800,
        'rate_limit_window_seconds' => 300,
        'rate_limit_max_attempts' => 5,
        'ip_hash_secret' => 'replace-this-with-a-long-random-secret',
    ],
];