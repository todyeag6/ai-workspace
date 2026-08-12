<?php

/**
 * P4-T3 — Client deploy config validator (CLI, fail-closed).
 *
 * Loads a deploy.config.php (BR-9.1 record + DSNs), validates it with
 * App\Deploy\DeployClientValidator, and writes a resolved env file for
 * docker compose. Refuses to proceed on any validation failure (FR-CONF-002
 * fail-closed spirit). This is a thin wrapper — all rules live in the testable
 * DeployClientValidator class.
 */

declare(strict_types=1);

use App\Deploy\DeployClientValidator;
use App\Deploy\DeployConfigException;

require __DIR__ . '/../vendor/autoload.php';

$configPath = $argv[1] ?? null;
if ($configPath === null) {
    fwrite(STDERR, "usage: php scripts/deploy-client.php <deploy.config.php>\n");
    exit(2);
}

if (!is_file($configPath)) {
    fwrite(STDERR, "deploy config not found: $configPath\n");
    exit(2);
}

$config = require $configPath;
if (!is_array($config)) {
    fwrite(STDERR, "deploy config must return an array\n");
    exit(2);
}

try {
    $resolved = (new DeployClientValidator())->validate($config);
} catch (DeployConfigException $e) {
    fwrite(STDERR, "DEPLOY REFUSED: " . $e->getMessage() . "\n");
    exit(1);
}

// Emit the resolved env (compose consumes it). No secrets are echoed back.
foreach (['deployment_model', 'data_location', 'model_location', 'config_version'] as $k) {
    echo sprintf("%s=%s\n", $k, $resolved[$k] ?? '');
}
echo "DEPLOY_VALIDATED=1\n";
exit(0);
