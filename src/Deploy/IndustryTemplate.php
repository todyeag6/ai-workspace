<?php

/**
 * Industry template loader (P5-T3).
 *
 * Loads a sector preset from config/deploy/templates/<name>.php. Each preset
 * composes a Phase-4 hardware tier (small/medium/large) with policy defaults and
 * sector notes. Pure — no IO beyond reading its own known template directory.
 * An unknown template name is refused (AC-002 allowlist of templates).
 */

declare(strict_types=1);

namespace App\Deploy;

use App\Deploy\DeployConfigException;

final class IndustryTemplate
{
    /** @var list<string> Allowed template names (AC-002 allowlist). */
    private const KNOWN = ['default', 'legal', 'healthcare', 'finance'];

    /**
     * @return array{hardware_profile: string, policy_defaults: array<string,mixed>, sector_notes: string}
     *
     * @throws DeployConfigException When the template name is not in the allowlist
     *                              or the file is missing/malformed.
     */
    public static function load(string $name, string $dir): array
    {
        if (!in_array($name, self::KNOWN, true)) {
            throw new DeployConfigException(sprintf('Unknown industry template: %s', $name));
        }
        $path = rtrim($dir, '/') . '/' . $name . '.php';
        if (!is_file($path)) {
            throw new DeployConfigException(sprintf('Template file missing: %s', $path));
        }
        $config = require $path;
        if (
            !is_array($config)
            || !isset($config['hardware_profile'], $config['policy_defaults'], $config['sector_notes'])
            || !in_array($config['hardware_profile'], ['small', 'medium', 'large'], true)
        ) {
            throw new DeployConfigException(sprintf('Malformed template: %s', $name));
        }
        /** @var array{hardware_profile: string, policy_defaults: array<string,mixed>, sector_notes: string} $config */
        return $config;
    }
}
