<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use DateInterval;
use DateTimeImmutable;
use InvalidArgumentException;
use JsonException;
use RuntimeException;

/**
 * The Finding Engine: "deduplicate, classify, score, map standards, assign
 * owner and SLA" (FRD section 2), implementing SFR-FIND-001 and the decision
 * half of SFR-FIND-002 and SFR-AI-001.
 *
 * WHY THIS COMPONENT DECIDES AND NEVER PERSISTS
 * ----------------------------------------------
 * FindingRepository only moves rows; the decision about what a piece of
 * evidence MEANS - which finding it is, how bad it is, which standards it maps
 * to, when it must be fixed by - lives here. That is the same decide-not-act
 * split ScopeManager / SafetyMonitor / EvidenceProcessor use in this module:
 * the judge holds no socket and no database handle. Every method returns a
 * value; whether it is stored is somebody else's call.
 *
 * WHY THE FINGERPRINT IS DETERMINISTIC AND NARROW (SFR-FIND-001/002)
 * -------------------------------------------------------------------
 * The fingerprint is what makes a repeat sighting recognisable as the SAME
 * finding, so it must be stable across runs and must NOT include anything that
 * legitimately varies between runs. It is therefore a digest of exactly three
 * things: the category, the canonical asset, and a normalised signature of
 * what was observed. Deliberately excluded:
 *   - the scan id and timestamp   (every run has new ones - including them
 *                                  would make every sighting a new finding,
 *                                  which is the dedup bug SFR-FIND-002 exists
 *                                  to prevent)
 *   - the scanner and its version (the same weakness found by a re-versioned
 *                                  tool is the same weakness; including the
 *                                  version would fork the finding on every
 *                                  adapter upgrade)
 *   - severity and confidence     (these are OPINIONS that a human may revise;
 *                                  a finding must not fork because someone
 *                                  re-rated it)
 * Note this differs on purpose from EvidenceProcessor's content hash, which
 * DOES include scanner/version/timestamp - that hash identifies an ARTIFACT,
 * this one identifies an ISSUE. Two different questions, two different digests.
 *
 * WHY SCORING PRODUCES A SUGGESTION AND NOT A DECISION (SFR-AI-001)
 * ------------------------------------------------------------------
 * BRD section 5: "Automated severity is advisory until validated according to
 * the service plan." So score() is named for what it is - it returns a
 * suggested severity, and the only place it can land is the finding's
 * ai_suggested_severity field. The engine has no method that writes an
 * authoritative severity; that transition exists only on FindingRepository and
 * only with a named human. The requirement is structural, not a checked rule.
 *
 * WHY THE SLA TABLE IS INJECTED
 * ------------------------------
 * SBR-5.1 requires "configured" remediation deadlines and the baseline
 * specifies no numbers. The hours therefore come from
 * config/security/FINDING_SLA.php (a ratifiable file), not from a constant
 * here - see that file's header. Injecting it also keeps this class pure and
 * lets a test pin the policy.
 *
 * NO DATABASE, NO CLOCK. Every moment is a parameter, so given the same inputs
 * the engine returns the same answer - which is what makes fingerprinting,
 * scoring and SLA maths provable without a scanner, a tenant or a socket.
 *
 * © AI WebScapes 2026
 */
final class FindingEngine
{
    private const HASH_ALGO = 'sha256';

    /**
     * Severity rank, used to combine the base severity of an issue class with
     * the evidence confidence. Higher is worse.
     *
     * @var array<string, int>
     */
    private const SEVERITY_RANK = [
        Finding::SEVERITY_INFORMATIONAL => 0,
        Finding::SEVERITY_LOW => 1,
        Finding::SEVERITY_MEDIUM => 2,
        Finding::SEVERITY_HIGH => 3,
        Finding::SEVERITY_CRITICAL => 4,
    ];

    /**
     * The standards each scan category maps onto (SFR-FIND-001 "standards
     * mapping"). Sourced from the approved Standards Register: OWASP ASVS
     * 5.0.x, OWASP Top 10:2025, OWASP API Security Top 10:2023, OWASP
     * GenAI/LLM Top 10, OWASP AISVS and NIST CSF 2.0.
     *
     * An ALLOWLIST, not a guess: a category with no mapping returns an empty
     * list rather than a plausible-looking invention, because a compliance
     * report citing a standard the finding was never assessed against is worse
     * than one that cites none.
     *
     * @var array<string, list<string>>
     */
    private const STANDARDS_MAP = [
        Finding::CATEGORY_TRANSPORT_EXPOSURE => [
            'OWASP ASVS 5.0:V9-Communication',
            'OWASP Top 10:2025:A02-Cryptographic-Failures',
            'NIST CSF 2.0:PR.DS',
        ],
        Finding::CATEGORY_HTTP_CONFIGURATION => [
            'OWASP ASVS 5.0:V13-Configuration',
            'OWASP Top 10:2025:A05-Security-Misconfiguration',
            'NIST CSF 2.0:PR.PS',
        ],
        Finding::CATEGORY_CONTENT_EXPOSURE => [
            'OWASP ASVS 5.0:V8-Data-Protection',
            'OWASP Top 10:2025:A01-Broken-Access-Control',
            'NIST CSF 2.0:PR.DS',
        ],
        Finding::CATEGORY_AUTHENTICATION_SESSION => [
            'OWASP ASVS 5.0:V6-Authentication',
            'OWASP ASVS 5.0:V7-Session-Management',
            'OWASP Top 10:2025:A07-Identification-and-Authentication-Failures',
            'NIST CSF 2.0:PR.AA',
        ],
        Finding::CATEGORY_AUTHORIZATION_API => [
            'OWASP ASVS 5.0:V4-Access-Control',
            'OWASP API Security:2023:API1-Broken-Object-Level-Authorization',
            'OWASP API Security:2023:API4-Unrestricted-Resource-Consumption',
            'NIST CSF 2.0:PR.AA',
        ],
        Finding::CATEGORY_INPUT_HANDLING => [
            'OWASP ASVS 5.0:V5-Validation-Sanitization-Encoding',
            'OWASP Top 10:2025:A03-Injection',
            'NIST CSF 2.0:PR.PS',
        ],
        Finding::CATEGORY_DEPENDENCIES => [
            'OWASP ASVS 5.0:V10-Malicious-Code',
            'OWASP Top 10:2025:A06-Vulnerable-and-Outdated-Components',
            'NIST SSDF:PW.4',
        ],
        Finding::CATEGORY_AI_SECURITY => [
            'OWASP GenAI:LLM01-Prompt-Injection',
            'OWASP GenAI:LLM02-Sensitive-Information-Disclosure',
            'OWASP GenAI:LLM06-Excessive-Agency',
            'OWASP AISVS',
            'NIST AI RMF 1.0:MEASURE',
        ],
        Finding::CATEGORY_OPERATIONAL_CONTROLS => [
            'OWASP ASVS 5.0:V16-Security-Logging-and-Error-Handling',
            'NIST CSF 2.0:DE.CM',
        ],
    ];

    /**
     * Hours from first sighting to the remediation deadline, per severity.
     * The DEFAULT plan (config/security/FINDING_SLA.php, ratified).
     *
     * @var array<string, int|null>
     */
    private array $slaHours;

    /**
     * Per-plan (support-tier) overrides, keyed by tier. A tier only lists the
     * severities it changes; anything absent falls back to $slaHours.
     *
     * @var array<string, array<string, int|null>>
     */
    private array $slaOverrides;

    /**
     * @param array<string, int|null>|null $slaHours Severity => hours until due,
     *        or null for "no deadline". Defaults to the ratified policy in
     *        config/security/FINDING_SLA.php (SBR-5.1).
     * @param array<string, array<string, int|null>> $slaOverrides Per-tier deltas
     *        from config/security/FINDING_SLA_PLANS.php.
     */
    public function __construct(?array $slaHours = null, array $slaOverrides = [])
    {
        $policy = $slaHours ?? self::defaultSlaPolicy();
        self::assertCompletePolicy($policy);

        $this->slaHours = $policy;
        // When no explicit override map was supplied, load the per-plan deltas
        // from config so the production path honours them without the caller
        // having to know the file exists.
        $this->slaOverrides = $slaOverrides === [] ? self::planOverrides() : $slaOverrides;
    }

    /**
     * Resolves the hours for a severity under a given plan (tier), falling
     * back to the default plan for any severity the tier does not override.
     */
    private function hoursFor(string $severity, ?string $plan): ?int
    {
        if ($plan !== null && isset($this->slaOverrides[$plan][$severity])) {
            return $this->slaOverrides[$plan][$severity];
        }

        return $this->slaHours[$severity] ?? null;
    }

    /**
     * The stable identity of an ISSUE (SFR-FIND-001 "unique fingerprint").
     *
     * Same category + same asset + same normalised signature = same finding,
     * run after run, tool version after tool version. See the class comment for
     * what is deliberately excluded and why.
     *
     * @param array<string, mixed> $signature What was observed, structurally.
     */
    public function fingerprint(string $category, string $canonicalAsset, array $signature): string
    {
        $this->assertCategory($category);

        $asset = trim($canonicalAsset);
        if ($asset === '') {
            throw new InvalidArgumentException(
                'A fingerprint needs the canonical asset the finding concerns (SFR-FIND-001).'
            );
        }

        $canonical = [
            'category' => $category,
            // Case-folded: two spellings of one host are one finding.
            'asset' => strtolower($asset),
            'signature' => $this->canonicalize($signature),
        ];

        try {
            $json = json_encode($canonical, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Could not canonicalize a finding for fingerprinting.', 0, $e);
        }

        return hash(self::HASH_ALGO, $json);
    }

    /**
     * The SUGGESTED severity for an issue (FRD section 2 "score"), combining
     * the base severity of the issue class with the confidence of the evidence
     * behind it - two of the inputs BRD section 5 enumerates.
     *
     * ADVISORY BY CONSTRUCTION (SFR-AI-001, BRD section 5). The return value is
     * a suggestion. Nothing in this class can write it to Finding::severity;
     * only a human decision through FindingRepository::reviseSeverity() can.
     *
     * Low-confidence evidence is de-rated by one rank: an unvalidated
     * observation should not, on its own, raise a critical alarm. High
     * confidence does NOT promote - promoting on the machine's own confidence
     * would be the engine talking itself into a higher severity.
     */
    public function score(string $baseSeverity, string $confidence): string
    {
        $this->assertSeverity($baseSeverity);

        if (!in_array($confidence, Finding::CONFIDENCES, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown evidence confidence "%s". It must be one of: %s.',
                $confidence,
                implode(', ', Finding::CONFIDENCES)
            ));
        }

        $rank = self::SEVERITY_RANK[$baseSeverity];

        if ($confidence === Finding::CONFIDENCE_LOW) {
            $rank = max(0, $rank - 1);
        }

        return Finding::SEVERITIES[$rank];
    }

    /**
     * The standards a finding in this category maps onto (SFR-FIND-001
     * "standards mapping").
     *
     * An unmapped category returns an empty list rather than a guess - see
     * STANDARDS_MAP.
     *
     * @return list<string>
     */
    public function mapStandards(string $category): array
    {
        $this->assertCategory($category);

        return self::STANDARDS_MAP[$category] ?? [];
    }

    /**
     * The remediation deadline for a finding of this severity, first seen at
     * this moment (SFR-FIND-001 "SLA", SBR-5.1).
     *
     * $plan is the support tier (a "plan", owner 2026-08-10): a tier may
     * override the default hours for this severity. Null / unknown tier falls
     * back to the ratified default.
     *
     * Null means the severity carries no deadline (informational). Measured
     * from FIRST sighting, not from the latest one: a finding that has been
     * open for a month is not given a fresh clock because it was seen again.
     */
    public function slaDueAt(string $severity, DateTimeImmutable $firstSeenAt, ?string $plan = null): ?DateTimeImmutable
    {
        $this->assertSeverity($severity);

        $hours = $this->hoursFor($severity, $plan);
        if ($hours === null) {
            return null;
        }

        return $firstSeenAt->add(new DateInterval('PT' . $hours . 'H'));
    }

    /**
     * Whether a finding of this severity must raise a configured alert
     * (SBR-5.1: "critical and high findings shall generate configured alerts
     * and remediation deadlines").
     *
     * The engine DECIDES that an alert is owed; sending it is somebody else's
     * job - this class opens no socket.
     */
    public function requiresAlert(string $severity): bool
    {
        $this->assertSeverity($severity);

        return in_array($severity, [Finding::SEVERITY_CRITICAL, Finding::SEVERITY_HIGH], true);
    }

    /**
     * The complete decision for a newly observed issue: fingerprint, standards
     * mapping, suggested severity and SLA, as a plain array the repository can
     * store.
     *
     * The authoritative severity is set to the SUGGESTION here because a brand
     * new finding has had no human review yet and something must be written;
     * what makes that safe is that the finding is born with status `open` and
     * NOT `confirmed`, so no report can present it as validated, and the same
     * value is recorded in ai_suggested_severity so the provenance of the
     * number stays visible (SFR-AI-001, BRD section 5 "advisory until
     * validated").
     *
     * @param array<string, mixed> $signature
     *
     * @return array{
     *     fingerprint: string,
     *     title: string,
     *     category: string,
     *     severity: string,
     *     confidence: string,
     *     standards_mapping: list<string>,
     *     sla_due_at: DateTimeImmutable|null,
     *     ai_suggested_severity: string,
     *     requires_alert: bool
     * }
     */
    public function classify(
        string $title,
        string $category,
        string $canonicalAsset,
        array $signature,
        string $baseSeverity,
        string $confidence,
        DateTimeImmutable $observedAt,
        ?string $plan = null
    ): array {
        if (trim($title) === '') {
            throw new InvalidArgumentException('A finding must carry a title (SFR-FIND-001).');
        }

        $suggested = $this->score($baseSeverity, $confidence);

        return [
            'fingerprint' => $this->fingerprint($category, $canonicalAsset, $signature),
            'title' => trim($title),
            'category' => $category,
            'severity' => $suggested,
            'confidence' => $confidence,
            'standards_mapping' => $this->mapStandards($category),
            'sla_due_at' => $this->slaDueAt($suggested, $observedAt, $plan),
            'ai_suggested_severity' => $suggested,
            'requires_alert' => $this->requiresAlert($suggested),
        ];
    }

    /**
     * The ratifiable SLA policy from config/security/FINDING_SLA.php.
     *
     * @return array<string, int|null>
     */
    private static function defaultSlaPolicy(): array
    {
        $path = dirname(__DIR__, 2) . '/config/security/FINDING_SLA.php';
        if (!is_file($path)) {
            throw new RuntimeException(sprintf(
                'The finding SLA policy file is missing at "%s"; deadlines are configured, '
                . 'not hardcoded (SBR-5.1).',
                $path
            ));
        }

        /** @var mixed $loaded */
        $loaded = require $path;
        if (!is_array($loaded)) {
            throw new RuntimeException('The finding SLA policy file must return an array.');
        }

        $policy = [];
        foreach ($loaded as $severity => $hours) {
            if (!is_string($severity)) {
                continue;
            }

            if ($hours === null) {
                $policy[$severity] = null;
                continue;
            }

            if (!is_int($hours)) {
                throw new RuntimeException(sprintf(
                    'The finding SLA for "%s" must be an integer number of hours or null.',
                    $severity
                ));
            }

            $policy[$severity] = $hours;
        }

        return $policy;
    }

    /**
     * The per-plan (support-tier) overrides from config/security/FINDING_SLA_PLANS.php.
     * A tier lists only the severities it changes; the rest fall back to the
     * default plan. Returns an empty array when the file is absent (so a build
     * without per-plan config keeps working on the default plan only).
     *
     * @return array<string, array<string, int|null>>
     */
    private static function planOverrides(): array
    {
        $path = dirname(__DIR__, 2) . '/config/security/FINDING_SLA_PLANS.php';
        if (!is_file($path)) {
            return [];
        }

        /** @var mixed $loaded */
        $loaded = require $path;
        if (!is_array($loaded)) {
            return [];
        }

        $out = [];
        foreach ($loaded as $tier => $deltas) {
            if (!is_string($tier) || !is_array($deltas)) {
                continue;
            }

            $tierMap = [];
            foreach ($deltas as $severity => $hours) {
                if (!is_string($severity)) {
                    continue;
                }

                $tierMap[$severity] = $hours === null ? null : (int) $hours;
            }

            $out[$tier] = $tierMap;
        }

        return $out;
    }

    /**
     * Fail closed: a default policy that omits a severity would silently leave
     * some findings with no deadline, and "no deadline" must be a stated
     * decision, not an omission.
     *
     * @param array<string, int|null> $policy
     */
    private static function assertCompletePolicy(array $policy): void
    {
        foreach (Finding::SEVERITIES as $severity) {
            if (!array_key_exists($severity, $policy)) {
                throw new InvalidArgumentException(sprintf(
                    'The SLA policy does not cover severity "%s" (SBR-5.1, SFR-FIND-001).',
                    $severity
                ));
            }

            $hours = $policy[$severity];
            if ($hours !== null && $hours <= 0) {
                throw new InvalidArgumentException(sprintf(
                    'The SLA for severity "%s" must be a positive number of hours, or null for none.',
                    $severity
                ));
            }
        }
    }

    private function assertCategory(string $category): void
    {
        if (!in_array($category, Finding::CATEGORIES, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown finding category "%s". It must be one of: %s (allowlist, AC-002).',
                $category,
                implode(', ', Finding::CATEGORIES)
            ));
        }
    }

    private function assertSeverity(string $severity): void
    {
        if (!array_key_exists($severity, self::SEVERITY_RANK)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown severity "%s". It must be one of: %s (allowlist, AC-002).',
                $severity,
                implode(', ', Finding::SEVERITIES)
            ));
        }
    }

    /**
     * Recursively canonicalizes mixed content into a stable, key-sorted form
     * so identical observations always fingerprint identically.
     */
    private function canonicalize(mixed $value): mixed
    {
        if (is_array($value)) {
            $out = [];
            // Sort by key so key order never influences the digest.
            $keys = array_keys($value);
            sort($keys);
            foreach ($keys as $key) {
                $out[$key] = $this->canonicalize($value[$key]);
            }

            return $out;
        }

        return $value;
    }
}
