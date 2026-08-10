<?php

declare(strict_types=1);

namespace App\SecurityAgent;

use DateTimeImmutable;
use InvalidArgumentException;

/**
 * One AI triage opinion about one finding (SFR-AI-001) — an immutable value
 * object that is, by construction, incapable of being a decision.
 *
 * WHAT THIS OBJECT CAN SAY, AND WHAT IT STRUCTURALLY CANNOT
 * ----------------------------------------------------------
 * SFR-AI-001 permits exactly three things: summarize, suggest a severity,
 * suggest a remediation. Those are the three fields here, plus the priority
 * ORDER the FRD's section 2 description asks for ("summarize and prioritize
 * evidence"). What is deliberately absent is the whole vocabulary of decision:
 * there is no status field, no confirmed flag, no owner, no risk-acceptance
 * approver, no close reason, no authoritative severity. A caller holding this
 * object cannot express "this finding is confirmed" or "close this" because
 * there is no field in which to write it.
 *
 * That is the same technique Finding::withAiSuggestion() uses one layer down,
 * and the two reinforce each other: the only sink for this object is
 * FindingRepository::attachAiSuggestion(), whose signature accepts precisely
 * these three advisory values. Even a compromised triage path — a model that
 * was successfully injected, an operator who mis-wired a caller — can produce
 * nothing more consequential than a suggestion sitting in an advisory column.
 *
 * WHY suggestedSeverity IS VALIDATED AGAINST THE ALLOWLIST HERE
 * -------------------------------------------------------------
 * AC-002: an unknown enum value is refused, not stored. A model that returns
 * "SEVERE" or "urgent!!!" has not produced a severity, and coercing it to
 * something plausible would be the platform inventing an opinion it then
 * attributes to the model. Refuse at the boundary, where the mistake is
 * visible.
 *
 * WHY THE MODEL IDENTIFIER AND POLICY VERSION ARE CARRIED
 * -------------------------------------------------------
 * FR-AI-002 requires a call to state its model/version and configuration
 * version; SFR-AUD-001 requires the change to be audited. Carrying them on the
 * suggestion means the audit row can name WHICH model, under WHICH policy,
 * produced the opinion a human is about to read — provenance travels with the
 * claim rather than being reconstructed from logs later.
 *
 * NO CLOCK OF ITS OWN. producedAt is passed in, so the record reflects the
 * observed moment and every path stays deterministic under test.
 *
 * © AI WebScapes 2026
 */
final class TriageSuggestion
{
    /**
     * The lowest priority rank. Rank 1 is "look at this first"; a larger
     * number is less urgent. Zero and negatives are refused — a priority
     * order that starts at zero invites "0 means unset" ambiguity.
     */
    private const MIN_PRIORITY = 1;

    /**
     * @param int         $findingId            The finding this opinion concerns.
     * @param string|null $suggestedSeverity    An allowlisted severity, or null for "no opinion".
     * @param string|null $suggestedRemediation Advisory fix guidance, or null.
     * @param string      $summary              The plain-language summary (SFR-AI-001 "summarize").
     * @param int         $priorityRank         1 = highest. FRD section 2 "prioritize".
     * @param string      $modelIdentifier      model@version that produced it (FR-AI-002).
     * @param string      $policyVersion        The triage policy config version.
     */
    public function __construct(
        private readonly int $findingId,
        private readonly ?string $suggestedSeverity,
        private readonly ?string $suggestedRemediation,
        private readonly string $summary,
        private readonly int $priorityRank,
        private readonly string $modelIdentifier,
        private readonly string $policyVersion,
        private readonly DateTimeImmutable $producedAt,
    ) {
        if ($findingId <= 0) {
            throw new InvalidArgumentException(
                'A triage suggestion must concern a real finding; 0 or negative is not one.'
            );
        }

        // AC-002: allowlist, not a guess. An unrecognised severity from a
        // model is a failed extraction, not a new severity level.
        if ($suggestedSeverity !== null && !in_array($suggestedSeverity, Finding::SEVERITIES, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown suggested severity "%s". It must be one of: %s (allowlist, AC-002).',
                $suggestedSeverity,
                implode(', ', Finding::SEVERITIES)
            ));
        }

        if (trim($summary) === '') {
            throw new InvalidArgumentException(
                'A triage suggestion must carry a summary; summarising is the one thing '
                . 'SFR-AI-001 asks this component to do.'
            );
        }

        if ($priorityRank < self::MIN_PRIORITY) {
            throw new InvalidArgumentException(sprintf(
                'A priority rank starts at %d (highest); %d is not a rank.',
                self::MIN_PRIORITY,
                $priorityRank
            ));
        }

        if (trim($modelIdentifier) === '') {
            throw new InvalidArgumentException(
                'A triage suggestion must name the model that produced it (FR-AI-002, SFR-AUD-001).'
            );
        }

        if (trim($policyVersion) === '') {
            throw new InvalidArgumentException(
                'A triage suggestion must name the policy version it was produced under '
                . '(FR-AI-002 configuration version).'
            );
        }
    }

    public function findingId(): int
    {
        return $this->findingId;
    }

    public function suggestedSeverity(): ?string
    {
        return $this->suggestedSeverity;
    }

    public function suggestedRemediation(): ?string
    {
        return $this->suggestedRemediation;
    }

    public function summary(): string
    {
        return $this->summary;
    }

    public function priorityRank(): int
    {
        return $this->priorityRank;
    }

    public function modelIdentifier(): string
    {
        return $this->modelIdentifier;
    }

    public function policyVersion(): string
    {
        return $this->policyVersion;
    }

    public function producedAt(): DateTimeImmutable
    {
        return $this->producedAt;
    }

    /**
     * The advisory projection a report or operator view may show.
     *
     * Every key is prefixed or named so a reader cannot mistake it for the
     * authoritative field: `suggested_severity`, never `severity`. A report
     * that renders this array next to a Finding cannot accidentally present
     * the machine's opinion as the human's decision, because the two never
     * share a key name (BRD section 5: advisory until validated).
     *
     * @return array<string, scalar|null>
     */
    public function toAdvisoryArray(): array
    {
        return [
            'finding_id' => $this->findingId,
            'suggested_severity' => $this->suggestedSeverity,
            'suggested_remediation' => $this->suggestedRemediation,
            'summary' => $this->summary,
            'priority_rank' => $this->priorityRank,
            'model' => $this->modelIdentifier,
            'policy_version' => $this->policyVersion,
            'produced_at' => $this->producedAt->format('Y-m-d H:i:s'),
            // Stated explicitly in the payload itself, so a downstream consumer
            // that never read SFR-AI-001 still cannot claim it did not know.
            'authoritative' => false,
        ];
    }
}
