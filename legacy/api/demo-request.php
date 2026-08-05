<?php declare(strict_types=1);
/**
 * © AI WebScapes 2026
 */

use App\Security\RateLimiter;

require_once dirname(__DIR__, 2) . '/includes/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response([
        'success' => false,
        'message' => 'Invalid request method.',
    ], 405);
}

$scope = 'demo_request';
$csrf = $_POST['csrf_token'] ?? null;

if (!verify_csrf($scope, is_string($csrf) ? $csrf : null)) {
    json_response([
        'success' => false,
        'message' => 'Security validation failed. Refresh the page and try again.',
    ], 403);
}

$honeypot = trim((string) ($_POST['website'] ?? ''));

if ($honeypot !== '') {
    json_response([
        'success' => true,
        'message' => 'Request received.',
    ]);
}

$config = $GLOBALS['config'];
$rateWindow = (int) $config['security']['rate_limit_window_seconds'];
$rateMax = (int) $config['security']['rate_limit_max_attempts'];

// LFR-CAP-003: the throttle counter lives in shared Redis storage, keyed on
// the HMAC of the client IP. The session-backed counter this replaces could
// be reset by simply dropping the session cookie; a shared counter cannot.
$rateKey = hash_ip(get_client_ip(), (string) $config['security']['ip_hash_secret']);

try {
    $rateLimiter = new RateLimiter(redis_client(), 'demo_request', $rateMax, $rateWindow);
    $withinLimit = $rateLimiter->hit($rateKey);
} catch (Throwable $exception) {
    // Fail closed. If the shared counter is unreachable we must not degrade
    // to unlimited submissions, which is the exact bypass this task removes.
    error_log('Demo request rate limiter unavailable: ' . $exception->getMessage());
    $withinLimit = false;
}

if (!$withinLimit) {
    json_response([
        'success' => false,
        'message' => 'Too many requests. Try again later.',
    ], 429);
}

$name = normalize_input((string) ($_POST['name'] ?? ''), 120);
$email = normalize_input((string) ($_POST['email'] ?? ''), 190);
$company = normalize_input((string) ($_POST['company'] ?? ''), 160);
$roleTitle = normalize_input((string) ($_POST['role_title'] ?? ''), 120);
$phone = normalize_input((string) ($_POST['phone'] ?? ''), 40);
$automationNeed = trim((string) ($_POST['automation_need'] ?? ''));
$automationNeed = mb_substr($automationNeed, 0, 2000);
$preferredContact = normalize_input((string) ($_POST['preferred_contact'] ?? 'email'), 30);

$allowedContactMethods = ['email', 'phone'];

$errors = [];

if ($name === '') {
    $errors['name'] = 'Name is required.';
}

if (!is_valid_email($email)) {
    $errors['email'] = 'A valid email is required.';
}

if ($automationNeed === '') {
    $errors['automation_need'] = 'Workflow details are required.';
}

if (!in_array($preferredContact, $allowedContactMethods, true)) {
    $errors['preferred_contact'] = 'Invalid contact preference.';
}

if ($errors !== []) {
    json_response([
        'success' => false,
        'message' => 'Please correct the highlighted fields.',
        'errors' => $errors,
    ], 422);
}

try {
    $pdo = db();

    $stmt = $pdo->prepare(
        'INSERT INTO demo_requests
            (name, email, company, role_title, phone, automation_need, preferred_contact, ip_hash, user_agent)
         VALUES
            (:name, :email, :company, :role_title, :phone, :automation_need, :preferred_contact, :ip_hash, :user_agent)'
    );

    $stmt->execute([
        ':name' => $name,
        ':email' => $email,
        ':company' => $company !== '' ? $company : null,
        ':role_title' => $roleTitle !== '' ? $roleTitle : null,
        ':phone' => $phone !== '' ? $phone : null,
        ':automation_need' => $automationNeed,
        ':preferred_contact' => $preferredContact,
        ':ip_hash' => hash_ip(get_client_ip(), (string) $config['security']['ip_hash_secret']),
        ':user_agent' => mb_substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255),
    ]);

    json_response([
        'success' => true,
        'message' => 'Request received. Aiwebscapes will review your workflow and follow up.',
    ]);
} catch (Throwable $exception) {
    error_log('Demo request failed: ' . $exception->getMessage());

    json_response([
        'success' => false,
        'message' => 'The request could not be processed right now.',
    ], 500);
}