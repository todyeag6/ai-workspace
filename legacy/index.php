<?php declare(strict_types=1);
/**
 * © AI WebScapes 2026
 */

require_once __DIR__ . '/includes/bootstrap.php';

$appConfig = $GLOBALS['config'] ?? [];

$demoCsrf = csrf_token('demo_request');
$appName = $appConfig['app']['name'] ?? 'Aiwebscapes';
$baseUrl = $appConfig['app']['base_url'] ?? 'https://aiwebscapes.com';
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= e($appName) ?> | AI Automation for Business Workflows</title>
  <meta
    name="description"
    content="Aiwebscapes builds secure AI automation systems for lead follow-up, customer intake, owner notifications, reporting, and operational workflows."
  >
  <meta name="robots" content="index, follow">
  <meta property="og:title" content="Aiwebscapes | AI Automation for Business Workflows">
  <meta property="og:description" content="Secure AI automation systems for practical business workflows.">
  <meta property="og:type" content="website">
  <meta property="og:url" content="<?= e($baseUrl) ?>">
  <meta name="theme-color" content="#111827">
  <link rel="stylesheet" href="assets/css/styles.css">
  <script src="assets/js/main.js" defer></script>
</head>
<body>
  <a class="skip-link" href="#main-content">Skip to main content</a>

  <header class="site-header">
    <nav class="nav" aria-label="Primary navigation">
      <a class="logo" href="/" aria-label="Aiwebscapes home">
        <span class="logo-mark">Ai²</span>
        <span class="logo-text">Aiwebscapes</span>
      </a>

      <button
        class="nav-toggle"
        type="button"
        aria-expanded="false"
        aria-controls="primary-menu"
      >
        <span class="sr-only">Toggle navigation</span>
        <span aria-hidden="true"></span>
        <span aria-hidden="true"></span>
        <span aria-hidden="true"></span>
      </button>

      <div class="nav-menu" id="primary-menu">
        <a href="#solutions">Solutions</a>
        <a href="#demo-system">Demo</a>
        <a href="#security">Security</a>
        <a href="#pricing">Pricing</a>
        <a href="#contact" class="nav-cta">Book a Demo</a>
      </div>
    </nav>
  </header>

  <main id="main-content">
    <section class="hero section">
      <div class="hero-content">
        <p class="eyebrow">B2B AI Automation Systems</p>
        <h1>AI automation systems that follow up, organize leads, and save your business time.</h1>
        <p class="hero-copy">
          Aiwebscapes builds practical AI-powered workflows for lead follow-up,
          customer intake, owner notifications, reporting, and admin visibility.
        </p>

        <div class="hero-actions" aria-label="Primary actions">
          <a class="button button-primary" href="#contact">Request a Live Demo</a>
          <a class="button button-secondary" href="#demo-system">See How It Works</a>
        </div>
      </div>

      <div class="workflow-card" aria-label="Automation workflow preview">
        <div class="workflow-step">
          <span>01</span>
          <strong>Lead Captured</strong>
          <p>Customer submits a secure form.</p>
        </div>
        <div class="workflow-arrow" aria-hidden="true">→</div>
        <div class="workflow-step">
          <span>02</span>
          <strong>AI Summary</strong>
          <p>Important details are organized instantly.</p>
        </div>
        <div class="workflow-arrow" aria-hidden="true">→</div>
        <div class="workflow-step">
          <span>03</span>
          <strong>Follow-Up Sent</strong>
          <p>Customer and owner receive next steps.</p>
        </div>
      </div>
    </section>

    <section class="trust-strip" aria-label="Trust signals">
      <p>Built for secure forms, structured data, human oversight, and practical business workflows.</p>
    </section>

    <section class="section" id="solutions">
      <div class="section-header">
        <p class="eyebrow">Problem vs. Solution</p>
        <h2>Replace scattered manual work with controlled automation.</h2>
      </div>

      <div class="bento-grid">
        <article class="bento-card">
          <h3>Lead Follow-Up</h3>
          <p class="problem">Problem: Leads sit unanswered for hours.</p>
          <p>Solution: Instant AI-assisted follow-up keeps prospects engaged.</p>
        </article>

        <article class="bento-card">
          <h3>Customer Intake</h3>
          <p class="problem">Problem: Intake details get buried in email threads.</p>
          <p>Solution: Every request is stored, summarized, and routed.</p>
        </article>

        <article class="bento-card">
          <h3>Owner Notifications</h3>
          <p class="problem">Problem: Important details are missed.</p>
          <p>Solution: Owners receive clean summaries with clear next steps.</p>
        </article>

        <article class="bento-card">
          <h3>Admin Visibility</h3>
          <p class="problem">Problem: Follow-up status is hard to track.</p>
          <p>Solution: A simple admin view keeps workflow activity organized.</p>
        </article>
      </div>
    </section>

    <section class="section split-section" id="demo-system">
      <div>
        <p class="eyebrow">Featured Demo</p>
        <h2>AI Lead Follow-Up System for Local Businesses</h2>
        <p>
          Start with one working automation instead of a giant platform.
          The demo shows how Aiwebscapes captures a lead, stores it,
          summarizes it, replies to the customer, notifies the owner,
          and keeps follow-up organized.
        </p>
      </div>

      <ul class="feature-list">
        <li>Landing page</li>
        <li>Secure contact form</li>
        <li>Lead storage</li>
        <li>AI-generated lead summary</li>
        <li>Automatic customer reply</li>
        <li>Owner notification</li>
        <li>Follow-up reminder</li>
        <li>Basic admin view</li>
      </ul>
    </section>

    <section class="impact-section" aria-labelledby="impact-title">
      <div class="section-header">
        <p class="eyebrow">Operational Impact</p>
        <h2 id="impact-title">Designed for measurable workflow improvement.</h2>
      </div>

      <div class="impact-grid">
        <article>
          <strong>Instant</strong>
          <span>lead response capability</span>
        </article>
        <article>
          <strong>100%</strong>
          <span>lead capture when forms are completed</span>
        </article>
        <article>
          <strong>Less</strong>
          <span>manual review and repeated admin work</span>
        </article>
      </div>
    </section>

    <section class="section split-section" id="security">
      <div>
        <p class="eyebrow">Security & Control</p>
        <h2>Built with secure web practices from the start.</h2>
        <p>
          Aiwebscapes systems are designed around controlled automation,
          protected forms, server-side validation, and role-based access
          for administrative workflows.
        </p>
      </div>

      <div class="security-card">
        <ul>
          <li>CSRF-protected forms</li>
          <li>Session hardening</li>
          <li>Prepared database statements</li>
          <li>Input validation and output escaping</li>
          <li>Role helper functions</li>
          <li>HTTPS-ready deployment</li>
          <li>Content Security Policy headers</li>
        </ul>
      </div>
    </section>

    <section class="section pricing-section" id="pricing">
      <div class="section-header">
        <p class="eyebrow">Launch Path</p>
        <h2>Start with one sellable automation.</h2>
        <p>
          Aiwebscapes should initially sell focused workflow systems:
          lead follow-up, intake automation, admin routing, and reporting.
        </p>
      </div>

      <div class="pricing-card">
        <h3>Starter Automation Build</h3>
        <p>
          A focused AI workflow demo built around one real business process.
        </p>
        <a class="button button-primary" href="#contact">Discuss This Build</a>
      </div>
    </section>

    <section class="section contact-section" id="contact">
      <div class="section-header">
        <p class="eyebrow">Book a Demo</p>
        <h2>Show us the workflow you want removed from your day.</h2>
        <p>
          Submit the form and Aiwebscapes will review the workflow,
          automation opportunity, and next demo step.
        </p>
      </div>

      <form class="demo-form" id="demo-form" action="/api/demo-request.php" method="post" novalidate>
        <input type="hidden" name="csrf_token" value="<?= e($demoCsrf) ?>">
        <input type="text" name="website" class="honeypot" tabindex="-1" autocomplete="off" aria-hidden="true">

        <div class="form-grid">
          <div class="form-field">
            <label for="name">Name <span aria-hidden="true">*</span></label>
            <input id="name" name="name" type="text" autocomplete="name" required maxlength="120">
          </div>

          <div class="form-field">
            <label for="email">Email <span aria-hidden="true">*</span></label>
            <input id="email" name="email" type="email" autocomplete="email" required maxlength="190">
          </div>

          <div class="form-field">
            <label for="company">Company</label>
            <input id="company" name="company" type="text" autocomplete="organization" maxlength="160">
          </div>

          <div class="form-field">
            <label for="role_title">Role</label>
            <input id="role_title" name="role_title" type="text" autocomplete="organization-title" maxlength="120">
          </div>

          <div class="form-field">
            <label for="phone">Phone</label>
            <input id="phone" name="phone" type="tel" autocomplete="tel" maxlength="40">
          </div>

          <div class="form-field">
            <label for="preferred_contact">Preferred Contact</label>
            <select id="preferred_contact" name="preferred_contact">
              <option value="email">Email</option>
              <option value="phone">Phone</option>
            </select>
          </div>
        </div>

        <div class="form-field">
          <label for="automation_need">What workflow do you want automated? <span aria-hidden="true">*</span></label>
          <textarea id="automation_need" name="automation_need" rows="6" required maxlength="2000"></textarea>
        </div>

        <div class="form-status" id="form-status" role="status" aria-live="polite"></div>

        <button class="button button-primary" type="submit">Request Demo</button>
      </form>
    </section>
  </main>

  <footer class="site-footer">
    <div>
      <a class="logo footer-logo" href="/" aria-label="Aiwebscapes home">
        <span class="logo-mark">Ai²</span>
        <span class="logo-text">Aiwebscapes</span>
      </a>
      <p>Secure AI automation systems for business workflows.</p>
    </div>

    <nav aria-label="Footer navigation">
      <a href="#solutions">Solutions</a>
      <a href="#demo-system">Demo</a>
      <a href="#security">Security</a>
      <a href="#contact">Contact</a>
    </nav>

    <p class="copyright">© AI WebScapes 2026. All rights reserved.</p>
  </footer>
</body>
</html>