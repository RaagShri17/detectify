/* ==========================================================================
   PhishGuard — main.js
   Three detectors:
     1. Message / Email Body Analyzer  → POST /analyze      (Flask)
     2. Website URL Scanner            → POST /analyze-url  (Flask)
     3. Email Address Analyzer         → Pure JS, no server needed
   ==========================================================================*/

/* --------------------------------------------------------------------------
   SAMPLE DATA
   --------------------------------------------------------------------------*/
const PHISHING_MSG = `Dear Valued Customer,

URGENT: Your account has been SUSPENDED due to unusual activity!!!

We have detected unauthorized login attempts on your PayPal account. You MUST verify your information IMMEDIATELY or your account will be permanently deleted within 24 HOURS!

Click here to verify: http://192.168.1.1/paypal-secure-login/verify.php

Please provide your:
- Full name and date of birth
- Credit card number and CVV
- Social Security Number
- Password and security questions

This is URGENT and requires IMMEDIATE action! Failure to comply will result in account termination!!!

Regards,
PayPal Security Team`;

const LEGIT_MSG = `Hi Sarah,

Your Amazon order #112-8473920-1234567 has shipped!

Your package containing "Wireless Headphones" is on its way and estimated to arrive by Wednesday, February 26.

Track your package: amazon.com/orders (please type this in your browser, don't click links in emails)

If you didn't place this order, please visit amazon.com/help or call 1-888-280-4331.

Thank you for shopping with Amazon.

Best,
The Amazon Team`;

/* --------------------------------------------------------------------------
   SHARED UTILITY — render any result panel
   --------------------------------------------------------------------------*/
function renderPanel(ids, labelMap, data) {
  // Show panel
  var panel = document.getElementById(ids.panel);
  panel.classList.remove('hidden');

  // Verdict badge
  var badge = document.getElementById(ids.badge);
  if (data.is_phishing) {
    badge.textContent = '🎣 ' + data.verdict;
    badge.className = 'verdict-badge verdict-phishing';
  } else {
    badge.textContent = '✅ ' + data.verdict;
    badge.className = 'verdict-badge verdict-legit';
  }

  // Probability bar
  var prob = data.phishing_probability;
  var bar  = document.getElementById(ids.bar);
  var val  = document.getElementById(ids.val);
  bar.style.width = '0%';
  bar.className = 'prob-bar ' + (prob >= 40 ? 'danger' : 'safe');
  setTimeout(function() { bar.style.width = prob + '%'; }, 80);
  val.textContent = prob + '% phishing probability  •  Confidence: ' + data.confidence;

  // Red flags
  var flagsList = document.getElementById(ids.flags);
  if (data.red_flags.length > 0) {
    flagsList.innerHTML = data.red_flags.map(function(f) {
      return '<li>' + f + '</li>';
    }).join('');
  } else {
    flagsList.innerHTML = '<li style="color:var(--text-dim)">No red flags detected</li>';
  }

  // Safe signs
  var safeList = document.getElementById(ids.safe);
  if (data.safe_signs.length > 0) {
    safeList.innerHTML = data.safe_signs.map(function(s) {
      return '<li>' + s + '</li>';
    }).join('');
  } else {
    safeList.innerHTML = '<li style="color:var(--text-dim)">No safe indicators found</li>';
  }

  // Feature grid
  var grid = document.getElementById(ids.grid);
  var html = '';
  var features = data.features;
  for (var key in features) {
    if (features.hasOwnProperty(key)) {
      var label = labelMap[key] || key.replace(/_/g, ' ');
      html += '<div class="feature-item">'
            +   '<span class="feature-name">' + label + '</span>'
            +   '<span class="feature-val">'  + features[key] + '</span>'
            + '</div>';
    }
  }
  grid.innerHTML = html;

  // Scroll into view
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/* --------------------------------------------------------------------------
   DETECTOR 1 — Message / Email Body Analyzer
   --------------------------------------------------------------------------*/
var msgTextarea = document.getElementById('messageInput');

if (msgTextarea) {

  // Word counter
  msgTextarea.addEventListener('input', function() {
    var words = msgTextarea.value.trim().split(/\s+/).filter(function(w) { return w.length > 0; });
    document.getElementById('wordCount').textContent = words.length + ' word' + (words.length !== 1 ? 's' : '');
  });

  // Clear
  document.getElementById('clearBtn').addEventListener('click', function() {
    msgTextarea.value = '';
    document.getElementById('wordCount').textContent = '0 words';
    document.getElementById('resultPanel').classList.add('hidden');
  });

  // Sample buttons
  var sampleBtns = document.querySelectorAll('.sample-btn');
  sampleBtns.forEach(function(btn) {
    btn.addEventListener('click', function() {
      msgTextarea.value = (btn.getAttribute('data-type') === 'phishing') ? PHISHING_MSG : LEGIT_MSG;
      msgTextarea.dispatchEvent(new Event('input'));
      document.getElementById('resultPanel').classList.add('hidden');
    });
  });

  // Analyze button
  document.getElementById('analyzeBtn').addEventListener('click', function() {
    var text = msgTextarea.value.trim();
    if (!text) {
      msgTextarea.style.borderColor = 'var(--danger)';
      setTimeout(function() { msgTextarea.style.borderColor = ''; }, 1200);
      msgTextarea.focus();
      return;
    }

    var btn     = document.getElementById('analyzeBtn');
    var btnText = btn.querySelector('.btn-text');
    var btnLoad = btn.querySelector('.btn-loading');
    btn.disabled = true;
    btnText.classList.add('hidden');
    btnLoad.classList.remove('hidden');

    fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: text })
    })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      renderPanel(
        { panel: 'resultPanel', badge: 'verdictBadge', bar: 'probBar',
          val: 'probValue', flags: 'redFlagsList', safe: 'safeSignsList', grid: 'featuresGrid' },
        { urgency_count: 'Urgency Words', suspicious_url_count: 'Suspicious URLs',
          sensitive_count: 'Sensitive Requests', exclamation_count: 'Exclamations',
          caps_ratio: 'Caps Ratio', domain_mismatch: 'Domain Mismatch',
          word_count: 'Word Count', url_count: 'URLs Found',
          entropy: 'Text Entropy', long_sentences: 'Long Sentences' },
        data
      );
    })
    .catch(function() {
      alert('Analysis failed. Make sure Flask is running on localhost:5000.');
    })
    .finally(function() {
      btn.disabled = false;
      btnText.classList.remove('hidden');
      btnLoad.classList.add('hidden');
    });
  });
}

/* --------------------------------------------------------------------------
   DETECTOR 2 — Website URL Scanner
   --------------------------------------------------------------------------*/
var urlInput = document.getElementById('urlInput');

if (urlInput) {

  // Clear
  document.getElementById('clearUrlBtn').addEventListener('click', function() {
    urlInput.value = '';
    document.getElementById('urlResultPanel').classList.add('hidden');
    urlInput.focus();
  });

  // Sample buttons
  document.querySelectorAll('.url-sample-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      urlInput.value = btn.getAttribute('data-url');
      document.getElementById('urlResultPanel').classList.add('hidden');
    });
  });

  // Enter key
  urlInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') document.getElementById('analyzeUrlBtn').click();
  });

  // Scan button
  document.getElementById('analyzeUrlBtn').addEventListener('click', function() {
    var url = urlInput.value.trim();
    if (!url) {
      urlInput.style.borderColor = 'var(--danger)';
      setTimeout(function() { urlInput.style.borderColor = ''; }, 1200);
      urlInput.focus();
      return;
    }

    var btn     = document.getElementById('analyzeUrlBtn');
    var btnText = btn.querySelector('.url-btn-text');
    var btnLoad = btn.querySelector('.url-btn-loading');
    btn.disabled = true;
    btnText.classList.add('hidden');
    btnLoad.classList.remove('hidden');

    fetch('/analyze-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      renderPanel(
        { panel: 'urlResultPanel', badge: 'urlVerdictBadge', bar: 'urlProbBar',
          val: 'urlProbValue', flags: 'urlRedFlagsList', safe: 'urlSafeSignsList', grid: 'urlFeaturesGrid' },
        { uses_https: 'HTTPS', is_ip_address: 'IP as Host', url_length: 'URL Length',
          subdomain_count: 'Subdomains', hyphen_count: 'Hyphens',
          suspicious_tld: 'Suspicious TLD', brand_in_domain: 'Brand Spoofing',
          at_symbol: '@ Symbol', double_slash_path: 'Double Slash',
          digit_in_domain: 'Digits in Domain', query_param_count: 'Query Params',
          query_length: 'Query Length', is_legit_domain: 'Known Safe Domain',
          path_depth: 'Path Depth' },
        data
      );
    })
    .catch(function() {
      alert('URL scan failed. Make sure Flask is running on localhost:5000.');
    })
    .finally(function() {
      btn.disabled = false;
      btnText.classList.remove('hidden');
      btnLoad.classList.add('hidden');
    });
  });
}

/* --------------------------------------------------------------------------
   DETECTOR 3 — Email Address Analyzer (pure client-side, no server needed)
   --------------------------------------------------------------------------*/
var emailInput = document.getElementById('emailInput');

if (emailInput) {

  /* Known safe domains */
  var LEGIT_DOMAINS = [
    'gmail.com','yahoo.com','outlook.com','hotmail.com','icloud.com',
    'protonmail.com','microsoft.com','apple.com','amazon.com','paypal.com',
    'google.com','facebook.com','twitter.com','linkedin.com','github.com',
    'netflix.com','spotify.com','adobe.com','dropbox.com','stripe.com',
    'salesforce.com','zoho.com','fastmail.com','cloudflare.com'
  ];

  /* High-risk TLDs */
  var RISKY_TLDS = [
    'xyz','tk','ml','ga','cf','gq','top','click','link','work',
    'win','download','loan','review','party','racing','date',
    'faith','bid','trade','accountant','support'
  ];

  /* Brands commonly spoofed */
  var BRANDS = [
    'paypal','amazon','apple','google','microsoft','netflix','facebook',
    'instagram','twitter','linkedin','ebay','bankofamerica','chase',
    'wellsfargo','citibank','hsbc','support','security','helpdesk',
    'noreply','alert','update','service','account','verify','confirm',
    'billing','admin'
  ];

  /* Disposable domains */
  var DISPOSABLE = [
    'mailinator.com','guerrillamail.com','10minutemail.com',
    'tempmail.com','throwam.com','yopmail.com','trashmail.com',
    'sharklasers.com','dispostable.com','maildrop.cc'
  ];

  function analyzeEmailAddress(email) {
    email = email.trim().toLowerCase();
    var atIdx  = email.lastIndexOf('@');
    var valid  = (atIdx > 0 && atIdx < email.length - 1);
    var local  = valid ? email.slice(0, atIdx) : email;
    var domain = valid ? email.slice(atIdx + 1) : '';
    var parts  = domain.split('.');
    var tld    = parts[parts.length - 1] || '';
    var fullSD = parts.length >= 2 ? parts.slice(-2).join('.') : domain;

    // Count features
    var hasAt         = valid ? 1 : 0;
    var multiAt       = (email.split('@').length - 1) > 1 ? 1 : 0;
    var hasSpaces     = /\s/.test(email) ? 1 : 0;
    var domainLen     = domain.length;
    var localLen      = local.length;
    var hyphens       = (domain.match(/-/g) || []).length;
    var digits        = (domain.match(/\d/g) || []).length;
    var subdomains    = Math.max(0, parts.length - 2);
    var riskyTld      = RISKY_TLDS.indexOf(tld) >= 0 ? 1 : 0;
    var isLegit       = LEGIT_DOMAINS.indexOf(fullSD) >= 0 ? 1 : 0;
    var isDisposable  = DISPOSABLE.indexOf(fullSD) >= 0 ? 1 : 0;
    var isLongDomain  = domainLen > 30 ? 1 : 0;
    var numericLocal  = /^\d+$/.test(local) ? 1 : 0;

    // Brand spoofing: brand keyword in domain but not the real domain
    var brandSpoof = 0;
    for (var i = 0; i < BRANDS.length; i++) {
      if (domain.indexOf(BRANDS[i]) >= 0 && LEGIT_DOMAINS.indexOf(fullSD) < 0) {
        brandSpoof++;
        break;
      }
    }

    // Lookalike: digits replacing letters (paypa1, amaz0n, g00gle)
    var lookalike = 0;
    var normalized = domain.replace(/0/g,'o').replace(/1/g,'l').replace(/3/g,'e').replace(/4/g,'a').replace(/5/g,'s');
    if (normalized !== domain) {
      for (var j = 0; j < BRANDS.length; j++) {
        if (normalized.indexOf(BRANDS[j]) >= 0 && LEGIT_DOMAINS.indexOf(fullSD) < 0) {
          lookalike = 1;
          break;
        }
      }
    }

    var features = {
      has_at_sign:       hasAt,
      multiple_at_signs: multiAt,
      has_spaces:        hasSpaces,
      domain_length:     domainLen,
      local_length:      localLen,
      hyphen_count:      hyphens,
      digit_count:       digits,
      subdomain_count:   subdomains,
      risky_tld:         riskyTld,
      is_legit_domain:   isLegit,
      disposable_domain: isDisposable,
      brand_spoof:       brandSpoof,
      lookalike_chars:   lookalike,
      is_long_domain:    isLongDomain,
      numeric_local:     numericLocal
    };

    // Weighted score
    var score = 0;
    score += brandSpoof    * 28;
    score += lookalike     * 32;
    score += isDisposable  * 35;
    score += riskyTld      * 22;
    score += multiAt       * 40;
    score += hasSpaces     * 40;
    score += hyphens       * 5;
    score += digits        * 3;
    score += subdomains    * 8;
    score += isLongDomain  * 12;
    score += numericLocal  * 10;
    if (!hasAt)   score += 30;
    if (isLegit)  score  = Math.max(0, score - 45);
    score = Math.min(100, score);

    // Build flags
    var redFlags  = [];
    var safeSigns = [];

    if (!hasAt)
      redFlags.push('🔴 Invalid format — missing @ symbol');
    if (multiAt)
      redFlags.push('🔴 Multiple @ symbols — malformed / attack address');
    if (hasSpaces)
      redFlags.push('🔴 Spaces detected — invalid email address');
    if (isDisposable)
      redFlags.push('🔴 Disposable / throwaway email service detected');
    if (lookalike)
      redFlags.push('🔴 Lookalike characters detected (e.g. amaz0n, paypa1)');
    if (brandSpoof)
      redFlags.push('🔴 Brand name in domain but NOT the official domain');
    if (riskyTld)
      redFlags.push('🔴 High-risk TLD (.' + tld + ') — commonly abused in phishing');
    if (subdomains > 1)
      redFlags.push('🔴 Deep subdomain nesting (' + subdomains + ' levels) — spoofing tactic');
    if (hyphens > 2)
      redFlags.push('🔴 Excessive hyphens (' + hyphens + ') — obfuscation tactic');
    if (isLongDomain)
      redFlags.push('🔴 Very long domain (' + domainLen + ' chars) to obscure real identity');
    if (numericLocal)
      redFlags.push('🔴 All-numeric local part — typical of auto-generated phishing addresses');

    if (isLegit)
      safeSigns.push('✅ Matches a known legitimate email domain');
    if (hasAt && !multiAt)
      safeSigns.push('✅ Properly formatted email structure');
    if (!riskyTld && hasAt)
      safeSigns.push('✅ Standard, reputable top-level domain');
    if (!brandSpoof)
      safeSigns.push('✅ No brand name spoofing detected');
    if (!lookalike)
      safeSigns.push('✅ No lookalike character substitutions');
    if (hyphens <= 1)
      safeSigns.push('✅ Clean domain with minimal hyphens');
    if (!isDisposable)
      safeSigns.push('✅ Not a known disposable email service');
    if (subdomains <= 1)
      safeSigns.push('✅ Simple, flat domain structure');

    return {
      is_phishing:          score >= 40,
      phishing_probability: score,
      verdict:              score >= 40 ? 'PHISHING' : 'LEGITIMATE',
      confidence:           Math.abs(score - 50) > 25 ? 'High' : 'Medium',
      red_flags:            redFlags,
      safe_signs:           safeSigns,
      features:             features
    };
  }

  // Clear
  document.getElementById('clearEmailBtn').addEventListener('click', function() {
    emailInput.value = '';
    document.getElementById('emailResultPanel').classList.add('hidden');
    emailInput.focus();
  });

  // Sample buttons
  document.querySelectorAll('.email-sample-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      emailInput.value = btn.getAttribute('data-email');
      document.getElementById('emailResultPanel').classList.add('hidden');
    });
  });

  // Enter key
  emailInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') document.getElementById('analyzeEmailBtn').click();
  });

  // Analyze button
  document.getElementById('analyzeEmailBtn').addEventListener('click', function() {
    var email = emailInput.value.trim();
    if (!email) {
      emailInput.style.borderColor = 'var(--danger)';
      setTimeout(function() { emailInput.style.borderColor = ''; }, 1200);
      emailInput.focus();
      return;
    }

    var btn     = document.getElementById('analyzeEmailBtn');
    var btnText = btn.querySelector('.email-btn-text');
    var btnLoad = btn.querySelector('.email-btn-loading');
    btn.disabled = true;
    btnText.classList.add('hidden');
    btnLoad.classList.remove('hidden');

    // Small delay for UX realism
    setTimeout(function() {
      var data = analyzeEmailAddress(email);
      renderPanel(
        { panel: 'emailResultPanel', badge: 'emailVerdictBadge', bar: 'emailProbBar',
          val: 'emailProbValue', flags: 'emailRedFlagsList', safe: 'emailSafeSignsList',
          grid: 'emailFeaturesGrid' },
        { has_at_sign: 'Has @ Sign', multiple_at_signs: 'Multiple @',
          has_spaces: 'Has Spaces', domain_length: 'Domain Length',
          local_length: 'Local Part Length', hyphen_count: 'Hyphens',
          digit_count: 'Digits in Domain', subdomain_count: 'Subdomains',
          risky_tld: 'Risky TLD', is_legit_domain: 'Known Safe Domain',
          disposable_domain: 'Disposable', brand_spoof: 'Brand Spoofing',
          lookalike_chars: 'Lookalike Chars', is_long_domain: 'Long Domain',
          numeric_local: 'Numeric Local Part' },
        data
      );
      btn.disabled = false;
      btnText.classList.remove('hidden');
      btnLoad.classList.add('hidden');
    }, 400);
  });
}