// PhishGuard — quiz.js
// Uses event delegation so buttons always work after re-renders

const questions = [
  {
    type: "phishing",
    badge: "🎣 Email",
    text: `From: account-security@amaz0n-verify.com\nSubject: ⚠️ URGENT: Your Amazon account has been LIMITED!\n\nDear Customer, your Amazon account has been LIMITED due to suspicious activity. You must VERIFY NOW within 12 hours or your account will be permanently suspended. Click: http://bit.ly/amzn-verifynow`,
    options: [
      "This is a legitimate Amazon email — I should click the link",
      "This is a phishing email — fake domain and urgency tactics",
      "This might be real — Amazon sometimes limits accounts",
      "The link looks short, so it should be safe"
    ],
    correct: 1,
    explanation: "🔍 Red flags: 'amaz0n' (zero instead of 'o'), generic greeting, extreme urgency, bit.ly shortened link hiding the real destination, and threatening language. Amazon would never use a third-party domain."
  },
  {
    type: "legit",
    badge: "✅ Email",
    text: `From: no-reply@github.com\nSubject: [GitHub] Please verify your email address\n\nHey @username,\n\nYou recently changed the email address for your GitHub account. Please verify the new address by clicking below.\n\nVerify email address → (github.com/users/confirm)\n\nIf you didn't make this change, you can ignore this email or contact support.`,
    options: [
      "Phishing — companies never ask you to verify emails",
      "Phishing — 'no-reply' addresses are always fake",
      "Legitimate — official github.com domain, matches action I took, no urgency",
      "Suspicious — I should not click anything"
    ],
    correct: 2,
    explanation: "✅ This is legitimate! Key indicators: official github.com domain, references a specific action you took, no threatening language, transparent link, and a clear way to ignore/report if wrong."
  },
  {
    type: "phishing",
    badge: "💬 SMS",
    text: `SMS from: +1-800-BANK-NOW\n\nALERT: Your Bank of America debit card ending in XXXX has been frozen due to fraud. To unfreeze, text back your 16-digit card number and PIN immediately.`,
    options: [
      "Legitimate — banks send urgent texts about fraud",
      "Phishing — banks NEVER ask for card numbers or PINs via SMS",
      "Real — they only want the last 4 digits",
      "Might be real — I should text back to check"
    ],
    correct: 1,
    explanation: "🔍 Major red flag: No legitimate bank will EVER ask for your full card number or PIN via text, email, or phone. This is a classic smishing (SMS phishing) attack. Call the number on the back of your card directly."
  },
  {
    type: "phishing",
    badge: "🎣 Email",
    text: `From: hr-payroll@your-company-payrol1.com\nSubject: Action Required: Update Your Direct Deposit Information\n\nHi Employee,\n\nDue to a system upgrade, all employees must update their banking information before Friday or your next paycheck will be delayed.\n\nPlease fill out this form: http://company-payroll-update.xyz/form`,
    options: [
      "Legitimate — HR sometimes needs updated banking info",
      "Phishing — misspelled domain and suspicious external link",
      "Real — the deadline proves it's urgent",
      "Safe — it's work-related so I should comply"
    ],
    correct: 1,
    explanation: "🔍 Red flags: domain 'payrol1.com' (number 1, not letter l), external .xyz link, generic 'Hi Employee', artificial deadline. Always verify payroll changes directly with your HR department using contact info from your company directory."
  },
  {
    type: "legit",
    badge: "✅ Email",
    text: `From: security@google.com\nSubject: New sign-in on Windows, Chicago IL\n\nWe noticed a new sign-in to your Google Account on a Windows device.\n\nIf this was you, you don't need to do anything.\n\nIf this wasn't you, visit myaccount.google.com/security (type this in your browser) to secure your account.`,
    options: [
      "Phishing — Google never emails about logins",
      "Phishing — I should click the link to verify",
      "Legitimate — official Google domain, gives info without demanding action, directs you to type the URL",
      "Suspicious — location data means they're tracking me"
    ],
    correct: 2,
    explanation: "✅ Legitimate! Google does send security notifications. This follows good security email practices: it's informational (not demanding), uses official google.com domain, and instructs you to TYPE the URL manually instead of clicking a link."
  },
  {
    type: "phishing",
    badge: "🎣 Email",
    text: `From: noreply@netflix-billing-update.com\nSubject: Your Netflix membership is about to be cancelled\n\nYour Netflix account payment FAILED. Update your billing info NOW to continue your subscription:\n\n>> CLICK HERE TO UPDATE PAYMENT <<\n\nThis link expires in 1 hour!`,
    options: [
      "Real — Netflix does have billing issues sometimes",
      "Phishing — fake domain, extreme urgency, fake expiring link",
      "Might be real — I'll click to check my account",
      "Legitimate — the 1-hour deadline is standard practice"
    ],
    correct: 1,
    explanation: "🔍 Red flags: domain 'netflix-billing-update.com' is not netflix.com, extreme time pressure ('1 hour!'), vague 'CLICK HERE' link (not showing where it goes). Always go directly to netflix.com by typing it — never through email links for billing."
  },
  {
    type: "phishing",
    badge: "🎣 Prize Scam",
    text: `CONGRATULATIONS! You have been selected as this week's WINNER!\n\nYou have won an Apple iPhone 15 Pro ($1,199 value) in our customer appreciation survey. To claim your prize, you only need to pay a small $5.99 shipping and handling fee.\n\nClaim now at: iphone-winner-claim2024.net`,
    options: [
      "Real — companies do hold giveaways",
      "Phishing/Scam — no legitimate prize requires payment to claim",
      "Maybe real — $5.99 is very cheap for a free iPhone",
      "Legitimate — I didn't enter but maybe someone entered for me"
    ],
    correct: 1,
    explanation: "🔍 This is a classic 'advance fee' scam. Legitimate prizes NEVER require you to pay shipping or fees. The small amount is a trick — they either steal your card details or keep charging you. The sketchy domain confirms it's fraudulent."
  },
  {
    type: "legit",
    badge: "✅ Email",
    text: `From: receipts@stripe.com\nSubject: Your receipt from Acme Software — $29.00\n\nYou paid Acme Software $29.00 on Feb 25, 2026.\n\nInvoice #: INV-2026-0847\nPlan: Monthly Pro Subscription\n\nView your receipt: dashboard.stripe.com/receipts/...\n\nIf you have questions about this charge, contact Acme Software directly.`,
    options: [
      "Phishing — I don't remember signing up for anything",
      "Phishing — payment emails are always suspicious",
      "Legitimate — official stripe.com domain, specific invoice number, professional tone",
      "Suspicious — I should dispute this charge"
    ],
    correct: 2,
    explanation: "✅ Legitimate Stripe receipt. Key signs: official stripe.com domain, specific details (invoice number, exact amount, date), professional neutral tone, and directs you to the actual vendor for questions. If you genuinely didn't sign up, visit stripe.com directly to investigate."
  }
];

let current = 0;
let score = 0;
let answers = [];
let answered = false;

function updateProgress() {
  document.getElementById('progressFill').style.width = `${(current / questions.length) * 100}%`;
  document.getElementById('progressText').textContent = `Question ${current + 1} of ${questions.length}`;
  document.getElementById('scoreDisplay').textContent = score;
  document.getElementById('totalDisplay').textContent = questions.length;
}

function renderQuestion() {
  answered = false;
  const q = questions[current];
  updateProgress();

  const badge = document.getElementById('questionBadge');
  badge.textContent = q.badge;
  badge.className = `question-badge ${q.type === 'phishing' ? 'badge-phishing' : 'badge-legit'}`;

  document.getElementById('questionText').textContent = q.text;

  const container = document.getElementById('optionsContainer');
  container.innerHTML = q.options
    .map((opt, i) => `<button class="option-btn" data-index="${i}">${opt}</button>`)
    .join('');

  document.getElementById('explanation').classList.add('hidden');
  document.getElementById('nextBtn').classList.add('hidden');
}

// Event delegation — survives innerHTML rewrites
document.getElementById('optionsContainer').addEventListener('click', e => {
  const btn = e.target.closest('.option-btn');
  if (!btn || answered) return;
  answered = true;

  const index = parseInt(btn.dataset.index, 10);
  const q = questions[current];
  const isCorrect = index === q.correct;

  document.querySelectorAll('.option-btn').forEach(b => {
    b.disabled = true;
    if (parseInt(b.dataset.index, 10) === q.correct) b.classList.add('correct');
  });
  if (!isCorrect) btn.classList.add('wrong');

  if (isCorrect) score++;
  answers.push({ correct: isCorrect });

  const expl = document.getElementById('explanation');
  expl.textContent = q.explanation;
  expl.classList.remove('hidden');

  const nextBtn = document.getElementById('nextBtn');
  nextBtn.textContent = current < questions.length - 1 ? 'Next Question →' : 'See Results →';
  nextBtn.classList.remove('hidden');

  document.getElementById('scoreDisplay').textContent = score;
});

document.getElementById('nextBtn').addEventListener('click', () => {
  current++;
  if (current >= questions.length) {
    showResults();
  } else {
    renderQuestion();
  }
});

function showResults() {
  document.getElementById('questionCard').classList.add('hidden');
  document.getElementById('resultsScreen').classList.remove('hidden');

  document.getElementById('progressFill').style.width = '100%';
  document.getElementById('progressText').textContent = 'Quiz Complete!';

  const pct = Math.round((score / questions.length) * 100);
  let icon, title, desc;

  if (pct >= 88) {
    icon = '🏆'; title = 'Phishing Expert!';
    desc = 'Outstanding! You have excellent phishing detection skills. Keep spreading awareness!';
  } else if (pct >= 62) {
    icon = '🛡️'; title = 'Security Aware!';
    desc = 'Good job! You catch most phishing attempts. Review the questions you missed to sharpen your skills.';
  } else {
    icon = '📚'; title = 'Keep Learning!';
    desc = 'Phishing can be very convincing. Head to our Learn page to study up and try again!';
  }

  document.getElementById('resultIcon').textContent = icon;
  document.getElementById('resultTitle').textContent = title;
  document.getElementById('resultDesc').textContent = desc;
  document.getElementById('finalScore').textContent = `${score} / ${questions.length}`;

  document.getElementById('resultBreakdown').innerHTML = answers.map((a, i) =>
    `<div style="display:flex;gap:0.5rem;align-items:center;margin-bottom:0.4rem;font-size:0.85rem">
      <span>${a.correct ? '✅' : '❌'}</span>
      <span style="color:var(--text-dim)">Q${i + 1}: ${a.correct ? 'Correct' : 'Incorrect'}</span>
    </div>`
  ).join('');
}

window.resetQuiz = function () {
  current = 0; score = 0; answers = []; answered = false;
  document.getElementById('resultsScreen').classList.add('hidden');
  document.getElementById('questionCard').classList.remove('hidden');
  renderQuestion();
};

renderQuestion();