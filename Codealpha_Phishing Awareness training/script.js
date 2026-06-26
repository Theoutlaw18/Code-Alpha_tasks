/* ===================================================
   PhishGuard — script.js
   Quiz behavior, page navigation, scroll tracking, and interactive email tips
   CodeAlpha Internship — Task 2
   =================================================== */

// ── QUIZ DATA ──────────────────────────────────────
const QUESTIONS = [
  {
    q: "Which of the following is the most common red flag in a phishing email?",
    options: [
      "The email arrives on a Monday morning",
      "Urgent language demanding immediate action within 24 hours",
      "The email is neatly formatted with a company logo",
      "The email was received from a known sender"
    ],
    answer: 1,
    explanation: "Urgency tactics ('Act NOW', '24 hours', 'Account will be suspended') are the #1 social engineering tool in phishing. Legitimate companies communicate calmly and professionally."
  },
  {
    q: "What does 'spear phishing' mean?",
    options: [
      "Phishing attacks sent via SMS text messages",
      "Mass phishing emails sent to millions of random users",
      "A targeted phishing attack aimed at a specific individual or organization",
      "Phishing via voice calls impersonating banks"
    ],
    answer: 2,
    explanation: "Spear phishing is highly targeted — attackers use personal information (name, employer, colleagues) gathered from social media and data breaches to craft convincing, personalized attacks."
  },
  {
    q: "Which of these URLs is MOST LIKELY a phishing attempt?",
    options: [
      "https://www.paypal.com/login",
      "https://accounts.paypal.com/security",
      "https://paypal-secure-verify.suspicious-login.ru/confirm",
      "https://www.paypal.com/help/contact"
    ],
    answer: 2,
    explanation: "The real domain here is 'suspicious-login.ru' — PayPal is just a subdomain used to deceive. Look at what comes right before the first slash after the protocol. Also note the foreign TLD (.ru) and 'secure-verify' language typical of phishing."
  },
  {
    q: "What should you do FIRST if you receive an email claiming your bank account was compromised?",
    options: [
      "Click the link in the email to immediately secure your account",
      "Reply to the email asking if it is legitimate",
      "Call your bank using the number on your official bank card or website",
      "Forward the email to colleagues to see if they received it too"
    ],
    answer: 2,
    explanation: "Always verify through an independent channel — call your bank using the number printed on your card or found on their official website. Never use contact details provided in the suspicious email itself."
  },
  {
    q: "HTTPS in a website's URL means:",
    options: [
      "The website is completely safe, verified, and legitimate",
      "The connection is encrypted, but it does NOT guarantee the site is legitimate",
      "The website is registered and approved by the government",
      "The website cannot host malware or steal your information"
    ],
    answer: 1,
    explanation: "HTTPS only means your connection to the site is encrypted in transit. Phishing sites very commonly use HTTPS too. Always verify the actual domain name carefully — the padlock icon alone is NOT proof of legitimacy."
  },
  {
    q: "Which social engineering tactic involves creating artificial time pressure?",
    options: [
      "Social proof",
      "Reciprocity",
      "Authority",
      "Urgency"
    ],
    answer: 3,
    explanation: "Urgency is one of the most powerful psychological levers attackers use. When you feel rushed, your brain bypasses critical evaluation. Any message that pressures you to act immediately without thinking should be treated as highly suspicious."
  },
  {
    q: "What is 'vishing'?",
    options: [
      "Phishing conducted via SMS text messages",
      "Phishing conducted via voice or phone calls",
      "Phishing via video conferencing software",
      "Phishing via email with video file attachments"
    ],
    answer: 1,
    explanation: "Vishing = Voice Phishing. Attackers call victims impersonating tech support, IRS agents, bank representatives, or Microsoft employees. The human voice creates a false sense of trust and authenticity."
  },
  {
    q: "An email reads: 'Dear Valued Customer, your account will be suspended in 24 hours unless you verify now.' What red flags are present?",
    options: [
      "The email was sent during business hours",
      "The email has a company logo",
      "Both a generic greeting AND urgency and fear tactics",
      "The email mentions account suspension"
    ],
    answer: 2,
    explanation: "This example contains TWO major red flags: (1) 'Dear Valued Customer' — a generic greeting revealing the sender doesn't know your name (mass phishing), and (2) '24 hours' plus 'unless you verify now' — classic urgency and fear manipulation."
  },
  {
    q: "What is 'smishing'?",
    options: [
      "Phishing disguised as social media notifications",
      "Phishing conducted via SMS text messages",
      "Phishing via voice phone calls",
      "Phishing using physical mail letters"
    ],
    answer: 1,
    explanation: "Smishing = SMS Phishing. Common smishing examples: fake delivery notifications, fake bank OTP alerts, prize win messages, and fraudulent 2FA code requests via text message."
  },
  {
    q: "Which is the BEST overall defense strategy against phishing attacks?",
    options: [
      "Only use email during official working hours",
      "Use the same strong password for all accounts to minimize confusion",
      "Pause before acting, verify through official channels, and enable MFA on all accounts",
      "Never use the internet for any financial transactions"
    ],
    answer: 2,
    explanation: "The three pillars: (1) Think before clicking — pause and question every unexpected message. (2) Verify independently through official channels. (3) Enable MFA so even if credentials are stolen, your accounts remain protected."
  }
];

// ── QUIZ STATE ─────────────────────────────────────
let currentQ = 0;
let userAnswers = new Array(QUESTIONS.length).fill(null);
let answered   = new Array(QUESTIONS.length).fill(false);

// ── QUIZ ───────────────────────────────────────────
function initQuiz() {
  renderQuestion(currentQ);
  updateQuizNav();
}

function renderQuestion(index) {
  const container = document.getElementById('questionContainer');
  if (!container) return;
  const q = QUESTIONS[index];
  const letters = ['A', 'B', 'C', 'D'];

  const optionsHTML = q.options.map((opt, i) => {
    let cls = 'option-btn';
    if (answered[index]) {
      if (i === q.answer)                                cls += ' correct';
      else if (i === userAnswers[index] && i !== q.answer) cls += ' wrong';
    } else if (i === userAnswers[index]) {
      cls += ' selected';
    }
    return `
      <button class="${cls}" onclick="selectAnswer(${i})" ${answered[index] ? 'disabled' : ''}>
        <span class="option-letter">${letters[i]}</span>
        ${opt}
      </button>`;
  }).join('');

  let feedbackHTML = '';
  if (answered[index]) {
    const correct = userAnswers[index] === q.answer;
    if (correct) {
      feedbackHTML = `<div class="answer-feedback feedback-correct">
        ✅ <strong>Correct!</strong> ${q.explanation}</div>`;
    } else {
      feedbackHTML = `<div class="answer-feedback feedback-wrong">
        ❌ <strong>Incorrect.</strong> The correct answer was:
        <span class="correct-ans">${letters[q.answer]}) ${q.options[q.answer]}</span>
        <br><br>${q.explanation}</div>`;
    }
  }

  container.innerHTML = `
    <div class="question-num">QUESTION ${String(index+1).padStart(2,'0')} / ${String(QUESTIONS.length).padStart(2,'0')}</div>
    <div class="question-text">${q.q}</div>
    <div class="options">${optionsHTML}</div>
    ${feedbackHTML}`;

  document.getElementById('qNum').textContent   = index + 1;
  document.getElementById('qTotal').textContent = QUESTIONS.length;

  const pct = (index / QUESTIONS.length) * 100;
  document.getElementById('quizBar').style.width = pct + '%';
}

function selectAnswer(optionIndex) {
  if (answered[currentQ]) return;
  userAnswers[currentQ] = optionIndex;
  answered[currentQ]    = true;
  renderQuestion(currentQ);
  updateQuizNav();
}

function nextQ() {
  if (currentQ < QUESTIONS.length - 1) {
    currentQ++;
    renderQuestion(currentQ);
    updateQuizNav();
    document.getElementById('questionContainer').scrollIntoView({ behavior:'smooth', block:'start' });
  }
}

function prevQ() {
  if (currentQ > 0) {
    currentQ--;
    renderQuestion(currentQ);
    updateQuizNav();
    document.getElementById('questionContainer').scrollIntoView({ behavior:'smooth', block:'start' });
  }
}

function updateQuizNav() {
  const prevBtn   = document.getElementById('qPrev');
  const nextBtn   = document.getElementById('qNext');
  const submitBtn = document.getElementById('qSubmit');
  if (!prevBtn || !nextBtn || !submitBtn) return;

  const isLast     = currentQ === QUESTIONS.length - 1;
  const allAnswered = answered.every(a => a === true);

  prevBtn.style.display   = currentQ === 0 ? 'none' : 'inline-block';
  nextBtn.style.display   = isLast ? 'none' : 'inline-block';
  submitBtn.style.display = (isLast && allAnswered) ? 'inline-block' : 'none';
  nextBtn.disabled        = !answered[currentQ];
}

function submitQuiz() {
  const score = userAnswers.reduce((acc, ans, i) =>
    acc + (ans === QUESTIONS[i].answer ? 1 : 0), 0);
  const total = QUESTIONS.length;
  const pct   = Math.round((score / total) * 100);

  document.getElementById('quizWrap').style.display = 'none';
  const results = document.getElementById('quizResults');
  results.style.display = 'block';

  let icon, band, bandClass, message;
  if (pct === 100) {
    icon = '🏆'; band = 'PERFECT SCORE — SECURITY EXPERT';    bandClass = 'band-excellent';
    message = 'Outstanding! You have mastered phishing awareness. Share this training with your team!';
  } else if (pct >= 80) {
    icon = '🎯'; band = 'EXCELLENT — HIGHLY AWARE';           bandClass = 'band-excellent';
    message = 'Great work! You have a strong understanding of phishing threats. Review the questions you missed to hit 100%.';
  } else if (pct >= 60) {
    icon = '📚'; band = 'GOOD — KEEP LEARNING';               bandClass = 'band-good';
    message = 'Decent foundation! Review the modules on email red flags and social engineering, then retry.';
  } else if (pct >= 40) {
    icon = '⚠️'; band = 'NEEDS IMPROVEMENT';                  bandClass = 'band-average';
    message = 'You are at risk. Please re-read modules 03, 04, and 05 carefully before retrying the quiz.';
  } else {
    icon = '🚨'; band = 'HIGH RISK — RETRAIN REQUIRED';       bandClass = 'band-poor';
    message = 'Your phishing awareness needs significant improvement. Study all modules from the beginning before retrying.';
  }

  document.getElementById('qrIcon').textContent  = icon;
  document.getElementById('qrTitle').textContent = 'Quiz Complete!';

  const scoreEl = document.getElementById('qrScore');
  scoreEl.textContent = `${score}/${total}`;
  scoreEl.style.color = pct >= 80 ? 'var(--accent-green)'
    : pct >= 60 ? 'var(--accent)'
    : pct >= 40 ? 'var(--accent-orange)'
    : 'var(--accent-red)';

  const bandEl = document.getElementById('qrBand');
  bandEl.textContent = band;
  bandEl.className   = `qr-band ${bandClass}`;
  document.getElementById('qrMessage').textContent = message;

  const letters = ['A','B','C','D'];
  document.getElementById('qrBreakdown').innerHTML =
    QUESTIONS.map((q, i) => {
      const ok   = userAnswers[i] === q.answer;
      const short = q.q.length > 65 ? q.q.substring(0, 65) + '…' : q.q;
      return `<div class="qrb-item ${ok ? 'pass' : 'fail'}">
        <span class="qrb-icon">${ok ? '✅' : '❌'}</span>
        <span class="qrb-q">Q${i+1}: ${short}</span>
        <span class="qrb-result">${ok ? 'CORRECT' : 'WRONG'}</span>
      </div>`;
    }).join('');

  results.scrollIntoView({ behavior:'smooth', block:'start' });
}

function retryQuiz() {
  currentQ    = 0;
  userAnswers = new Array(QUESTIONS.length).fill(null);
  answered    = new Array(QUESTIONS.length).fill(false);
  document.getElementById('quizResults').style.display = 'none';
  document.getElementById('quizWrap').style.display    = 'block';
  initQuiz();
  document.getElementById('quizWrap').scrollIntoView({ behavior:'smooth', block:'start' });
}

// ── SIDEBAR ────────────────────────────────────────
const sidebar      = document.getElementById('sidebar');
const menuToggle   = document.getElementById('menuToggle');
const overlay      = document.getElementById('sidebarOverlay');

if (menuToggle) {
  menuToggle.addEventListener('click', () => {
    sidebar.classList.toggle('open');
    menuToggle.classList.toggle('open');
    overlay.classList.toggle('show');
  });
}
if (overlay) {
  overlay.addEventListener('click', () => {
    sidebar.classList.remove('open');
    menuToggle.classList.remove('open');
    overlay.classList.remove('show');
  });
}

document.querySelectorAll('.nav-item').forEach(link => {
  link.addEventListener('click', () => {
    if (window.innerWidth <= 900) {
      sidebar.classList.remove('open');
      menuToggle.classList.remove('open');
      overlay.classList.remove('show');
    }
  });
});

// ── ACTIVE NAV ─────────────────────────────────────
const sections = document.querySelectorAll('section[id]');
const navLinks  = document.querySelectorAll('.nav-item');

function updateActiveNav() {
  let current = '';
  sections.forEach(sec => {
    if (window.scrollY >= sec.offsetTop - 120) current = sec.getAttribute('id');
  });
  navLinks.forEach(link => {
    link.classList.remove('active');
    if (link.getAttribute('href') === `#${current}`) link.classList.add('active');
  });
}

// ── READING PROGRESS ───────────────────────────────
function updateProgress() {
  const total    = document.body.scrollHeight - window.innerHeight;
  const progress = total > 0 ? Math.min(Math.round((window.scrollY / total) * 100), 100) : 0;
  const bar      = document.getElementById('readingBar');
  const pct      = document.getElementById('readingPercent');
  if (bar) bar.style.width = progress + '%';
  if (pct) pct.textContent = progress + '%';
}

// ── SCROLL REVEAL ──────────────────────────────────
// Reveal sections as they come into view while scrolling
function revealVisibleNow() {
  sections.forEach(sec => {
    const rect = sec.getBoundingClientRect();
    // Reveal when the section begins to enter the viewport
    if (rect.top < window.innerHeight + 60) {
      sec.classList.add('visible');
    }
  });
}

function setupScrollReveal() {
  if (!('IntersectionObserver' in window)) {
    // Fallback: reveal everything immediately
    sections.forEach(sec => sec.classList.add('visible'));
    return;
  }

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
      }
    });
  }, { threshold: 0.05, rootMargin: '0px 0px -40px 0px' });

  sections.forEach(sec => observer.observe(sec));
}

// ── INTERACTIVE EMAIL FLAGS ─────────────────────────
function setupEmailFlags() {
  document.querySelectorAll('.flag-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const tipId = btn.getAttribute('data-tip');
      const tip   = document.getElementById(tipId);
      if (!tip) return;
      // Close others
      document.querySelectorAll('.flag-tip.show').forEach(t => {
        if (t !== tip) t.classList.remove('show');
      });
      tip.classList.toggle('show');
    });
  });

  document.addEventListener('click', e => {
    if (!e.target.closest('.flag-btn') && !e.target.closest('.flag-tip')) {
      document.querySelectorAll('.flag-tip.show').forEach(t => t.classList.remove('show'));
    }
  });
}

// ── SMOOTH SCROLL ──────────────────────────────────
function setupSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', e => {
      e.preventDefault();
      const target = document.querySelector(anchor.getAttribute('href'));
      if (target) {
        const top = target.getBoundingClientRect().top + window.scrollY - 24;
        window.scrollTo({ top, behavior: 'smooth' });
      }
    });
  });
}

// ── SCROLL EVENT ───────────────────────────────────
window.addEventListener('scroll', () => {
  updateActiveNav();
  updateProgress();
  revealVisibleNow();
}, { passive: true });

// ── INIT ───────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {

  // Enable CSS scroll animations ONLY after JS is ready
  document.body.classList.add('js-ready');

  // Immediately reveal all sections already on screen (handles #hash navigation too)
  revealVisibleNow();

  // Safety net: reveal everything after 600ms no matter what
  setTimeout(() => {
    sections.forEach(sec => sec.classList.add('visible'));
  }, 600);

  setupScrollReveal();
  setupEmailFlags();
  setupSmoothScroll();
  initQuiz();
  updateActiveNav();
  updateProgress();
});
