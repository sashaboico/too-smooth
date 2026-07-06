// TooSmooth popup — paste a message, hit /analyze, render the explainable verdict card.
const API_URL = "https://too-smooth-production.up.railway.app/analyze";

// Human-readable names for the six interpretable features.
const FEATURE_LABELS = {
  urgency_signal_density: "Urgency",
  personalization_depth_score: "Personalization",
  authority_spoofing_signals: "Authority / Impersonation",
  emotional_pressure_index: "Emotional pressure",
  syntactic_smoothness: "Smoothness (AI tell)",
  manipulation_arc_indicators: "Manipulation arc",
};

// Verdict label -> icon + display text.
const LABEL_INFO = {
  ai_phishing: { icon: "⚠️", text: "AI Phishing Detected" },
  human_phishing: { icon: "⚠️", text: "Phishing Detected" },
  legitimate: { icon: "✓", text: "Looks Legitimate" },
};

const FILL_COLORS = { low: "#34a853", medium: "#fbbc04", high: "#ea4335" };

document.getElementById("ts-analyze").addEventListener("click", analyze);
document.getElementById("ts-input").addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") analyze();
});

async function analyze() {
  const text = document.getElementById("ts-input").value.trim();
  const result = document.getElementById("ts-result");
  result.replaceChildren(); // clear the previous card so results don't stack

  if (!text) {
    renderNote(result, "Paste a message above, then click Analyze.");
    return;
  }

  renderLoading(result);
  try {
    const resp = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (!resp.ok) {
      renderOffline(result, `TooSmooth: Server error (${resp.status}).`);
      return;
    }
    const data = await resp.json();
    result.replaceChildren();
    renderCard(result, data);
  } catch (err) {
    // Network failure = backend not running. Show a quiet card, never a JS error.
    renderOffline(result);
  }
}

function headerColorClass(riskScore) {
  if (riskScore < 30) return "toosmooth-header-green";
  if (riskScore < 70) return "toosmooth-header-yellow";
  return "toosmooth-header-red";
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderNote(container, message) {
  const card = el("div", "toosmooth-card");
  const body = el("div", "toosmooth-note");
  body.textContent = message;
  card.appendChild(body);
  container.appendChild(card);
}

function renderLoading(container) {
  const card = el("div", "toosmooth-card");
  const body = el("div", "toosmooth-note");
  body.textContent = "🔍 TooSmooth analyzing…";
  card.appendChild(body);
  container.appendChild(card);
}

function renderOffline(container, message) {
  container.replaceChildren();
  const card = el("div", "toosmooth-card");
  const body = el("div", "toosmooth-offline");
  body.textContent =
    message ||
    "TooSmooth: Server offline — start the backend to enable analysis.";
  card.appendChild(body);
  container.appendChild(card);
}

function renderCard(container, data) {
  const { label, risk_score, features, top_flags } = data;
  const topFlags = new Set(top_flags || []);
  const info = LABEL_INFO[label] || { icon: "•", text: label };

  const card = el("div", "toosmooth-card");

  // Colored header with verdict + dismiss.
  const header = el("div", `toosmooth-header ${headerColorClass(risk_score)}`);
  const title = el(
    "div",
    "toosmooth-title",
    `${info.icon} ${info.text} — Risk: ${risk_score}/100`
  );
  const dismiss = el("button", "toosmooth-dismiss", "×");
  dismiss.title = "Dismiss";
  dismiss.addEventListener("click", () => card.remove());
  header.appendChild(title);
  header.appendChild(dismiss);
  card.appendChild(header);

  // Body: collapsible feature breakdown (collapsed by default).
  const body = el("div", "toosmooth-body");
  const toggle = el("button", "toosmooth-toggle");
  const arrow = el("span", "toosmooth-arrow", "▸");
  toggle.appendChild(arrow);
  toggle.appendChild(document.createTextNode(" Feature breakdown"));

  const breakdown = el("div", "toosmooth-breakdown");
  breakdown.style.display = "none";

  for (const [key, f] of Object.entries(features)) {
    breakdown.appendChild(buildFeatureRow(key, f, topFlags.has(key)));
  }

  toggle.addEventListener("click", () => {
    const open = breakdown.style.display === "none";
    breakdown.style.display = open ? "block" : "none";
    arrow.textContent = open ? "▾" : "▸";
  });

  body.appendChild(toggle);
  body.appendChild(breakdown);
  card.appendChild(body);
  container.appendChild(card);
}

function buildFeatureRow(key, f, isTopFlag) {
  const row = el("div", "toosmooth-feature" + (isTopFlag ? " toosmooth-top-flag" : ""));

  const head = el("div", "toosmooth-feature-head");
  const name = el("span", "toosmooth-feature-name", FEATURE_LABELS[key] || key);
  head.appendChild(name);
  if (isTopFlag) head.appendChild(el("span", "toosmooth-top-tag", "top signal"));
  head.appendChild(el("span", `toosmooth-badge toosmooth-badge-${f.risk_level}`, f.risk_level));
  row.appendChild(head);

  // Score bar.
  const track = el("div", "toosmooth-score-bar");
  const fill = el("div", "toosmooth-score-bar-fill");
  fill.style.width = Math.round((f.score || 0) * 100) + "%";
  fill.style.background = FILL_COLORS[f.risk_level] || "#ea4335";
  track.appendChild(fill);
  row.appendChild(track);

  row.appendChild(el("div", "toosmooth-reason", f.reason));
  return row;
}
