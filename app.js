import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { SUPABASE_PUBLISHABLE_KEY, SUPABASE_URL } from "./supabase-config.js";

const STORAGE_KEY = "bayanlink-service-requests-v1";
const LEGACY_ACCOUNTS_STORAGE_KEY = "bayanlink-accounts-v1";
const LEGACY_PASSWORD_ITERATIONS = 210000;
const EMAIL_COOLDOWN_STORAGE_KEY = "bayanlink-email-cooldown-v1";
const EMAIL_SEND_COOLDOWN_MS = 60 * 1000;
const EMAIL_RATE_LIMIT_COOLDOWN_MS = 60 * 60 * 1000;
const protectedPages = new Set(["overview", "submit", "track", "queue", "reports"]);

const categories = [
  "Documents",
  "Complaints",
  "Infrastructure",
  "Health & Sanitation",
  "Peace & Order",
  "Other",
];
const statuses = ["New", "In review", "In progress", "Resolved"];

const sampleRequests = [
  {
    id: "BL-2026-041",
    name: "Maria Santos",
    address: "Purok 2, Riverside",
    contact: "",
    description: "A large tree branch has fallen across the sidewalk after last night's rain.",
    category: "Infrastructure",
    urgent: true,
    status: "New",
    assigned: "Unassigned",
    createdAt: daysAgo(0, 4),
  },
  {
    id: "BL-2026-040",
    name: "Jose Reyes",
    address: "Purok 1, Centro",
    contact: "",
    description: "Requesting a barangay clearance for a new job application.",
    category: "Documents",
    urgent: false,
    status: "In review",
    assigned: "Staff member",
    createdAt: daysAgo(1, 2),
  },
  {
    id: "BL-2026-039",
    name: "Ana Cruz",
    address: "Purok 4, Hillside",
    contact: "",
    description: "There is a water leak from the pipe near the community court.",
    category: "Infrastructure",
    urgent: false,
    status: "In progress",
    assigned: "Staff member",
    createdAt: daysAgo(2, 5),
  },
  {
    id: "BL-2026-038",
    name: "Ramon Garcia",
    address: "Purok 3, Riverside",
    contact: "",
    description: "The garbage collection on our street was missed this week.",
    category: "Health & Sanitation",
    urgent: false,
    status: "New",
    assigned: "Unassigned",
    createdAt: daysAgo(2, 1),
  },
  {
    id: "BL-2026-037",
    name: "Liza Mendoza",
    address: "Purok 5, Centro",
    contact: "",
    description: "Request for a copy of my certificate of residency.",
    category: "Documents",
    urgent: false,
    status: "Resolved",
    assigned: "Staff member",
    createdAt: daysAgo(4, 3),
  },
  {
    id: "BL-2026-036",
    name: "Pedro Dela Rosa",
    address: "Purok 2, Riverside",
    contact: "",
    description: "Loud noise from a nearby gathering late last night.",
    category: "Peace & Order",
    urgent: false,
    status: "New",
    assigned: "Unassigned",
    createdAt: daysAgo(0, 12),
  },
  {
    id: "BL-2026-035",
    name: "Nina Flores",
    address: "Purok 1, Centro",
    contact: "",
    description: "I would like to report a concern about a neighborhood dispute.",
    category: "Complaints",
    urgent: false,
    status: "In review",
    assigned: "Staff member",
    createdAt: daysAgo(3, 2),
  },
];

let requests = loadRequests();
let currentPage = "landing";
let trackingCode = "";
let accountMode = "create";
let accountSubmitting = false;
let pendingRequestPage = "";
let pendingConfirmationEmail = "";
let accountEmail = "";
let passwordRecovery = false;
let currentAccount = null;
let accountNotice = "";
let supabase = null;
let supabaseConfigurationError = "";
let chatSubmitting = false;

function getEmailCooldownUntil() {
  try {
    const until = Number(localStorage.getItem(EMAIL_COOLDOWN_STORAGE_KEY));
    return Number.isFinite(until) && until > Date.now() ? until : 0;
  } catch (error) {
    console.error("Could not read the email cooldown:", error);
    return 0;
  }
}

function setEmailCooldown(duration) {
  const until = Date.now() + duration;
  try {
    localStorage.setItem(EMAIL_COOLDOWN_STORAGE_KEY, String(until));
  } catch (error) {
    console.error("Could not save the email cooldown:", error);
  }
  return until;
}

function emailRateLimitMessage() {
  const remaining = Math.max(0, getEmailCooldownUntil() - Date.now());
  if (remaining <= EMAIL_SEND_COOLDOWN_MS + 5000) {
    return "Please wait about a minute before requesting another email.";
  }
  const minutes = Math.ceil(remaining / 60000);
  return `Supabase has temporarily limited email delivery for this project. Wait about ${minutes} minutes before trying again. The built-in email provider allows only 2 emails per hour; repeated requests won’t send the email sooner.`;
}

function isEmailRateLimitError(error) {
  const message = String(error?.message || "").toLowerCase();
  return error?.code === "over_email_send_rate_limit" ||
    error?.status === 429 || error?.statusCode === 429 ||
    (message.includes("email") && (message.includes("rate") || message.includes("too many")));
}

function canSendAuthEmail() {
  return getEmailCooldownUntil() <= Date.now();
}

function hasSupabaseConfiguration() {
  return /^https:\/\/[a-z0-9-]+\.supabase\.co\/?$/i.test(SUPABASE_URL) &&
    SUPABASE_PUBLISHABLE_KEY.length > 20 &&
    !SUPABASE_PUBLISHABLE_KEY.includes("YOUR_");
}

function accountFromUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    email: user.email || "",
    name: user.user_metadata?.full_name || user.email || "Resident",
  };
}

async function verifyLegacyPassword(password, salt, expectedHash) {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Secure password verification is unavailable. Use localhost or HTTPS.");
  }
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: Uint8Array.from(atob(salt), (character) => character.charCodeAt(0)),
    iterations: LEGACY_PASSWORD_ITERATIONS,
    hash: "SHA-256",
  }, key, 256);
  const actualHash = Array.from(new Uint8Array(bits), (byte) => byte.toString(16).padStart(2, "0")).join("");
  if (actualHash.length !== expectedHash.length) return false;
  let difference = 0;
  for (let index = 0; index < actualHash.length; index += 1) {
    difference |= actualHash.charCodeAt(index) ^ expectedHash.charCodeAt(index);
  }
  return difference === 0;
}

function findLegacyAccount(email) {
  try {
    const saved = localStorage.getItem(LEGACY_ACCOUNTS_STORAGE_KEY);
    if (saved === null) return null;
    const parsed = JSON.parse(saved);
    if (!Array.isArray(parsed)) throw new Error("Saved legacy account data is not a list.");
    return parsed.find((account) =>
      account && typeof account.email === "string" &&
      account.email.toLowerCase() === email &&
      typeof account.name === "string" &&
      typeof account.salt === "string" &&
      typeof account.passwordHash === "string") || null;
  } catch (error) {
    console.error("Could not read a legacy browser account:", error);
    return null;
  }
}

function initializeSupabase() {
  if (!hasSupabaseConfiguration()) {
    supabaseConfigurationError = "Add your Supabase project URL and publishable key to supabase-config.js to enable shared account registration and login.";
    render();
    return;
  }

  try {
    supabase = createClient(SUPABASE_URL.replace(/\/+$/, ""), SUPABASE_PUBLISHABLE_KEY, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: true,
      },
    });
  } catch (error) {
    console.error("Could not initialize Supabase:", error);
    supabaseConfigurationError = "Supabase configuration could not be loaded. Check the project URL and publishable key in supabase-config.js.";
    render();
    return;
  }
  supabase.auth.onAuthStateChange((event, session) => {
    currentAccount = accountFromUser(session?.user);
    if (event === "PASSWORD_RECOVERY") {
      passwordRecovery = true;
      accountMode = "update-password";
      currentPage = "account";
      render();
      return;
    }
    handleAuthSession();
  });
  supabase.auth.getSession().then(({ data, error }) => {
    if (error) throw error;
    currentAccount = accountFromUser(data.session?.user);
    handleAuthSession();
  }).catch((error) => {
    console.error("Could not restore the Supabase session:", error);
    showToast("Could not check your sign-in session. Please refresh and try again.", true);
  });
}

function daysAgo(days, hours = 0) {
  return new Date(Date.now() - (days * 24 + hours) * 60 * 60 * 1000).toISOString();
}

function loadRequests() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === null) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(sampleRequests));
      return [...sampleRequests];
    }
    const parsed = JSON.parse(saved);
    if (!Array.isArray(parsed)) throw new Error("Saved request data is not a list.");
    return parsed.filter(isValidRequest);
  } catch (error) {
    console.error("Could not load saved requests:", error);
    return [...sampleRequests];
  }
}

function handleAuthSession() {
  if (currentAccount && pendingRequestPage) {
    continueAfterLogin();
    return;
  }
  if (!currentAccount && protectedPages.has(currentPage)) {
    pendingRequestPage = "";
    accountMode = "login";
    accountNotice = "Please log in to access the workspace.";
    currentPage = "account";
  }
  render();
}

function isValidRequest(request) {
  return request && typeof request.id === "string" &&
    typeof request.name === "string" &&
    typeof request.description === "string" &&
    categories.includes(request.category) &&
    statuses.includes(request.status);
}

function saveRequests() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(requests));
    return true;
  } catch (error) {
    console.error("Could not save requests:", error);
    showToast("Could not save changes in this browser.", true);
    return false;
  }
}

function escapeHTML(value = "") {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function classifyText(text) {
  const value = text.toLowerCase();
  const rules = [
    {
      category: "Documents",
      words: ["clearance", "certificate", "document", "residency", "indigency", "permit", "copy of", "id "],
    },
    {
      category: "Complaints",
      words: ["complaint", "complain", "dispute", "report a concern", "neighbor", "neighbour"],
    },
    {
      category: "Infrastructure",
      words: ["road", "streetlight", "street light", "pothole", "sidewalk", "pipe", "water leak", "drain", "bridge", "tree", "fallen", "electricity"],
    },
    {
      category: "Health & Sanitation",
      words: ["garbage", "trash", "waste", "sanitation", "sewage", "mosquito", "health", "clean", "pest"],
    },
    {
      category: "Peace & Order",
      words: ["noise", "theft", "suspicious", "threat", "disturbance", "safety", "fight", "violence", "security"],
    },
  ];
  const match = rules.find((rule) => rule.words.some((word) => value.includes(word)));
  const urgentWords = [
    "urgent", "emergency", "immediately", "right now", "fire", "injured",
    "injury", "accident", "danger", "dangerous", "flood", "trapped", "threat",
    "violence", "gas leak",
  ];
  return {
    category: match ? match.category : (text.trim() ? "Other" : "—"),
    urgent: urgentWords.some((word) => value.includes(word)),
  };
}

function formatDate(dateString, options = { month: "short", day: "numeric" }) {
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) return "Date unavailable";
  return new Intl.DateTimeFormat("en-PH", options).format(date);
}

function formatDateTime(dateString) {
  return formatDate(dateString, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

function relativeTime(dateString) {
  const hours = Math.max(0, Math.floor((Date.now() - new Date(dateString).getTime()) / 3600000));
  if (hours < 1) return "Just now";
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function statusClass(status) {
  return ({
    "New": "new",
    "In review": "review",
    "In progress": "progress",
    "Resolved": "resolved",
  })[status] || "new";
}

function statusPill(status) {
  return `<span class="pill pill-status-${statusClass(status)}">${escapeHTML(status)}</span>`;
}

function urgencyPill(urgent) {
  return urgent
    ? '<span class="pill pill-urgent">● Urgent</span>'
    : '<span class="pill pill-normal">Normal</span>';
}

function renderTableRows(list, includeContact = false) {
  if (!list.length) {
    return `<tr><td colspan="${includeContact ? 7 : 6}"><div class="empty-state">No requests found. Try adjusting your filters.</div></td></tr>`;
  }
  return list.map((request) => `
    <tr data-open-request="${escapeHTML(request.id)}" tabindex="0" aria-label="Open request ${escapeHTML(request.id)}">
      <td><strong>${escapeHTML(request.id)}</strong></td>
      <td><span class="request-title">${escapeHTML(request.description)}</span><span class="request-subtitle">${escapeHTML(request.address || "Address not provided")}</span></td>
      <td>${escapeHTML(request.category)}</td>
      ${includeContact ? `<td>${escapeHTML(request.name)}</td>` : ""}
      <td>${urgencyPill(request.urgent)}</td>
      <td>${statusPill(request.status)}</td>
      <td>${escapeHTML(formatDate(request.createdAt))}</td>
    </tr>
  `).join("");
}

function pageHeading(eyebrow, title, description, action = "") {
  return `<div class="page-heading"><div><p class="eyebrow">${eyebrow}</p><h1>${title}</h1><p>${description}</p></div>${action}</div>`;
}

function renderOverview() {
  const openCount = requests.filter((request) => request.status !== "Resolved").length;
  const urgentCount = requests.filter((request) => request.urgent && request.status !== "Resolved").length;
  const newCount = requests.filter((request) => request.status === "New").length;
  const resolvedCount = requests.filter((request) => request.status === "Resolved").length;
  const maxCategory = Math.max(1, ...categories.map((category) => requests.filter((request) => request.category === category).length));
  const categoryBars = categories.map((category) => {
    const count = requests.filter((request) => request.category === category).length;
    return `<div class="chart-row"><span>${category}</span><div class="chart-track"><div class="chart-fill" style="width:${Math.max(count ? 5 : 0, count / maxCategory * 100)}%"></div></div><span class="chart-count">${count}</span></div>`;
  }).join("");
  const priorityItems = requests
    .filter((request) => request.urgent && request.status !== "Resolved")
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
    .slice(0, 4);
  const priorityContent = priorityItems.length
    ? priorityItems.map((request) => `<div class="priority-item" data-open-request="${escapeHTML(request.id)}" tabindex="0"><span class="priority-dot"></span><span class="priority-copy"><strong>${escapeHTML(request.description)}</strong><small>${escapeHTML(request.id)} · ${escapeHTML(request.address || "Address not provided")}</small></span><span class="priority-time">${relativeTime(request.createdAt)}</span></div>`).join("")
    : '<div class="empty-state">No urgent requests need attention right now.</div>';
  const latest = [...requests].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 5);

  return `
    ${pageHeading("COMMUNITY SERVICE DESK", "Good day, Barangay team 👋", "Here’s what’s happening with your community requests today.",
      '<button class="button button-primary" data-page="submit"><span class="button-icon">＋</span> New request</button>')}
    <section class="stats-grid" aria-label="Request summary">
      <article class="stat-card"><div class="stat-top"><span>Total requests</span><span class="stat-icon">▤</span></div><div class="stat-value">${requests.length}</div><div class="stat-foot">All requests received</div></article>
      <article class="stat-card"><div class="stat-top"><span>Open requests</span><span class="stat-icon">◷</span></div><div class="stat-value">${openCount}</div><div class="stat-foot"><span class="good">${newCount} new</span> · awaiting resolution</div></article>
      <article class="stat-card"><div class="stat-top"><span>Urgent attention</span><span class="stat-icon">△</span></div><div class="stat-value">${urgentCount}</div><div class="stat-foot">${urgentCount ? "Needs prompt staff review" : "Nothing flagged right now"}</div></article>
      <article class="stat-card"><div class="stat-top"><span>Resolved</span><span class="stat-icon">✓</span></div><div class="stat-value">${resolvedCount}</div><div class="stat-foot">Requests marked complete</div></article>
    </section>
    <section class="dashboard-grid">
      <article class="panel"><div class="panel-heading"><div><h2>Requests by category</h2><p>Overview of community concerns</p></div><button class="text-link" data-page="reports">View reports →</button></div><div class="category-chart">${categoryBars}</div></article>
      <article class="panel"><div class="panel-heading"><div><h2>Needs attention</h2><p>Requests flagged as urgent</p></div><span class="pill pill-urgent">${urgentCount} urgent</span></div><div class="priority-list">${priorityContent}</div></article>
    </section>
    <section class="panel queue-panel">
      <div class="panel-heading"><div><h2>Recent requests</h2><p>Latest updates from residents</p></div><button class="text-link" data-page="queue">View all requests →</button></div>
      <div class="table-wrap"><table class="request-table"><thead><tr><th>Reference</th><th>Request</th><th>Category</th><th>Priority</th><th>Status</th><th>Received</th></tr></thead><tbody>${renderTableRows(latest)}</tbody></table></div>
    </section>
  `;
}

function renderSubmit() {
  return `
    ${pageHeading("RESIDENT PORTAL", "Submit a service request", "Tell us what you need. Your request will be sent to the barangay service desk.")}
    <div class="form-layout">
      <form class="form-card" id="request-form">
        <h2>Request details</h2>
        <p class="form-intro">Share enough detail so our team can understand and follow up on your concern.</p>
        <div class="form-grid">
          <div class="form-field"><label for="resident-name">Full name</label><input id="resident-name" name="name" autocomplete="name" maxlength="100" required placeholder="e.g. Maria Santos" value="${escapeHTML(currentAccount?.name || "")}" /></div>
          <div class="form-field"><label for="resident-contact">Contact number <span class="optional">· optional</span></label><input id="resident-contact" name="contact" autocomplete="tel" maxlength="30" placeholder="09XX XXX XXXX" /></div>
          <div class="form-field full"><label for="resident-address">Purok / address</label><input id="resident-address" name="address" maxlength="140" required placeholder="e.g. Purok 2, Riverside" /></div>
          <div class="form-field full"><label for="request-description">How can we help?</label><textarea id="request-description" name="description" maxlength="1200" required minlength="8" placeholder="Describe your request or concern. If it needs urgent attention, let us know why."></textarea><span class="field-help">Please don't include passwords, financial details, or other sensitive personal information.</span></div>
        </div>
        <div class="form-actions"><span class="privacy-copy">By submitting, you agree that barangay staff may use these details to respond to your request.</span><button class="button button-primary" type="submit">Submit request <span aria-hidden="true">→</span></button></div>
      </form>
      <aside>
        <div class="classification-card"><h3>Request assessment</h3><p class="classification-label">A quick, transparent text check suggests a category and flags possible urgency.</p><div class="prediction-box"><span class="prediction-caption">Suggested category</span><div class="prediction-category" id="prediction-category">Add a request description</div><div class="prediction-urgency" id="prediction-urgency"><span class="urgency-dot"></span><span>Priority not assessed</span></div></div><p class="classifier-disclaimer">This prototype uses example keyword rules, not a trained AI model. Staff should review every suggestion before taking action.</p></div>
        <div class="guidance-card"><strong>Need immediate help?</strong><p>This portal is not monitored for emergencies. Contact your local emergency hotline or visit your barangay hall directly.</p></div>
      </aside>
    </div>
  `;
}

function renderAccount() {
  if (passwordRecovery || accountMode === "update-password") {
    return `
      ${pageHeading("RESIDENT PORTAL", "Choose a new password", "Create a new password for your Baranggay San Isidro account.")}
      <section class="form-card account-card">
        <form id="password-update-form" class="account-form">
          <div class="form-field"><label for="new-password">New password</label><input id="new-password" name="password" type="password" autocomplete="new-password" minlength="8" maxlength="128" required placeholder="At least 8 characters" /></div>
          <div class="form-field"><label for="confirm-new-password">Confirm new password</label><input id="confirm-new-password" name="confirmPassword" type="password" autocomplete="new-password" minlength="8" maxlength="128" required placeholder="Re-enter your new password" /></div>
          <button class="button button-primary account-submit" type="submit">Save new password</button>
        </form>
        <p class="account-disclaimer">Only use this form after opening the password reset link sent by Supabase.</p>
      </section>
    `;
  }

  if (currentAccount) {
    const initials = currentAccount.name.trim().split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase();
    return `
      ${pageHeading("RESIDENT PORTAL", "Your account", "Manage your Baranggay San Isidro sign-in.")}
      <section class="form-card account-card">
        <div class="account-summary"><div class="account-avatar">${escapeHTML(initials || "BL")}</div><div><h2>${escapeHTML(currentAccount.name)}</h2><p>${escapeHTML(currentAccount.email)}</p></div></div>
        <div class="account-status"><span class="online-dot"></span> You’re signed in to your Supabase account.</div>
        <p class="form-intro">Your account is stored by the connected Supabase project. Your sign-in stays on this browser until you log out.</p>
        <button class="button button-secondary" id="logout-button" type="button">Log out</button>
        <p class="account-disclaimer">Account authentication is handled by Supabase. Service requests are still stored in this browser and are not shared between devices.</p>
      </section>
    `;
  }

  const creating = accountMode === "create";
  const accountDescription = supabase
    ? "Create an account or log in. Your account is saved in the connected Supabase project."
    : "Connect a free Supabase project to store accounts and enable registration and login.";
  const formDescription = !supabase
    ? "Set up and connect your free Supabase project before creating an account."
    : creating
      ? "Your account is saved in Supabase. You’ll be logged in automatically if email confirmation is disabled."
      : accountMode === "reset"
        ? "Enter the email address on your account. We’ll send a secure password reset link."
        : "Log in with the email and password you registered with.";
  const emailCooldownActive = !canSendAuthEmail();
  if (accountMode === "reset") {
    return `
      ${pageHeading("RESIDENT PORTAL", "Reset your password", "We’ll email you a secure link to choose a new password.")}
      <section class="form-card account-card">
        ${supabaseConfigurationError ? `<div class="account-setup-alert" role="status"><strong>Account service not connected</strong><span>${escapeHTML(supabaseConfigurationError)}</span></div>` : ""}
        ${accountNotice ? `<div class="account-setup-alert account-notice" role="status"><strong>Password reset</strong><span>${escapeHTML(accountNotice)}</span></div>` : ""}
        <form id="password-reset-form" class="account-form">
          <div class="form-field"><label for="reset-email">Email address</label><input id="reset-email" name="email" type="email" autocomplete="email" maxlength="254" required placeholder="you@example.com" value="${escapeHTML(accountEmail)}" /></div>
          ${emailCooldownActive ? `<p class="account-help">${escapeHTML(emailRateLimitMessage())} This does not block password login; it only pauses email-based actions.</p>` : ""}
          <button class="button button-primary account-submit" type="submit"${supabaseConfigurationError || emailCooldownActive ? " disabled" : ""}>Send reset link</button>
        </form>
        <button class="account-text-button" type="button" data-account-mode="login">Back to log in</button>
        <p class="account-disclaimer">${formDescription}</p>
      </section>
    `;
  }
  return `
    ${pageHeading("RESIDENT PORTAL", "Welcome to Baranggay San Isidro", accountDescription)}
    <section class="form-card account-card">
      ${supabaseConfigurationError ? `<div class="account-setup-alert" role="status"><strong>Account service not connected</strong><span>${escapeHTML(supabaseConfigurationError)}</span></div>` : ""}
    ${accountNotice ? `<div class="account-setup-alert account-notice" role="status"><strong>Account update</strong><span>${escapeHTML(accountNotice)}</span>${pendingConfirmationEmail && accountMode === "login" && !emailCooldownActive ? '<button class="account-text-button" id="resend-confirmation" type="button">Resend confirmation email</button>' : ""}</div>` : ""}
      <div class="account-tabs" role="tablist" aria-label="Account action">
        <button class="account-tab${creating ? " active" : ""}" type="button" data-account-mode="create" role="tab" aria-selected="${creating}">Create account</button>
        <button class="account-tab${!creating ? " active" : ""}" type="button" data-account-mode="login" role="tab" aria-selected="${!creating}">Log in</button>
      </div>
      <h2>${creating ? "Create your account" : "Welcome back"}</h2>
      <p class="form-intro">${formDescription}</p>
      <form id="account-form" class="account-form">
        ${creating ? `<div class="form-field"><label for="account-name">Full name</label><input id="account-name" name="name" autocomplete="name" maxlength="100" required placeholder="e.g. Maria Santos" /></div>` : ""}
        <div class="form-field"><label for="account-email">Email address</label><input id="account-email" name="email" type="email" autocomplete="email" maxlength="254" required placeholder="you@example.com" value="${escapeHTML(accountEmail)}" /></div>
        <div class="form-field"><label for="account-password">Password</label><input id="account-password" name="password" type="password" autocomplete="${creating ? "new-password" : "current-password"}" minlength="8" maxlength="128" required placeholder="${creating ? "At least 8 characters" : "Enter your password"}" /></div>
        ${creating ? `<div class="form-field"><label for="account-confirm-password">Confirm password</label><input id="account-confirm-password" name="confirmPassword" type="password" autocomplete="new-password" minlength="8" maxlength="128" required placeholder="Re-enter your password" /></div>` : ""}
        <button class="button button-primary account-submit" type="submit"${supabaseConfigurationError || (creating && emailCooldownActive) ? " disabled" : ""}>${creating ? "Create account" : "Log in"} <span aria-hidden="true">→</span></button>
        ${!creating ? '<button class="account-text-button" id="forgot-password" type="button">Forgot password?</button>' : ""}
      </form>
      ${creating && emailCooldownActive ? `<p class="account-help">${escapeHTML(emailRateLimitMessage())}</p>` : ""}
      <p class="account-disclaimer">Accounts and passwords are managed by Supabase, not stored in this website’s repository. The Supabase project URL and publishable key are public browser configuration; never put a service-role key here.</p>
    </section>
  `;
}

function renderLanding() {
  const primaryAction = currentAccount
    ? '<button class="landing-button landing-button-primary" data-landing-action="portal">Go to my portal <span aria-hidden="true">→</span></button>'
    : '<button class="landing-button landing-button-primary" data-landing-action="create">Create an account <span aria-hidden="true">→</span></button>';
  const accountLink = currentAccount
    ? `<button class="landing-login" data-landing-action="portal">My portal</button>`
    : `<button class="landing-login" data-landing-action="login">Log in</button>`;
  return `
    <header class="landing-header">
      <a class="landing-brand" href="#" data-landing-action="home" aria-label="Baranggay San Isidro home">
        <span class="landing-brand-mark" aria-hidden="true">＋</span>
        <span><strong>Baranggay San Isidro</strong><small>BARANGAY SERVICE DESK</small></span>
      </a>
      <nav class="landing-nav" aria-label="Landing page navigation">
        <a href="#landing-services">Services</a>
        <a href="#landing-how">How it works</a>
        <button class="landing-nav-link" data-landing-action="track">Track a request</button>
        ${accountLink}
        ${currentAccount ? "" : '<button class="landing-register" data-landing-action="create">Create account</button>'}
      </nav>
      <button class="landing-menu" id="landing-menu" aria-label="Open navigation" aria-expanded="false">☰</button>
    </header>
    <main>
      <section class="landing-hero">
        <div class="landing-hero-inner">
          <div class="landing-copy">
            <div class="landing-kicker"><span class="landing-kicker-dot"></span> YOUR BARANGAY, HERE FOR YOU</div>
            <h1>Better services.<br /><span>Stronger community.</span></h1>
            <p class="landing-lead">A simpler way to reach your barangay. Submit a service request, follow its progress, and help make our community a better place for everyone.</p>
            <div class="landing-actions">${primaryAction}<button class="landing-button landing-button-outline" data-landing-action="track">Track a request</button></div>
            <div class="landing-trust"><span class="trust-check">✓</span> Easy to use <span class="trust-separator">·</span><span class="trust-check">✓</span> Keep up to date <span class="trust-separator">·</span><span class="trust-check">✓</span> Here for our community</div>
          </div>
          <div class="landing-art" aria-hidden="true">
            <div class="art-orbit orbit-one"></div><div class="art-orbit orbit-two"></div>
            <div class="art-sun"></div><div class="art-cloud cloud-one"></div><div class="art-cloud cloud-two"></div>
            <div class="art-building building-back"><i></i><i></i><i></i><i></i></div>
            <div class="art-building building-front"><i></i><i></i><i></i></div>
            <div class="art-home"><div class="home-roof"></div><div class="home-body"><span class="home-cross">＋</span><span class="home-door"></span></div></div>
            <div class="art-ground"></div>
            <div class="art-request-card"><span class="art-card-icon">✓</span><span><strong>Request received</strong><small>Your barangay is on it.</small></span><span class="art-card-status">NEW</span></div>
            <div class="art-note"><span>✳</span> Better, together.</div>
          </div>
          <div class="landing-scroll-cue"><span></span> A more connected community</div>
        </div>
      </section>
      <section class="landing-services" id="landing-services">
        <div class="landing-section-heading"><div><p class="landing-section-kicker">HOW WE CAN HELP</p><h2>Local support, made simpler.</h2></div><p>One place to share a concern, ask for help, and stay informed about your request.</p></div>
        <div class="landing-service-grid">
          <article class="landing-service-card"><span class="service-icon service-doc">▤</span><h3>Barangay documents</h3><p>Ask about clearances, certificates, and other barangay documents.</p></article>
          <article class="landing-service-card"><span class="service-icon service-community">♡</span><h3>Community concerns</h3><p>Share feedback or raise a concern for the barangay team.</p></article>
          <article class="landing-service-card"><span class="service-icon service-place">⌖</span><h3>Neighborhood services</h3><p>Report local infrastructure, sanitation, and safety concerns.</p></article>
          <article class="landing-service-card"><span class="service-icon service-track">◷</span><h3>Request tracking</h3><p>Use your reference number to check the latest request status.</p></article>
        </div>
      </section>
      <section class="landing-how" id="landing-how"><div><p class="landing-section-kicker">GETTING STARTED</p><h2>Help is just a few steps away.</h2><p>Create an account, tell us what you need, and check your request whenever you like.</p></div><button class="landing-button landing-button-primary" data-landing-action="${currentAccount ? "portal" : "create"}">${currentAccount ? "Go to my portal" : "Get started"} <span aria-hidden="true">→</span></button></section>
    </main>
    <footer class="landing-footer"><a class="landing-footer-brand" href="#" data-landing-action="home">Baranggay San Isidro</a><span>Barangay services, connected to the community.</span><span>Prototype · requests remain in this browser</span></footer>
  `;
}

function renderTrack() {
  const request = trackingCode
    ? requests.find((item) => item.id.toLowerCase() === trackingCode.trim().toLowerCase())
    : null;
  let result = "";
  if (trackingCode) {
    if (request) {
      const currentIndex = statuses.indexOf(request.status);
      result = `
        <div class="tracking-result">
          <div class="panel-heading"><div><h2>Request ${escapeHTML(request.id)}</h2><p>Submitted ${formatDateTime(request.createdAt)}</p></div>${statusPill(request.status)}</div>
          <p class="detail-description">${escapeHTML(request.description)}</p>
          <div class="detail-grid"><div class="detail-cell"><small>Category</small><strong>${escapeHTML(request.category)}</strong></div><div class="detail-cell"><small>Priority</small><strong>${request.urgent ? "Urgent" : "Normal"}</strong></div></div>
          <h3 class="eyebrow">STATUS UPDATES</h3>
          <div class="timeline">${statuses.map((status, index) => {
            const completed = index <= currentIndex;
            return `<div class="timeline-item ${completed ? "" : "pending"}"><span class="timeline-dot"></span><span class="timeline-copy"><strong>${status}</strong><small>${completed ? (status === request.status ? `Current status · ${formatDateTime(request.createdAt)}` : "Step completed") : "Not started yet"}</small></span></div>`;
          }).join("")}</div>
        </div>`;
    } else {
      result = '<div class="tracking-result empty-state">No request found for that reference. Please check the code and try again.</div>';
    }
  }
  return `
    ${pageHeading("RESIDENT PORTAL", "Track your request", "Enter the reference number you received when your request was submitted.")}
    <div class="tracker-layout">
      <section class="form-card"><h2>Find a request</h2><p class="form-intro">Your reference number looks like <strong>BL-2026-041</strong>. Request details are only available with the exact reference.</p>
        <form class="track-form" id="track-form"><label class="sr-only" for="tracking-code">Request reference</label><input class="field-control" id="tracking-code" name="trackingCode" required maxlength="32" placeholder="Enter your reference number" value="${escapeHTML(trackingCode)}" /><button class="button button-primary" type="submit">Track request</button></form>
        ${result}
      </section>
      <aside class="classification-card"><h3>What do the statuses mean?</h3><p class="classification-label">Your request moves through these steps as the barangay team works on it.</p><div class="timeline">${statuses.map((status) => `<div class="timeline-item"><span class="timeline-dot"></span><span class="timeline-copy"><strong>${status}</strong><small>${({
    "New": "Received by the service desk",
    "In review": "Being checked by barangay staff",
    "In progress": "The team is working on it",
    "Resolved": "Marked complete by the team",
  })[status]}</small></span></div>`).join("")}</div></aside>
    </div>
  `;
}

function renderQueue() {
  const rows = [...requests].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  return `
    ${pageHeading("STAFF WORKSPACE", "Request queue", "Review, assign, and update requests received by your barangay.",
      '<button class="button button-primary" data-page="submit"><span class="button-icon">＋</span> New request</button>')}
    <section class="panel queue-panel">
      <div class="panel-heading"><div><h2>All service requests</h2><p>Open any request to view its details or update its status.</p></div><span class="result-count" id="result-count">${rows.length} requests</span></div>
      <div class="filter-bar"><label class="search-input"><span class="sr-only">Search requests</span><input id="queue-search" type="search" placeholder="Search requests…" /></label>
        <label><span class="sr-only">Filter by status</span><select class="field-control" id="queue-status"><option value="">All statuses</option>${statuses.map((status) => `<option>${status}</option>`).join("")}</select></label>
        <label><span class="sr-only">Filter by category</span><select class="field-control" id="queue-category"><option value="">All categories</option>${categories.map((category) => `<option>${category}</option>`).join("")}</select></label>
      </div>
      <div class="table-wrap"><table class="request-table"><thead><tr><th>Reference</th><th>Request</th><th>Category</th><th>Resident</th><th>Priority</th><th>Status</th><th>Received</th></tr></thead><tbody id="queue-rows">${renderTableRows(rows, true)}</tbody></table></div>
    </section>
  `;
}

function renderReports() {
  const resolved = requests.filter((request) => request.status === "Resolved").length;
  const urgent = requests.filter((request) => request.urgent).length;
  const open = requests.length - resolved;
  const maxCategory = Math.max(1, ...categories.map((category) => requests.filter((request) => request.category === category).length));
  const categoryRows = categories.map((category) => {
    const count = requests.filter((request) => request.category === category).length;
    return `<div class="report-bar-row"><span>${category}</span><div class="report-bar-track"><div class="report-bar-fill" style="width:${Math.max(count ? 5 : 0, count / maxCategory * 100)}%"></div></div><span>${count}</span></div>`;
  }).join("");
  const statusMetrics = statuses.map((status) => `<div class="report-metric"><strong>${requests.filter((request) => request.status === status).length}</strong><span>${status}</span></div>`).join("");
  return `
    ${pageHeading("STAFF WORKSPACE", "Service reports", "A snapshot of requests and community service activity.",
      '<button class="button button-secondary" id="export-csv"><span class="button-icon">↓</span> Export CSV</button>')}
    <section class="report-grid">
      <article class="report-card"><h2>Request summary</h2><p>All requests currently in this browser</p><div class="report-metrics"><div class="report-metric"><strong>${requests.length}</strong><span>Total received</span></div><div class="report-metric"><strong>${open}</strong><span>Still open</span></div><div class="report-metric"><strong>${urgent}</strong><span>Flagged urgent</span></div></div></article>
      <article class="report-card"><h2>Status breakdown</h2><p>Progress across all requests</p><div class="report-metrics">${statusMetrics}</div></article>
      <article class="report-card"><h2>Requests by category</h2><p>Distribution of community concerns</p><div class="report-bars">${categoryRows}</div></article>
      <article class="report-card"><h2>Evaluation reminder</h2><p>For a complete system assessment</p><div class="report-insight"><strong>Prototype data is not an accuracy or usability study.</strong> Evaluate a trained classifier using a labeled test set (for example, per-category precision, recall, and F1), and assess usability with representative residents and staff using an agreed standard such as ISO/IEC 25010.</div></article>
      <article class="report-card report-wide"><h2>Data and privacy</h2><p>Know where this prototype stores information</p><div class="report-insight">Requests are saved in this browser’s local storage for demonstration. There is no server, staff authentication, multi-device sync, trained AI model, or secure resident identity verification. Do not enter real sensitive or confidential information.</div></article>
    </section>
  `;
}

const pageTitles = {
  landing: "Home",
  overview: "Overview",
  submit: "Submit a request",
  track: "Track a request",
  queue: "Request queue",
  reports: "Reports",
  account: "Account",
};

function render() {
  if (protectedPages.has(currentPage) && !currentAccount) {
    currentPage = "account";
    accountMode = "login";
    accountNotice = "Please log in to access the workspace.";
  }
  const landingPage = document.querySelector("#landing-page");
  const appShell = document.querySelector(".app-shell");
  if (currentPage === "landing") {
    landingPage.innerHTML = renderLanding();
    landingPage.hidden = false;
    appShell.hidden = true;
    bindLandingEvents();
    return;
  }
  landingPage.hidden = true;
  appShell.hidden = false;
  appShell.classList.toggle("is-signed-out", !currentAccount);
  const content = document.querySelector("#page-content");
  const renderer = {
    overview: renderOverview,
    submit: renderSubmit,
    track: renderTrack,
    queue: renderQueue,
    reports: renderReports,
    account: renderAccount,
  }[currentPage];
  document.querySelector("#breadcrumb-current").textContent = pageTitles[currentPage];
  document.querySelectorAll(".nav-item").forEach((item) => {
    const active = item.dataset.page === currentPage;
    item.classList.toggle("active", active);
    if (active) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  });
  document.querySelector("#queue-nav-count").textContent = requests.filter((request) => request.status !== "Resolved").length;
  document.querySelector("#profile-avatar").textContent = currentAccount
    ? currentAccount.name.trim().split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase()
    : "BS";
  document.querySelector("#profile-name").textContent = currentAccount?.name || "Barangay staff";
  document.querySelector("#profile-caption").textContent = currentAccount ? currentAccount.email : "Service desk";
  document.querySelector("#profile-action").textContent = currentAccount ? "↗" : "···";
  document.querySelector("#profile-action").setAttribute("aria-label", currentAccount ? "Open account settings" : "Open account");
  content.innerHTML = renderer();
  bindPageEvents();
}

function goTo(page) {
  if (!pageTitles[page]) return;
  if (protectedPages.has(page) && !currentAccount) {
    pendingRequestPage = page;
    accountMode = "login";
    currentPage = "account";
    accountNotice = "Please log in to access the workspace.";
    render();
    document.querySelector("#page-content")?.focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: "smooth" });
    return;
  }
  currentPage = page;
  trackingCode = "";
  render();
  document.querySelector("#page-content")?.focus({ preventScroll: true });
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function continueAfterLogin() {
  const destination = pendingRequestPage || "overview";
  pendingRequestPage = "";
  accountNotice = "";
  goTo(destination);
}

function bindLandingEvents() {
  document.querySelectorAll("[data-landing-action]").forEach((element) => {
    element.addEventListener("click", (event) => {
      const action = event.currentTarget.dataset.landingAction;
      if (action === "login") accountMode = "login";
      if (action === "create") accountMode = "create";
      if (action === "home") {
        event.preventDefault();
        goTo("landing");
        return;
      }
      if (action === "track") goTo("track");
      else if (action === "portal") goTo(currentAccount ? "overview" : "account");
      else if (action === "login" || action === "create") goTo("account");
    });
  });
  const menu = document.querySelector("#landing-menu");
  menu.addEventListener("click", () => {
    const open = menu.getAttribute("aria-expanded") !== "true";
    menu.setAttribute("aria-expanded", String(open));
    menu.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    document.querySelector(".landing-nav").classList.toggle("is-open", open);
  });
  document.querySelectorAll(".landing-nav a").forEach((link) => {
    link.addEventListener("click", () => {
      menu.setAttribute("aria-expanded", "false");
      menu.setAttribute("aria-label", "Open navigation");
      document.querySelector(".landing-nav").classList.remove("is-open");
    });
  });
}

function showToast(message, error = false) {
  const toast = document.createElement("div");
  toast.className = `toast${error ? " error" : ""}`;
  toast.textContent = message;
  document.querySelector("#toast-region").append(toast);
  window.setTimeout(() => toast.remove(), 3400);
}

function appendChatMessage(role, text) {
  const message = document.createElement("div");
  message.className = `chat-message ${role}`;
  message.textContent = text;
  document.querySelector("#chat-messages").append(message);
  message.scrollIntoView({ block: "nearest" });
  return message;
}

function getSupportReply(question) {
  const value = question.toLowerCase();
  const matches = (...terms) => terms.some((term) => value.includes(term));

  if (matches("911", "emergency", "emergencies", "urgent danger", "life-threatening")) {
    return "If someone is in immediate danger, call 911 now. This chat is not monitored and cannot contact emergency services.";
  }
  if (matches("password", "bank", "credit card", "personal information", "private information", "phone number", "my address")) {
    return "Please don’t share passwords, account details, addresses, phone numbers, or other sensitive information in chat. This support chat cannot look up or change your account or requests.";
  }
  if (matches("track", "tracking", "reference number", "status", "follow up")) {
    return "To track a request, log in to your account, open “Track a request,” and enter the reference number you received when submitting it. This prototype stores requests in the current browser, so they may not appear on another device.";
  }
  if (matches("submit", "file a request", "make a request", "send a request", "report a concern", "complaint")) {
    return "To submit a request, log in or create an account, choose “Submit a request,” and describe the concern with your purok or address. Don’t include sensitive information. Requests in this prototype are saved only in the current browser.";
  }
  if (matches("account", "sign up", "signup", "register", "create a user", "log in", "login", "sign in")) {
    return "Choose “Create account” to register with your name, email, and password, or choose “Log in” if you already have an account. Check your email for a confirmation message if your account requires one.";
  }
  if (matches("document", "documents", "clearance", "certificate", "indigency", "permit")) {
    return "You can submit questions or requests about barangay documents through “Submit a request.” This chat doesn’t have verified document requirements, fees, or processing times—please confirm those details with the barangay office.";
  }
  if (matches("office", "open", "hours", "schedule", "contact", "phone", "address", "fee", "fees", "how much", "requirements")) {
    return "I don’t have verified office hours, contact details, fees, or official requirements. Please check directly with the barangay office for accurate information.";
  }
  return "I can help with creating an account, submitting or tracking a request, and general document questions. I don’t have verified barangay policies or access to request records—please check with the barangay office for those details.";
}

function sendChatMessage(text) {
  if (chatSubmitting) return;
  const input = document.querySelector("#chat-input");
  const form = document.querySelector("#chat-form");
  const sendButton = form.querySelector('button[type="submit"]');
  chatSubmitting = true;
  input.disabled = true;
  sendButton.disabled = true;
  document.querySelector("#chat-suggestions")?.remove();
  appendChatMessage("user", text);
  appendChatMessage("assistant", getSupportReply(text));
  chatSubmitting = false;
  input.disabled = false;
  sendButton.disabled = false;
  if (!document.querySelector("#chat-panel").hidden) input.focus();
}

function initializeChatWidget() {
  const panel = document.querySelector("#chat-panel");
  const launcher = document.querySelector("#chat-launcher");
  const input = document.querySelector("#chat-input");
  const form = document.querySelector("#chat-form");
  const close = document.querySelector("#chat-close");

  function setOpen(open) {
    panel.hidden = !open;
    launcher.setAttribute("aria-expanded", String(open));
    if (open) input.focus();
    else launcher.focus();
  }

  launcher.addEventListener("click", () => setOpen(panel.hidden));
  close.addEventListener("click", () => setOpen(false));
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const text = input.value.trim();
    if (!text || chatSubmitting) return;
    input.value = "";
    sendChatMessage(text);
  });
  document.querySelector("#chat-suggestions").addEventListener("click", (event) => {
    const button = event.target.closest("button");
    if (!button || chatSubmitting) return;
    sendChatMessage(button.textContent);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !panel.hidden) setOpen(false);
  });
}

function bindPageEvents() {
  document.querySelectorAll("[data-page]").forEach((button) => {
    button.addEventListener("click", () => goTo(button.dataset.page));
  });
  document.querySelectorAll("[data-open-request]").forEach((element) => {
    element.addEventListener("click", () => openRequest(element.dataset.openRequest));
    element.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openRequest(element.dataset.openRequest);
      }
    });
  });

  document.querySelectorAll("[data-account-mode]").forEach((button) => {
    button.addEventListener("click", () => {
      accountMode = button.dataset.accountMode;
      accountNotice = "";
      render();
      document.querySelector(`#account-${accountMode === "create" ? "name" : "email"}`)?.focus();
    });
  });
  const accountForm = document.querySelector("#account-form");
  if (accountForm) accountForm.addEventListener("submit", submitAccountForm);
  const resetForm = document.querySelector("#password-reset-form");
  if (resetForm) resetForm.addEventListener("submit", submitPasswordReset);
  const resendConfirmation = document.querySelector("#resend-confirmation");
  if (resendConfirmation) resendConfirmation.addEventListener("click", resendConfirmationEmail);
  const passwordUpdateForm = document.querySelector("#password-update-form");
  if (passwordUpdateForm) passwordUpdateForm.addEventListener("submit", submitPasswordUpdate);
  const forgotPassword = document.querySelector("#forgot-password");
  if (forgotPassword) {
    forgotPassword.addEventListener("click", () => {
      accountMode = "reset";
      accountNotice = "";
      render();
    });
  }
  const logoutButton = document.querySelector("#logout-button");
  if (logoutButton) logoutButton.addEventListener("click", logout);

  const description = document.querySelector("#request-description");
  if (description) {
    description.addEventListener("input", () => updatePrediction(description.value));
    document.querySelector("#request-form").addEventListener("submit", submitRequest);
  }

  const trackForm = document.querySelector("#track-form");
  if (trackForm) {
    trackForm.addEventListener("submit", (event) => {
      event.preventDefault();
      trackingCode = new FormData(trackForm).get("trackingCode").trim();
      render();
    });
  }

  const search = document.querySelector("#queue-search");
  if (search) {
    [search, document.querySelector("#queue-status"), document.querySelector("#queue-category")].forEach((control) => {
      control.addEventListener("input", filterQueue);
      control.addEventListener("change", filterQueue);
    });
  }

  const exportButton = document.querySelector("#export-csv");
  if (exportButton) exportButton.addEventListener("click", exportCSV);
}

async function submitAccountForm(event) {
  event.preventDefault();
  if (accountSubmitting) return;
  if (!supabase) {
    showToast("Connect a Supabase project before using account registration or login.", true);
    return;
  }
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  if (accountMode === "create" && !canSendAuthEmail()) {
    accountNotice = emailRateLimitMessage();
    render();
    return;
  }
  accountSubmitting = true;
  const submitButton = form.querySelector('button[type="submit"]');
  submitButton.disabled = true;
  try {
    const values = new FormData(form);
    const email = values.get("email").trim().toLowerCase();
    accountEmail = email;
    const password = values.get("password");

    if (accountMode === "create") {
      const name = values.get("name").trim();
      if (name.length < 2) {
        showToast("Please enter your full name.", true);
        return;
      }
      if (password !== values.get("confirmPassword")) {
        showToast("The passwords do not match.", true);
        return;
      }
      const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: { full_name: name },
          emailRedirectTo: new URL(window.location.pathname, window.location.origin).href,
        },
      });
      if (error) throw error;
      if (data.session) {
        currentAccount = accountFromUser(data.user);
        if (pendingRequestPage) continueAfterLogin();
        else render();
        showToast("Account created and saved to Supabase. You’re now logged in.");
      } else {
        currentAccount = null;
        pendingConfirmationEmail = email;
        accountMode = "login";
        setEmailCooldown(EMAIL_SEND_COOLDOWN_MS);
        accountNotice = "Your account has been saved. Check your email to confirm it, then log in. Email confirmation can be changed in your Supabase Auth settings.";
        render();
        showToast("Account created. Check your email to confirm the address.");
      }
      return;
    }

    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) {
      const errorMessage = error.message.toLowerCase();
      if (errorMessage.includes("not confirmed")) {
        pendingConfirmationEmail = email;
        accountNotice = "Supabase requires this email address to be confirmed before login. Check your inbox and spam folder for the confirmation link. If you cannot find it, wait for the email limit to clear and use the resend option, or ask the project owner to confirm the user in Supabase.";
        render();
        return;
      }
      if (errorMessage.includes("invalid login credentials")) {
        const legacyAccount = findLegacyAccount(email);
        if (legacyAccount && await verifyLegacyPassword(password, legacyAccount.salt, legacyAccount.passwordHash)) {
          await migrateLegacyAccount(legacyAccount, email, password);
          return;
        }
        accountNotice = legacyAccount
          ? "These credentials don’t match your older browser account. Try the password you originally used, or reset your Supabase password."
          : "Supabase could not sign you in. Check that the account exists in this project and that its email is confirmed (Authentication → Users). If it is confirmed, check your email and password or use Forgot password. Email confirmation is currently required for new accounts.";
        pendingConfirmationEmail = email;
        render();
        showToast("Email or password not recognized. See the account help message.", true);
        return;
      }
      throw error;
    }
    currentAccount = accountFromUser(data.user);
    if (pendingRequestPage) continueAfterLogin();
    else render();
    showToast("You’re logged in.");
  } catch (error) {
    if (accountMode === "create" && isEmailRateLimitError(error)) {
      setEmailCooldown(EMAIL_RATE_LIMIT_COOLDOWN_MS);
      accountNotice = emailRateLimitMessage();
      render();
      showToast("Supabase email limit reached. Please wait before requesting another email.", true);
      return;
    }
    console.error("Could not complete account authentication:", error);
    showToast(error.message || "Could not authenticate with Supabase. Check your connection and try again.", true);
  } finally {
    accountSubmitting = false;
    if (submitButton.isConnected) submitButton.disabled = false;
  }
}

async function resendConfirmationEmail(event) {
  const button = event.currentTarget;
  if (!supabase || !pendingConfirmationEmail || button.disabled) return;
  if (!canSendAuthEmail()) {
    accountNotice = emailRateLimitMessage();
    render();
    return;
  }
  button.disabled = true;
  try {
    const { error } = await supabase.auth.resend({
      type: "signup",
      email: pendingConfirmationEmail,
      options: {
        emailRedirectTo: new URL(window.location.pathname, window.location.origin).href,
      },
    });
    if (error) throw error;
    setEmailCooldown(EMAIL_SEND_COOLDOWN_MS);
    accountNotice = "If this account still needs confirmation, Supabase has sent a new link. Check your inbox and spam folder.";
    render();
    showToast("If the account needs confirmation, a new email is on its way.");
  } catch (error) {
    if (isEmailRateLimitError(error)) {
      setEmailCooldown(EMAIL_RATE_LIMIT_COOLDOWN_MS);
      accountNotice = emailRateLimitMessage();
      render();
      showToast("Supabase email limit reached. Please wait before requesting another email.", true);
      return;
    }
    console.error("Could not resend the confirmation email:", error);
    showToast(error.message || "Could not resend the confirmation email. Please try again later.", true);
    if (button.isConnected) button.disabled = false;
  }
}

async function migrateLegacyAccount(legacyAccount, email, password) {
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      data: { full_name: legacyAccount.name },
      emailRedirectTo: new URL(window.location.pathname, window.location.origin).href,
    },
  });
  if (error) {
    const errorMessage = error.message.toLowerCase();
    if (errorMessage.includes("already") || errorMessage.includes("registered")) {
      accountNotice = "Your old browser account matches, but this email already has a different Supabase account. Use Forgot password to reset the Supabase password.";
      render();
      return;
    }
    throw error;
  }
  if (Array.isArray(data.user?.identities) && data.user.identities.length === 0) {
    accountNotice = "Your old browser account matches, but a Supabase account already exists for this email. Use Forgot password to reset the Supabase password.";
    render();
    return;
  }
  if (!data.user || !data.session) {
    accountNotice = "Your old browser account was verified and migrated to Supabase. Check your email to confirm the account, then log in.";
    accountMode = "login";
    render();
    return;
  }
  removeLegacyAccount(email);
  currentAccount = accountFromUser(data.user);
  if (pendingRequestPage) continueAfterLogin();
  else render();
  showToast("Your older browser account was moved to Supabase. You’re now logged in.");
}

function removeLegacyAccount(email) {
  try {
    const saved = localStorage.getItem(LEGACY_ACCOUNTS_STORAGE_KEY);
    if (saved === null) return;
    const parsed = JSON.parse(saved);
    if (!Array.isArray(parsed)) throw new Error("Saved legacy account data is not a list.");
    localStorage.setItem(LEGACY_ACCOUNTS_STORAGE_KEY, JSON.stringify(
      parsed.filter((account) => account?.email?.toLowerCase() !== email)));
  } catch (error) {
    console.error("Could not remove a migrated legacy account from this browser:", error);
  }
}

async function submitPasswordReset(event) {
  event.preventDefault();
  if (accountSubmitting) return;
  if (!canSendAuthEmail()) {
    accountNotice = emailRateLimitMessage();
    render();
    return;
  }
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  accountSubmitting = true;
  const submitButton = form.querySelector('button[type="submit"]');
  submitButton.disabled = true;
  try {
    const email = new FormData(form).get("email").trim().toLowerCase();
    accountEmail = email;
    const redirectTo = new URL(window.location.pathname, window.location.origin).href;
    const { error } = await supabase.auth.resetPasswordForEmail(email, { redirectTo });
    if (error) throw error;
    setEmailCooldown(EMAIL_SEND_COOLDOWN_MS);
    accountNotice = "If an account exists for that address, Supabase will send a password reset email. Check your inbox and spam folder.";
    render();
  } catch (error) {
    if (isEmailRateLimitError(error)) {
      setEmailCooldown(EMAIL_RATE_LIMIT_COOLDOWN_MS);
      accountNotice = emailRateLimitMessage();
      render();
      showToast("Supabase email limit reached. Please wait before requesting another email.", true);
      return;
    }
    console.error("Could not request a password reset:", error);
    showToast(error.message || "Could not send a reset email. Please try again.", true);
  } finally {
    accountSubmitting = false;
    if (submitButton.isConnected) submitButton.disabled = false;
  }
}

async function submitPasswordUpdate(event) {
  event.preventDefault();
  if (accountSubmitting) return;
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  accountSubmitting = true;
  const submitButton = form.querySelector('button[type="submit"]');
  submitButton.disabled = true;
  try {
    const values = new FormData(form);
    const password = values.get("password");
    if (password !== values.get("confirmPassword")) {
      showToast("The passwords do not match.", true);
      return;
    }
    const { data, error } = await supabase.auth.updateUser({ password });
    if (error) throw error;
    passwordRecovery = false;
    accountMode = "login";
    currentAccount = accountFromUser(data.user);
    accountNotice = "Your password has been updated.";
    if (pendingRequestPage) continueAfterLogin();
    else render();
    showToast("Password updated. You’re logged in.");
  } catch (error) {
    console.error("Could not update the password:", error);
    showToast(error.message || "Could not update the password. Request a new reset link and try again.", true);
  } finally {
    accountSubmitting = false;
    if (submitButton.isConnected) submitButton.disabled = false;
  }
}

async function logout() {
  if (!supabase) return;
  try {
    const { error } = await supabase.auth.signOut({ scope: "local" });
    if (error) throw error;
    currentAccount = null;
    accountMode = "login";
    accountNotice = "";
    render();
    showToast("You’re logged out.");
  } catch (error) {
    console.error("Could not log out:", error);
    showToast(error.message || "Could not log out of Supabase. Please try again.", true);
  }
}

function updatePrediction(text) {
  const prediction = classifyText(text);
  document.querySelector("#prediction-category").textContent = prediction.category;
  const urgency = document.querySelector("#prediction-urgency");
  urgency.classList.toggle("is-urgent", prediction.urgent);
  urgency.querySelector("span:last-child").textContent = text.trim()
    ? (prediction.urgent ? "May need urgent attention" : "No urgent keywords found")
    : "Priority not assessed";
}

function submitRequest(event) {
  event.preventDefault();
  if (!currentAccount) {
    goTo("submit");
    return;
  }
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const values = new FormData(form);
  const description = values.get("description").trim();
  if (description.length < 8) {
    showToast("Please add a little more detail to your request.", true);
    return;
  }
  const prediction = classifyText(description);
  const id = createReference();
  requests.unshift({
    id,
    name: values.get("name").trim(),
    contact: values.get("contact").trim(),
    address: values.get("address").trim(),
    description,
    category: prediction.category,
    urgent: prediction.urgent,
    status: "New",
    assigned: "Unassigned",
    createdAt: new Date().toISOString(),
  });
  if (!saveRequests()) {
    requests.shift();
    return;
  }
  trackingCode = id;
  showToast(`Request submitted. Your reference is ${id}.`);
  goTo("track");
  trackingCode = id;
  render();
}

function createReference() {
  let reference;
  const year = new Date().getFullYear();
  do {
    const serial = String(Math.floor(100 + Math.random() * 900));
    reference = `BL-${year}-${serial}`;
  } while (requests.some((request) => request.id === reference));
  return reference;
}

function filterQueue() {
  const query = document.querySelector("#queue-search").value.trim().toLowerCase();
  const selectedStatus = document.querySelector("#queue-status").value;
  const selectedCategory = document.querySelector("#queue-category").value;
  const filtered = [...requests]
    .filter((request) => {
      const searchText = [request.id, request.name, request.address, request.description, request.category].join(" ").toLowerCase();
      return (!query || searchText.includes(query)) &&
        (!selectedStatus || request.status === selectedStatus) &&
        (!selectedCategory || request.category === selectedCategory);
    })
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  document.querySelector("#queue-rows").innerHTML = renderTableRows(filtered, true);
  document.querySelector("#result-count").textContent = `${filtered.length} ${filtered.length === 1 ? "request" : "requests"}`;
  document.querySelectorAll("#queue-rows [data-open-request]").forEach((element) => {
    element.addEventListener("click", () => openRequest(element.dataset.openRequest));
    element.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openRequest(element.dataset.openRequest);
      }
    });
  });
}

function openRequest(id) {
  const request = requests.find((item) => item.id === id);
  if (!request) {
    showToast("That request could not be found.", true);
    return;
  }
  document.querySelector("#modal-root").innerHTML = `
    <div class="modal-backdrop" id="modal-backdrop">
      <section class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
        <div class="modal-heading"><div><h2 id="modal-title">Request details</h2><p>${escapeHTML(request.id)} · Received ${formatDateTime(request.createdAt)}</p></div><button class="icon-button" id="close-modal" aria-label="Close dialog">×</button></div>
        <p class="detail-description">${escapeHTML(request.description)}</p>
        <div class="detail-grid">
          <div class="detail-cell"><small>Resident</small><strong>${escapeHTML(request.name)}</strong></div>
          <div class="detail-cell"><small>Contact</small><strong>${escapeHTML(request.contact || "Not provided")}</strong></div>
          <div class="detail-cell"><small>Address</small><strong>${escapeHTML(request.address || "Not provided")}</strong></div>
          <div class="detail-cell"><small>Category · priority</small><strong>${escapeHTML(request.category)} · ${request.urgent ? "Urgent" : "Normal"}</strong></div>
        </div>
        <div class="form-grid">
          <div class="form-field"><label for="edit-status">Request status</label><select id="edit-status">${statuses.map((status) => `<option${status === request.status ? " selected" : ""}>${status}</option>`).join("")}</select></div>
          <div class="form-field"><label for="edit-assignee">Assigned to</label><input id="edit-assignee" maxlength="80" value="${escapeHTML(request.assigned || "")}" placeholder="Staff member or unassigned" /></div>
        </div>
        <div class="modal-actions"><button class="button button-secondary" id="cancel-modal">Close</button><button class="button button-primary" id="save-request" data-request-id="${escapeHTML(request.id)}">Save changes</button></div>
      </section>
    </div>`;
  const close = () => { document.querySelector("#modal-root").innerHTML = ""; };
  document.querySelector("#close-modal").addEventListener("click", close);
  document.querySelector("#cancel-modal").addEventListener("click", close);
  document.querySelector("#modal-backdrop").addEventListener("click", (event) => {
    if (event.target.id === "modal-backdrop") close();
  });
  document.querySelector("#save-request").addEventListener("click", (event) => {
    const updated = requests.find((item) => item.id === event.currentTarget.dataset.requestId);
    if (!updated) {
      showToast("That request could not be found.", true);
      close();
      return;
    }
    updated.status = document.querySelector("#edit-status").value;
    updated.assigned = document.querySelector("#edit-assignee").value.trim() || "Unassigned";
    if (!saveRequests()) return;
    close();
    render();
    showToast("Request updated.");
  });
  document.querySelector("#close-modal").focus();
}

function exportCSV() {
  function csvCell(value) {
    const text = String(value ?? "");
    const safeText = /^[\u0000-\u0020]*[=+\-@]/.test(text) ? `'${text}` : text;
    return `"${safeText.replace(/"/g, '""')}"`;
  }

  const columns = ["Reference", "Resident", "Contact", "Address", "Request", "Category", "Urgent", "Status", "Assigned to", "Received"];
  const rows = requests.map((request) => [
    request.id,
    request.name,
    request.contact,
    request.address,
    request.description,
    request.category,
    request.urgent ? "Yes" : "No",
    request.status,
    request.assigned,
    formatDateTime(request.createdAt),
  ]);
  const csv = [columns, ...rows].map((row) => row.map(csvCell).join(",")).join("\r\n");
  const blob = new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "bayanlink-service-requests.csv";
  link.click();
  URL.revokeObjectURL(link.href);
  showToast("Report exported as CSV.");
}

document.querySelector("#today-date").textContent = new Intl.DateTimeFormat("en-PH", {
  weekday: "short",
  month: "short",
  day: "numeric",
}).format(new Date());

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && document.querySelector("#modal-root .modal-backdrop")) {
    document.querySelector("#modal-root").innerHTML = "";
  }
});

render();
initializeSupabase();
initializeChatWidget();
