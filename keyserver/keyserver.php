<?php
// Configuration
define('DB_FILE', __DIR__ . '/keyserver.db');
define('USERNAME_MAX_LENGTH', 50);
define('PASSWORD_MIN_LENGTH', 8);
define('SELF_URL', basename($_SERVER['SCRIPT_NAME']));
define('SELF_PATH', rtrim(dirname($_SERVER['SCRIPT_NAME']), '/') . '/' . SELF_URL);
define('CSRF_SECRET_FILE', __DIR__ . '/.csrf_secret');

// Rate limiting
define('RL_LOGIN_MAX_ATTEMPTS', 5);        // max failed logins ...
define('RL_LOGIN_WINDOW', 900);            // ... per 15 minutes (per IP+username)
define('RL_REGISTER_MAX_ATTEMPTS', 3);     // max registrations ...
define('RL_REGISTER_WINDOW', 3600);        // ... per hour (per IP)
define('RL_CLEANUP_PROBABILITY', 5);       // 1-in-N requests triggers old-row cleanup

// Error Handling
ini_set('display_errors', 0);
error_reporting(E_ALL);

// Session-Setup
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.gc_maxlifetime', 3600);
ini_set('session.cookie_lifetime', 0);
if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
    ini_set('session.cookie_secure', 1);
}
ini_set('session.cookie_samesite', 'Lax');

// CSRF-Secret (persistent, no Cookie)
function get_csrf_secret(): string {
    if (!file_exists(CSRF_SECRET_FILE)) {
        file_put_contents(CSRF_SECRET_FILE, bin2hex(random_bytes(32)), LOCK_EX);
        @chmod(CSRF_SECRET_FILE, 0600);
    }
    return trim(file_get_contents(CSRF_SECRET_FILE));
}
function make_csrf_token(string $secret): string {
    $ts = time();
    $nonce = bin2hex(random_bytes(8));
    $data = $ts . '|' . $nonce;
    $sig = hash_hmac('sha256', $data, $secret);
    return $data . '|' . $sig;
}
function verify_csrf_token(?string $token, string $secret, int $max_age = 3600): bool {
    if (!$token) return false;
    $parts = explode('|', $token);
    if (count($parts) !== 3) return false;
    [$ts, $nonce, $sig] = $parts;
    if (!ctype_digit($ts)) return false;
    if (time() - (int)$ts > $max_age) return false;
    $expected = hash_hmac('sha256', $ts . '|' . $nonce, $secret);
    return hash_equals($expected, $sig);
}

$csrf_secret = get_csrf_secret();

// Start the session only if absolutely necessary
$needs_session = false;
if (isset($_COOKIE[session_name()])) $needs_session = true;
if ($_SERVER['REQUEST_METHOD'] === 'POST') $needs_session = true;
if (isset($_GET['action']) && $_GET['action'] === 'logout') $needs_session = true;

if ($needs_session && session_status() === PHP_SESSION_NONE) {
    session_start();
}
if (session_status() === PHP_SESSION_ACTIVE) {
    if (!isset($_SESSION['last_regen']) || time() - $_SESSION['last_regen'] > 900) {
        session_regenerate_id(true);
        $_SESSION['last_regen'] = time();
    }
}

$csrf_token = make_csrf_token($csrf_secret);

// DB Setup
try {
    $db = new PDO('sqlite:' . DB_FILE);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    // WAL improves concurrency for rate-limit writes
    $db->exec("PRAGMA journal_mode = WAL");
    $db->exec("PRAGMA busy_timeout = 5000");

    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        public_key TEXT DEFAULT NULL,
        key_updated_at DATETIME DEFAULT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    $db->exec("CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bucket TEXT NOT NULL,
        identifier TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_rate_limits_lookup
               ON rate_limits (bucket, identifier, created_at)");
} catch (PDOException $e) {
    error_log("DB Error: " . $e->getMessage());
    die("Database error. Please check server logs.");
}

// Helpers
function h(?string $s): string {
    return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8');
}
function is_logged_in(): bool {
    return session_status() === PHP_SESSION_ACTIVE && isset($_SESSION['user_id']);
}
function current_user(PDO $db): ?array {
    if (!is_logged_in()) return null;
    $stmt = $db->prepare("SELECT id, username, public_key FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    return $stmt->fetch() ?: null;
}
function get_user_by_username(PDO $db, string $u): ?array {
    $stmt = $db->prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE");
    $stmt->execute([$u]);
    return $stmt->fetch() ?: null;
}

// Rate limiting helpers
function client_ip(): string {
    // Default: direct connection (safe). If you run behind a trusted reverse
    // proxy, read X-Forwarded-For ONLY after validating the proxy — see README.
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function rl_key(string $bucket, string $identifier): string {
    // Hash the identifier so raw usernames/IPs aren't stored in plaintext
    return hash('sha256', $identifier);
}

function rl_count(PDO $db, string $bucket, string $identifier, int $window): int {
    $stmt = $db->prepare("SELECT COUNT(*) FROM rate_limits
                          WHERE bucket = ? AND identifier = ? AND created_at >= ?");
    $stmt->execute([$bucket, rl_key($bucket, $identifier), time() - $window]);
    return (int)$stmt->fetchColumn();
}

function rl_hit(PDO $db, string $bucket, string $identifier): void {
    $stmt = $db->prepare("INSERT INTO rate_limits (bucket, identifier, created_at) VALUES (?, ?, ?)");
    $stmt->execute([$bucket, rl_key($bucket, $identifier), time()]);
}

function rl_reset(PDO $db, string $bucket, string $identifier): void {
    $stmt = $db->prepare("DELETE FROM rate_limits WHERE bucket = ? AND identifier = ?");
    $stmt->execute([$bucket, rl_key($bucket, $identifier)]);
}

function rl_cleanup(PDO $db): void {
    // Keep the table small; a single DELETE per N requests is enough.
    $db->exec("DELETE FROM rate_limits WHERE created_at < " . (time() - 86400));
}

// NaClbox Key Validation
function validate_naclbox_key(string $key): bool {
    $pattern = '/^-----BEGIN NaClbox PUBLIC KEY-----\s*\n'
             . '([A-Za-z0-9+\/]{43}=)\s*\n'
             . '-----END NaClbox PUBLIC KEY-----$/';
    if (!preg_match($pattern, $key, $m)) return false;
    $decoded = base64_decode($m[1], true);
    return $decoded !== false && strlen($decoded) === 32;
}
function normalize_naclbox_key(string $key): string {
    return str_replace(["\r\n", "\r"], "\n", trim($key));
}

// Logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $p["path"], $p["domain"], $p["secure"], $p["httponly"]);
        }
        session_destroy();
    }
    header("Location: " . SELF_PATH . "?loggedout=1");
    exit;
}

$auth_error = null;
$action_error = null;

// POST Actions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && session_status() === PHP_SESSION_ACTIVE) {
    // Occasional cleanup of old rate-limit rows
    if (random_int(1, RL_CLEANUP_PROBABILITY) === 1) {
        rl_cleanup($db);
    }

    $action = $_POST['action'] ?? '';
    $submitted_csrf = $_POST['csrf_token'] ?? '';
    if (!verify_csrf_token($submitted_csrf, $csrf_secret)) {
        $auth_error = $action_error = "Invalid form submission. Please try again.";
        $action = '';
    }

    switch ($action) {
        case 'register':
            $username = trim($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';
            $confirm  = $_POST['password_confirm'] ?? '';

            // Rate limit: registration attempts per IP
            $rl_id = client_ip();
            if (rl_count($db, 'register', $rl_id, RL_REGISTER_WINDOW) >= RL_REGISTER_MAX_ATTEMPTS) {
                $auth_error = "Too many registration attempts. Please try again later.";
                break;
            }

            if ($username === '' || $password === '' || $confirm === '') {
                $auth_error = "All fields are required.";
            } elseif ($password !== $confirm) {
                $auth_error = "Passwords do not match.";
            } elseif (mb_strlen($password) < PASSWORD_MIN_LENGTH) {
                $auth_error = "Password must be at least " . PASSWORD_MIN_LENGTH . " characters.";
            } elseif (mb_strlen($username) > USERNAME_MAX_LENGTH) {
                $auth_error = "Username too long (max " . USERNAME_MAX_LENGTH . ").";
            } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
                $auth_error = "Username may only contain letters, numbers, underscore.";
            } elseif (get_user_by_username($db, $username)) {
                $auth_error = "Username already taken.";
            } else {
                // Count every valid-format attempt, so abuse is rate-limited
                rl_hit($db, 'register', $rl_id);
                try {
                    $stmt = $db->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
                    $stmt->execute([$username, password_hash($password, PASSWORD_DEFAULT)]);
                    session_regenerate_id(true);
                    $_SESSION['user_id'] = $db->lastInsertId();
                    $_SESSION['last_regen'] = time();
                    header("Location: " . SELF_PATH);
                    exit;
                } catch (PDOException $e) {
                    error_log("Register error: " . $e->getMessage());
                    $auth_error = "Registration failed.";
                }
            }
            break;

        case 'login':
            $username = trim($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';

            // Rate limit: failed logins per IP + username
            $rl_id = client_ip() . '|' . mb_strtolower($username);
            if (rl_count($db, 'login', $rl_id, RL_LOGIN_WINDOW) >= RL_LOGIN_MAX_ATTEMPTS) {
                $auth_error = "Too many failed login attempts. Please try again later.";
                break;
            }

            $user = get_user_by_username($db, $username);
            if ($user && password_verify($password, $user['password_hash'])) {
                // Successful login clears the counter for this IP+username
                rl_reset($db, 'login', $rl_id);
                session_regenerate_id(true);
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['last_regen'] = time();
                header("Location: " . SELF_PATH);
                exit;
            }
            // Count only failures
            rl_hit($db, 'login', $rl_id);
            $auth_error = "Invalid username or password.";
            break;

        case 'save_key':
            $user = current_user($db);
            if (!$user) { $action_error = "Not logged in."; break; }
            $raw_key = normalize_naclbox_key($_POST['public_key'] ?? '');
            if ($raw_key === '') {
                $action_error = "Public key cannot be empty.";
            } elseif (!validate_naclbox_key($raw_key)) {
                $action_error = "Invalid NaClbox public key format.";
            } else {
                $stmt = $db->prepare("UPDATE users SET public_key = ?, key_updated_at = CURRENT_TIMESTAMP WHERE id = ?");
                $stmt->execute([$raw_key, $user['id']]);
                header("Location: " . SELF_PATH . "?saved=1");
                exit;
            }
            break;

        case 'delete_key':
            $user = current_user($db);
            if (!$user) { $action_error = "Not logged in."; break; }
            $stmt = $db->prepare("UPDATE users SET public_key = NULL, key_updated_at = NULL WHERE id = ?");
            $stmt->execute([$user['id']]);
            header("Location: " . SELF_PATH . "?deleted=1");
            exit;
    }
}

// Detail View
$view_user = null;
if (isset($_GET['user'])) {
    $view_user = get_user_by_username($db, trim($_GET['user']));
}

// Listing
$stmt = $db->query("SELECT username, public_key, key_updated_at FROM users WHERE public_key IS NOT NULL ORDER BY username COLLATE NOCASE ASC");
$public_users = $stmt->fetchAll();

$current_user = current_user($db);

// Form Control
$show_login_form = false;
$show_register_form = false;
if (isset($_GET['do']) && $_GET['do'] === 'login') {
    $show_login_form = true;
}
if (isset($_GET['do']) && $_GET['do'] === 'register') {
    $show_register_form = true;
}
if ($auth_error && ($_POST['action'] ?? '') === 'register') {
    $show_register_form = true;
}
if ($auth_error && ($_POST['action'] ?? '') === 'login') {
    $show_login_form = true;
}
?>
<!DOCTYPE html>
<html lang="en">
<link rel="icon" type="image/x-icon" href="/nbox.ico">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NaClbox Key Server</title>
<style>
:root {
  --bg: #1a1a1a; --text: #e0e0e0; --border: #444; --post-bg: #282828;
  --header-bg: #333; --link: #ffa500; --link-hover: #c0caf5;
  --accent-red: #ffa500; --accent-green: #ffa500; --accent-blue: #ffa500;
  --input-bg: #404040; --input-border: #555; --button-bg: #555; --button-hover: #666;
  --error-bg: #5c2424; --error-border: #a04040; --error-text: #f7768e;
  --success-bg: #2a502a; --success-border: #4a804a; --success-text: #9ece6a;
}
body { background: var(--bg); color: var(--text); font-family: sans-serif; font-size: 10pt; margin: 0; padding: 0; }
.container { max-width: 800px; margin: 15px auto; padding: 0 15px; }
a { color: var(--link); text-decoration: none; }
a:hover { color: var(--link-hover); text-decoration: underline; }
header { background: var(--header-bg); border: 1px solid var(--border); margin-bottom: 15px; padding: 10px; position: relative; text-align: center; }
header h1 { color: var(--accent-red); margin: 5px 0; font-size: 1.6em; }
.auth-links { position: absolute; top: 5px; right: 10px; font-size: 0.9em; }
.auth-links a, .auth-links span { margin-left: 10px; }
.auth-links span { color: var(--link); }
.form-box { background: var(--post-bg); border: 1px solid var(--border); padding: 15px; margin-bottom: 20px; }
.form-box h2 { margin: 0 0 10px; color: var(--accent-blue); font-size: 1.2em; }
.form-box table { border-collapse: collapse; width: 100%; }
.form-box th { width: 130px; text-align: right; padding: 6px 10px 6px 0; }
.form-box td { padding: 6px 0; }
.form-box input[type=text], .form-box input[type=password], .form-box textarea {
  width: calc(100% - 16px); padding: 7px; border: 1px solid var(--input-border);
  background: var(--input-bg); color: var(--text); box-sizing: border-box; font-family: monospace;
}
.form-box textarea { min-height: 100px; resize: vertical; }
.form-box input[type=submit], .form-box button {
  padding: 6px 15px; font-weight: bold; cursor: pointer; background: var(--button-bg);
  color: var(--text); border: 1px solid var(--input-border); border-radius: 3px;
}
.form-box input[type=submit]:hover, .form-box button:hover { background: var(--button-hover); }
.error, .success { font-weight: bold; border: 1px solid; padding: 10px; margin-bottom: 15px; border-radius: 4px; text-align: center; }
.error { color: var(--error-text); background: var(--error-bg); border-color: var(--error-border); }
.success { color: var(--success-text); background: var(--success-bg); border-color: var(--success-border); }
.key-list { list-style: none; padding: 0; margin: 0; }
.key-list li {
  background: var(--post-bg); border: 1px solid var(--border); border-radius: 4px;
  padding: 10px 15px; margin-bottom: 8px; display: flex; justify-content: space-between;
  align-items: center; flex-wrap: wrap; gap: 5px;
}
.key-list .name { font-weight: bold; color: var(--accent-green); font-size: 1.05em; flex: 1; }
.key-list .date { font-size: 0.85em; color: #aaa; }
.key-list a.view { color: var(--link); font-size: 0.9em; }
.key-list a.view:hover { color: var(--link-hover); text-decoration: underline; }
pre.key {
  background: #222; color: #ccc; border: 1px solid var(--border); padding: 12px;
  overflow-x: auto; font-size: 0.95em; border-radius: 4px; user-select: all;
  white-space: pre; word-break: normal;
}
.info-line { color: #aaa; font-size: 0.9em; margin-bottom: 10px; }
.button-row { margin-top: 10px; display: flex; gap: 10px; flex-wrap: wrap; }
.button-row form { display: inline; }
.delete-btn { background: var(--accent-red) !important; color: #fff !important; border-color: var(--accent-red) !important; }
.delete-btn:hover { background: #d05a70 !important; }
.privacy-note { color: #888; font-size: 0.85em; text-align: center; margin-top: 30px; padding-top: 15px; border-top: 1px solid var(--border); }
@media (max-width: 600px) {
  .form-box th { text-align: left; display: block; padding: 4px 0 2px; }
  .form-box td { display: block; padding: 0 0 6px; }
  .auth-links { position: static; text-align: center; margin-top: 5px; }
}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>NaClbox Public Key Server</h1>
    <div class="auth-links">
      <?php if ($current_user): ?>
        <span>Hi, <strong><?= h($current_user['username']) ?></strong></span>
        <a href="<?= h(SELF_PATH) ?>?action=logout">Logout</a>
      <?php else: ?>
        <a href="<?= h(SELF_PATH) ?>?do=login">Login</a>
        <a href="<?= h(SELF_PATH) ?>?do=register">Register</a>
      <?php endif; ?>
    </div>
  </header>

  <?php if (isset($_GET['loggedout'])): ?><p class="success">Logged out. Session cookie removed.</p><?php endif; ?>
  <?php if (isset($_GET['saved'])): ?><p class="success">Public key saved.</p><?php endif; ?>
  <?php if (isset($_GET['deleted'])): ?><p class="success">Public key deleted.</p><?php endif; ?>
  <?php if ($auth_error): ?><p class="error"><?= h($auth_error) ?></p><?php endif; ?>
  <?php if ($action_error): ?><p class="error"><?= h($action_error) ?></p><?php endif; ?>

  <?php // Detail View ?>
  <?php if ($view_user): ?>
    <div class="form-box">
      <h2>Public Key for <?= h($view_user['username']) ?></h2>
      <?php if ($view_user['public_key']): ?>
        <p class="info-line">Last updated: <?= h($view_user['key_updated_at'] ?? 'unknown') ?></p>
        <pre class="key"><?= h($view_user['public_key']) ?></pre>
      <?php else: ?>
        <p class="error">This user has no public key.</p>
      <?php endif; ?>
      <p><a href="<?= h(SELF_PATH) ?>">← Back to main page</a></p>
    </div>

  <?php // My Key Management ?>
  <?php elseif ($current_user): ?>
    <div class="form-box">
      <h2>My Public Key</h2>
      <?php if ($current_user['public_key']): ?>
        <p class="info-line">Currently stored:</p>
        <pre class="key"><?= h($current_user['public_key']) ?></pre>
        <div class="button-row">
          <form method="post" action="<?= h(SELF_PATH) ?>" onsubmit="return confirm('Delete your public key?');">
            <input type="hidden" name="action" value="delete_key">
            <input type="hidden" name="csrf_token" value="<?= h($csrf_token) ?>">
            <button type="submit" class="delete-btn">Delete Key</button>
          </form>
        </div>
        <hr style="border-color: var(--border); margin: 15px 0;">
      <?php endif; ?>
      <h2><?= $current_user['public_key'] ? 'Replace Key' : 'Add Key' ?></h2>
      <p class="info-line">Paste your NaClbox public key below.</p>
      <form method="post" action="<?= h(SELF_PATH) ?>">
        <input type="hidden" name="action" value="save_key">
        <input type="hidden" name="csrf_token" value="<?= h($csrf_token) ?>">
        <textarea name="public_key" required placeholder="-----BEGIN NaClbox PUBLIC KEY-----
...
-----END NaClbox PUBLIC KEY-----"><?= h($current_user['public_key'] ?? '') ?></textarea>
        <div class="button-row">
          <input type="submit" value="Save Key">
        </div>
      </form>
      <p class="info-line" style="margin-top: 10px;">
        Your key is publicly viewable at
        <a href="<?= h(SELF_PATH) ?>?user=<?= urlencode($current_user['username']) ?>"><?= h(SELF_PATH) ?>?user=<?= h($current_user['username']) ?></a>
      </p>
    </div>

  <?php // Guest: login/registration form only when ?do=... ?>
  <?php else: ?>
    <?php if ($show_login_form): ?>
      <div class="form-box" id="login">
        <h2>Login</h2>
        <form method="post" action="<?= h(SELF_PATH) ?>">
          <input type="hidden" name="action" value="login">
          <input type="hidden" name="csrf_token" value="<?= h($csrf_token) ?>">
          <table>
            <tr><th><label for="login_user">Username</label></th><td><input type="text" name="username" id="login_user" required></td></tr>
            <tr><th><label for="login_pass">Password</label></th><td><input type="password" name="password" id="login_pass" required></td></tr>
            <tr><th></th><td><input type="submit" value="Login"></td></tr>
          </table>
        </form>
        <p class="info-line" style="margin-top:10px;">No account? <a href="<?= h(SELF_PATH) ?>?do=register">Register here</a>.</p>
      </div>
    <?php endif; ?>

    <?php if ($show_register_form): ?>
      <div class="form-box" id="register">
        <h2>Register</h2>
        <form method="post" action="<?= h(SELF_PATH) ?>">
          <input type="hidden" name="action" value="register">
          <input type="hidden" name="csrf_token" value="<?= h($csrf_token) ?>">
          <table>
            <tr><th><label for="reg_user">Username</label></th><td><input type="text" name="username" id="reg_user" required maxlength="<?= USERNAME_MAX_LENGTH ?>" pattern="[a-zA-Z0-9_]+"> <small>(letters, numbers, _)</small></td></tr>
            <tr><th><label for="reg_pass">Password</label></th><td><input type="password" name="password" id="reg_pass" required minlength="<?= PASSWORD_MIN_LENGTH ?>"> <small>(min <?= PASSWORD_MIN_LENGTH ?>)</small></td></tr>
            <tr><th><label for="reg_confirm">Confirm</label></th><td><input type="password" name="password_confirm" id="reg_confirm" required></td></tr>
            <tr><th></th><td><input type="submit" value="Register"></td></tr>
          </table>
        </form>
        <p class="info-line" style="margin-top:10px;">Already have an account? <a href="<?= h(SELF_PATH) ?>?do=login">Login here</a>.</p>
      </div>
    <?php endif; ?>

    <?php if ($show_login_form || $show_register_form): ?>
      <p class="info-line" style="text-align:center;">
        <a href="<?= h(SELF_PATH) ?>">← Back to public key list</a>
      </p>
    <?php endif; ?>
  <?php endif; ?>

  <?php // Public Listing (only for guests on the start page, not on form/detail/logged-in views) ?>
  <?php if (!$view_user && !$show_login_form && !$show_register_form && !$current_user): ?>
    <div class="form-box">
      <h2>Registered Public Keys (<?= count($public_users) ?>)</h2>
      <?php if (empty($public_users)): ?>
        <p class="info-line">No public keys yet. Be the first!</p>
      <?php else: ?>
        <ul class="key-list">
          <?php foreach ($public_users as $u): ?>
            <li>
              <span class="name"><?= h($u['username']) ?></span>
              <span class="date"><?= h($u['key_updated_at'] ?? '') ?></span>
              <a class="view" href="<?= h(SELF_PATH) ?>?user=<?= urlencode($u['username']) ?>">View Key →</a>
            </li>
          <?php endforeach; ?>
        </ul>
      <?php endif; ?>
    </div>
  <?php endif; ?>

</div>
</body>
</html>
