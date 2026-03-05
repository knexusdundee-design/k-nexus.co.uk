<?php
// ══════════════════════════════════════════════════════════════════
// K-NEXUS ADMIN BACKEND — admin_backend.php
// Real PHP auth. Director + staff roles. Session-based.
//
// SETUP:
//   1. Upload to your server root as /admin/admin_backend.php
//   2. Create /admin/.htaccess to block direct access to this file
//   3. Set credentials in config section below OR move to .env
//   4. Call from your site JS via fetch('/admin/admin_backend.php', ...)
// ══════════════════════════════════════════════════════════════════

// ── CONFIG ─────────────────────────────────────────────────────────
define('ADMIN_USERS', [
    'andrew' => [
        'role'    => 'director',
        'hash'    => '', // Set with: echo password_hash('YourPassword', PASSWORD_BCRYPT);
        'display' => 'Andrew Lafferty',
    ],
    'admin' => [
        'role'    => 'staff',
        'hash'    => '', // Set with: echo password_hash('StaffPassword', PASSWORD_BCRYPT);
        'display' => 'K-NEXUS Admin',
    ],
]);

define('SESSION_LIFETIME', 3600);      // 1 hour
define('ALLOWED_ORIGINS', [
    'https://knexus.co.uk',
    'https://www.knexus.co.uk',
    'http://localhost',                 // dev
]);
define('LOG_FILE', __DIR__ . '/admin_log.txt');
define('CONTENT_FILE', __DIR__ . '/../data/content.json');
define('SITE_STATUS_FILE', __DIR__ . '/../data/site_status.json');

// ── BOOTSTRAP ──────────────────────────────────────────────────────
session_start([
    'cookie_httponly' => true,
    'cookie_secure'   => isset($_SERVER['HTTPS']),
    'cookie_samesite' => 'Strict',
    'gc_maxlifetime'  => SESSION_LIFETIME,
]);

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

// CORS
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, ALLOWED_ORIGINS)) {
    header("Access-Control-Allow-Origin: $origin");
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
}
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

// ── HELPERS ────────────────────────────────────────────────────────
function respond(bool $ok, $data = [], int $code = 200): void {
    http_response_code($code);
    echo json_encode(['ok' => $ok, ...(array)$data]);
    exit;
}

function log_event(string $event, string $user = 'anon'): void {
    $ts   = date('Y-m-d H:i:s');
    $ip   = $_SERVER['REMOTE_ADDR'] ?? '?';
    $line = "[$ts] [$ip] [$user] $event" . PHP_EOL;
    file_put_contents(LOG_FILE, $line, FILE_APPEND | LOCK_EX);
}

function require_auth(string $min_role = 'staff'): array {
    if (empty($_SESSION['user']) || empty($_SESSION['expires'])) {
        respond(false, ['error' => 'Not authenticated'], 401);
    }
    if (time() > $_SESSION['expires']) {
        session_destroy();
        respond(false, ['error' => 'Session expired'], 401);
    }
    $user = ADMIN_USERS[$_SESSION['user']] ?? null;
    if (!$user) { respond(false, ['error' => 'Invalid session'], 401); }
    if ($min_role === 'director' && $user['role'] !== 'director') {
        respond(false, ['error' => 'Director access required'], 403);
    }
    // Refresh expiry on activity
    $_SESSION['expires'] = time() + SESSION_LIFETIME;
    return $user;
}

function read_json(string $file, array $default = []): array {
    if (!file_exists($file)) return $default;
    $data = json_decode(file_get_contents($file), true);
    return is_array($data) ? $data : $default;
}

function write_json(string $file, array $data): void {
    $dir = dirname($file);
    if (!is_dir($dir)) mkdir($dir, 0755, true);
    file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
}

// ── CSRF TOKEN ─────────────────────────────────────────────────────
function generate_csrf(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}
function verify_csrf(string $token): bool {
    return hash_equals($_SESSION['csrf_token'] ?? '', $token);
}

// ── RATE LIMITER ────────────────────────────────────────────────────
define('MAX_ATTEMPTS', 5);
define('LOCKOUT_SECONDS', 300);
define('ATTEMPTS_FILE', __DIR__ . '/login_attempts.json');

function check_rate_limit(string $ip): void {
    $data = file_exists(ATTEMPTS_FILE)
        ? (json_decode(file_get_contents(ATTEMPTS_FILE), true) ?? []) : [];
    $now = time();
    $r = $data[$ip] ?? ['count'=>0,'first'=>$now,'locked_until'=>0];
    if ($now < $r['locked_until']) {
        $wait = $r['locked_until'] - $now;
        respond(false, ['error'=>"Too many attempts. Try again in {$wait}s."], 429);
    }
}
function record_failed_attempt(string $ip): void {
    $data = file_exists(ATTEMPTS_FILE)
        ? (json_decode(file_get_contents(ATTEMPTS_FILE), true) ?? []) : [];
    $now = time();
    $r = $data[$ip] ?? ['count'=>0,'first'=>$now,'locked_until'=>0];
    if ($now - $r['first'] > LOCKOUT_SECONDS) $r = ['count'=>0,'first'=>$now,'locked_until'=>0];
    $r['count']++;
    if ($r['count'] >= MAX_ATTEMPTS) $r['locked_until'] = $now + LOCKOUT_SECONDS;
    $data[$ip] = $r;
    file_put_contents(ATTEMPTS_FILE, json_encode($data), LOCK_EX);
}
function clear_attempts(string $ip): void {
    if (!file_exists(ATTEMPTS_FILE)) return;
    $d = json_decode(file_get_contents(ATTEMPTS_FILE), true) ?? [];
    unset($d[$ip]);
    file_put_contents(ATTEMPTS_FILE, json_encode($d), LOCK_EX);
}

// ── ROUTER ─────────────────────────────────────────────────────────
$body   = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $body['action'] ?? $_GET['action'] ?? '';
$client_ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

switch ($action) {

    // ── LOGIN ───────────────────────────────────────────────────────

    // ── GET CSRF TOKEN ──────────────────────────────────────────────
    case 'csrf':
        respond(true, ['token' => generate_csrf()]);

    case 'login':
        check_rate_limit($client_ip);
        $username = strtolower(trim($body['username'] ?? ''));
        $password = $body['password'] ?? '';
        $csrf     = $body['csrf_token'] ?? '';
        $user     = ADMIN_USERS[$username] ?? null;

        if (!$user || !password_verify($password, $user['hash'])) {
            log_event("FAILED LOGIN: $username from $client_ip");
            record_failed_attempt($client_ip);
            sleep(2);
            respond(false, ['error' => 'Invalid credentials'], 401);
        }
        // Success — clear rate limit
        clear_attempts($client_ip);

        // Regenerate session ID on login
        session_regenerate_id(true);
        $_SESSION['user']    = $username;
        $_SESSION['role']    = $user['role'];
        $_SESSION['expires'] = time() + SESSION_LIFETIME;

        log_event("LOGIN OK: $username ({$user['role']})");
        respond(true, [
            'role'    => $user['role'],
            'display' => $user['display'],
            'expires' => $_SESSION['expires'],
        ]);

    // ── LOGOUT ──────────────────────────────────────────────────────
    case 'logout':
        $u = $_SESSION['user'] ?? 'anon';
        session_destroy();
        log_event("LOGOUT: $u");
        respond(true, ['message' => 'Logged out']);

    // ── CHECK SESSION ───────────────────────────────────────────────
    case 'check':
        if (empty($_SESSION['user']) || time() > ($_SESSION['expires'] ?? 0)) {
            respond(false, ['authenticated' => false]);
        }
        $user = ADMIN_USERS[$_SESSION['user']];
        respond(true, [
            'authenticated' => true,
            'role'          => $user['role'],
            'display'       => $user['display'],
            'expires'       => $_SESSION['expires'],
        ]);

    // ── SITE STATUS (deploy / undeploy) ─────────────────────────────
    case 'site_status':
        require_auth('director');
        $status = read_json(SITE_STATUS_FILE, ['online' => true, 'updated_at' => null]);
        respond(true, $status);

    case 'site_toggle':
        $user = require_auth('director');
        $status = read_json(SITE_STATUS_FILE, ['online' => true]);
        $status['online']     = !$status['online'];
        $status['updated_at'] = date('c');
        $status['updated_by'] = $_SESSION['user'];
        write_json(SITE_STATUS_FILE, $status);
        log_event('SITE TOGGLE → ' . ($status['online'] ? 'ONLINE' : 'OFFLINE'), $_SESSION['user']);
        respond(true, $status);

    case 'site_set':
        require_auth('director');
        $online = (bool)($body['online'] ?? true);
        $status = [
            'online'     => $online,
            'updated_at' => date('c'),
            'updated_by' => $_SESSION['user'],
            'reason'     => $body['reason'] ?? '',
        ];
        write_json(SITE_STATUS_FILE, $status);
        log_event('SITE SET → ' . ($online ? 'ONLINE' : 'OFFLINE'), $_SESSION['user']);
        respond(true, $status);

    // ── CONTENT: POSTS (Nexus 4 feed) ───────────────────────────────
    case 'posts_list':
        require_auth();
        $content  = read_json(CONTENT_FILE, ['posts' => []]);
        $posts    = $content['posts'] ?? [];
        $cutoff   = strtotime('-60 days');
        // Return all for admin; flag stale ones
        foreach ($posts as &$p) {
            $p['stale'] = strtotime($p['created_at'] ?? '0') < $cutoff;
        }
        usort($posts, fn($a, $b) => strcmp($b['created_at'] ?? '', $a['created_at'] ?? ''));
        respond(true, ['posts' => $posts]);

    case 'post_add':
        require_auth();
        $content = read_json(CONTENT_FILE, ['posts' => []]);
        $post = [
            'id'         => uniqid('post_', true),
            'title'      => strip_tags($body['title'] ?? ''),
            'body'       => strip_tags($body['body'] ?? '', '<b><i><a><ul><ol><li><br>'),
            'author'     => $_SESSION['user'],
            'branch'     => $body['branch'] ?? 'K-NEXUS',
            'created_at' => date('c'),
            'pinned'     => false,
        ];
        if (!$post['title'] || !$post['body']) {
            respond(false, ['error' => 'Title and body required'], 400);
        }
        array_unshift($content['posts'], $post);
        write_json(CONTENT_FILE, $content);
        log_event("POST ADDED: {$post['title']}", $_SESSION['user']);
        respond(true, ['post' => $post]);

    case 'post_delete':
        require_auth('director');
        $id      = $body['id'] ?? '';
        $content = read_json(CONTENT_FILE, ['posts' => []]);
        $before  = count($content['posts']);
        $content['posts'] = array_values(array_filter($content['posts'], fn($p) => $p['id'] !== $id));
        write_json(CONTENT_FILE, $content);
        $deleted = $before - count($content['posts']);
        log_event("POST DELETED: $id", $_SESSION['user']);
        respond(true, ['deleted' => $deleted]);

    case 'post_archive_stale':
        require_auth('director');
        $content = read_json(CONTENT_FILE, ['posts' => [], 'archive' => []]);
        $cutoff  = strtotime('-60 days');
        $keep    = []; $archived = [];
        foreach ($content['posts'] as $p) {
            if (strtotime($p['created_at'] ?? '0') < $cutoff) {
                $archived[] = $p;
            } else {
                $keep[] = $p;
            }
        }
        $content['posts']   = $keep;
        $content['archive'] = array_merge($content['archive'] ?? [], $archived);
        write_json(CONTENT_FILE, $content);
        log_event("ARCHIVED " . count($archived) . " STALE POSTS", $_SESSION['user']);
        respond(true, ['archived' => count($archived), 'remaining' => count($keep)]);

    // ── MEMBERS ─────────────────────────────────────────────────────
    case 'members_list':
        require_auth();
        $members_file = __DIR__ . '/../data/members.json';
        $members = read_json($members_file, []);
        respond(true, ['members' => $members, 'count' => count($members)]);

    case 'member_add':
        require_auth();
        $mf = __DIR__ . '/../data/members.json';
        $members = read_json($mf, []);
        $m = [
            'id'         => uniqid('mem_', true),
            'name'       => strip_tags($body['name'] ?? ''),
            'email'      => filter_var($body['email'] ?? '', FILTER_SANITIZE_EMAIL),
            'rfid'       => preg_replace('/[^A-Za-z0-9]/', '', $body['rfid'] ?? ''),
            'joined'     => date('c'),
            'status'     => 'active',
            'added_by'   => $_SESSION['user'],
        ];
        if (!$m['name']) respond(false, ['error' => 'Name required'], 400);
        $members[] = $m;
        write_json($mf, $members);
        log_event("MEMBER ADDED: {$m['name']}", $_SESSION['user']);
        respond(true, ['member' => $m]);

    // ── ADMIN LOG ───────────────────────────────────────────────────
    case 'get_log':
        require_auth('director');
        $lines = file_exists(LOG_FILE) ? file(LOG_FILE) : [];
        $lines = array_slice(array_reverse($lines), 0, 200);
        respond(true, ['log' => array_values($lines)]);

    // ── CHANGE PASSWORD ─────────────────────────────────────────────
    case 'gen_hash':
        // Director-only utility to generate a new password hash
        // Usage: POST {"action":"gen_hash","password":"newpassword"}
        // Returns hash to paste into ADMIN_USERS above
        require_auth('director');
        $pw = $body['password'] ?? '';
        if (strlen($pw) < 8) respond(false, ['error' => 'Min 8 characters'], 400);
        $hash = password_hash($pw, PASSWORD_BCRYPT, ['cost' => 12]);
        respond(true, ['hash' => $hash, 'note' => 'Paste this into ADMIN_USERS hash field and remove this endpoint in production']);

    default:
        respond(false, ['error' => "Unknown action: $action"], 400);
}
