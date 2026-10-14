<?php
// Tests for configs/rules/achilles-php.yaml (opengrep --test). Never run.
// "ruleid: X" says the next line must be reported by rule X; "ok: X" says it must not.

function users($conn, $pdo)
{
    $name = $_GET['name'];
    // ruleid: achilles.php.sql-injection
    mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $name . "'");
    // ruleid: achilles.php.sql-injection
    $pdo->query("SELECT * FROM users WHERE id = {$_POST['id']}");
    // ok: achilles.php.sql-injection
    $stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
    // ok: achilles.php.sql-injection
    $stmt->execute([$name]);
    // ok: achilles.php.sql-injection
    mysqli_query($conn, "SELECT * FROM users WHERE id = " . intval($_GET['id']));
    // ok: achilles.php.sql-injection
    mysqli_query($conn, "SELECT count(*) FROM users");
}

function laravel($request)
{
    // ruleid: achilles.php.sql-injection
    DB::select("SELECT * FROM orders WHERE status = '" . $request->input('status') . "'");
    // ruleid: achilles.php.sql-injection
    User::query()->orderByRaw($request->query('sort'));
    // ok: achilles.php.sql-injection
    User::query()->where('status', $request->input('status'))->get();
}

function commands()
{
    $host = $_GET['host'];
    // ruleid: achilles.php.command-injection
    system("ping -c 1 " . $host);
    // ruleid: achilles.php.command-injection
    $out = shell_exec("nslookup $host");
    // ruleid: achilles.php.command-injection
    $out = `dig {$_POST['domain']}`;
    // ok: achilles.php.command-injection
    system("ping -c 1 " . escapeshellarg($host));
    // ok: achilles.php.command-injection
    system("uptime");
    // ok: achilles.php.command-injection
    proc_open(['ping', '-c', '1', $host], $spec, $pipes);
}

function code()
{
    // ruleid: achilles.php.code-injection
    eval($_POST['code']);
    $fn = $_GET['callback'];
    // ruleid: achilles.php.code-injection
    call_user_func($fn, 1);
    // ruleid: achilles.php.code-injection
    $fn();
    // ok: achilles.php.code-injection
    eval('return 1;');
    // ok: achilles.php.code-injection
    call_user_func('strtoupper', $_GET['x']);
}

function pages()
{
    $page = $_GET['page'];
    // ruleid: achilles.php.file-inclusion
    include $page . '.php';
    // ruleid: achilles.php.file-inclusion
    require_once($_REQUEST['module']);
    // ok: achilles.php.file-inclusion
    include 'pages/' . basename($page) . '.php';
    // ok: achilles.php.file-inclusion
    require_once __DIR__ . '/config.php';
}

function files()
{
    // ruleid: achilles.php.path-traversal
    readfile('/srv/uploads/' . $_GET['file']);
    // ruleid: achilles.php.path-traversal
    $data = file_get_contents($_POST['path']);
    // ruleid: achilles.php.path-traversal
    unlink($_REQUEST['f']);
    // ok: achilles.php.path-traversal
    readfile('/srv/uploads/' . basename($_GET['file']));
    // ok: achilles.php.path-traversal
    $cfg = file_get_contents(__DIR__ . '/config.json');
}

function fetch($client)
{
    // ruleid: achilles.php.ssrf
    $ch = curl_init($_GET['url']);
    $ch2 = curl_init();
    // ruleid: achilles.php.ssrf
    curl_setopt($ch2, CURLOPT_URL, $_POST['webhook']);
    // ruleid: achilles.php.ssrf
    $client->request('GET', $_GET['feed']);
    // ok: achilles.php.ssrf
    $ch3 = curl_init('https://api.example.com/search?q=' . urlencode($_GET['q']));
}

function page()
{
    // ruleid: achilles.php.xss
    echo "Hello, " . $_GET['name'];
    // ruleid: achilles.php.xss
    print($_POST['comment']);
    // ruleid: achilles.php.xss
    echo $_SERVER['PHP_SELF'];
    // ok: achilles.php.xss
    echo "Hello, " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
    // ok: achilles.php.xss
    echo "Static text";
}

function back()
{
    // ruleid: achilles.php.open-redirect
    header("Location: " . $_GET['next']);
    // ok: achilles.php.open-redirect
    header("Location: /dashboard");
    // ok: achilles.php.open-redirect
    header("Content-Type: application/json");
}

function restore()
{
    // ruleid: achilles.php.unsafe-deserialization
    $state = unserialize($_COOKIE['state']);
    // ruleid: achilles.php.unsafe-deserialization
    $obj = unserialize(base64_decode($_POST['data']));
    // ok: achilles.php.unsafe-deserialization
    $arr = unserialize($_COOKIE['state'], ['allowed_classes' => false]);
    // ok: achilles.php.unsafe-deserialization
    $arr = json_decode($_COOKIE['state'], true);
}

function vars()
{
    $is_admin = false;
    // ruleid: achilles.php.variable-overwrite
    extract($_POST);
    // ruleid: achilles.php.variable-overwrite
    parse_str($_SERVER['QUERY_STRING']);
    // ok: achilles.php.variable-overwrite
    parse_str($_SERVER['QUERY_STRING'], $params);
    // ok: achilles.php.variable-overwrite
    extract($defaults);
}

function tls($ch)
{
    // ruleid: achilles.php.tls-verification-disabled
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    // ruleid: achilles.php.tls-verification-disabled
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    // ruleid: achilles.php.tls-verification-disabled
    $ctx = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);
    // ok: achilles.php.tls-verification-disabled
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
}

function passwords($password, $file)
{
    // ruleid: achilles.php.weak-password-hash
    $h = md5($password);
    // ruleid: achilles.php.weak-password-hash
    $h = hash('sha256', $_POST['passwd']);
    // ok: achilles.php.weak-password-hash
    $h = password_hash($password, PASSWORD_DEFAULT);
    // ok: achilles.php.weak-password-hash
    $etag = md5($file);
}
