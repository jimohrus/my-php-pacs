<?php
// install_pacs.php - Enhanced for reusable deployment with choosable directory
header('Content-Type: text/html; charset=UTF-8');

// Debug logging
$homeDir = '/home1/' . get_current_user() . '/';
$debugLog = $homeDir . 'install_log.txt';
function debugLog($message) {
    global $debugLog;
    file_put_contents($debugLog, date('Y-m-d H:i:s') . ": $message\n", FILE_APPEND);
}
debugLog("Starting install_pacs.php");

// Error reporting
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Check PHP extensions
$required_extensions = ['mysqli', 'zip', 'fileinfo', 'gd'];
$missing_extensions = array_filter($required_extensions, fn($ext) => !extension_loaded($ext));
if (!empty($missing_extensions)) {
    debugLog("Missing PHP extensions: " . implode(', ', $missing_extensions));
    die("Error: Missing PHP extensions: " . implode(', ', $missing_extensions) . ". Enable them in your hosting control panel > PHP Settings.");
}

// Output buffer for colored logs
ob_start();
$logs = [];

// Log messages
function logMessage($message, $type = 'success') {
    global $logs;
    $message = preg_replace('/(https?:\/\/[^\s]+)/', '<a href="$1" target="_blank" style="color: #007bff; text-decoration: underline;">$1</a>', $message);
    $logs[] = ['message' => $message, 'type' => $type];
    debugLog("[$type] $message");
}

// Write files (force overwrite)
function writeFile($path, $content) {
    global $logs;
    if (file_put_contents($path, $content) === false) {
        logMessage("Failed to write $path", 'error');
        return false;
    }
    chmod($path, 0644);
    logMessage("Created/Updated $path", 'success');
    return true;
}

// Handle form submission
$hospitalName = 'PACS App'; // Default
$domain = '';
$dbHost = 'localhost';
$dbName = '';
$dbUser = '';
$dbPass = '';
$installDir = 'PACS'; // Default
$faviconExt = 'png'; // Default
$logoExt = 'png'; // Default
$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Hospital name
    if (!empty($_POST['hospital_name'])) {
        $hospitalName = filter_var($_POST['hospital_name'], FILTER_SANITIZE_STRING);
        if (strlen($hospitalName) > 100) {
            $errors[] = "Hospital name must be 100 characters or less.";
        }
    } else {
        $errors[] = "Hospital name is required.";
    }

    // Domain
    if (!empty($_POST['domain'])) {
        $domain = filter_var($_POST['domain'], FILTER_SANITIZE_URL);
        $domain = preg_replace('#^https?://#', '', rtrim($domain, '/'));
        if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9-\.]*\.[a-zA-Z]{2,}$/', $domain)) {
            $errors[] = "Invalid domain format. Example: pacs.example.com";
        }
    } else {
        $errors[] = "Domain is required.";
    }

    // Install directory
    if (!empty($_POST['install_dir'])) {
        $installDir = filter_var($_POST['install_dir'], FILTER_SANITIZE_STRING);
        $installDir = trim($installDir, '/');
        if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9-_\/]*$/', $installDir)) {
            $errors[] = "Invalid installation directory. Use letters, numbers, hyphens, underscores, or slashes (e.g., public_html/pacs).";
        } else {
            $basePath = $homeDir . $installDir . '/';
            if (!file_exists($basePath) && !mkdir($basePath, 0755, true)) {
                $errors[] = "Failed to create installation directory: $basePath. Ensure parent directory is writable.";
            } elseif (!is_writable($basePath)) {
                $errors[] = "Installation directory $basePath is not writable. Check permissions.";
            }
        }
    } else {
        $errors[] = "Installation directory is required.";
    }

    // Database credentials
    $dbHost = filter_var($_POST['db_host'] ?? 'localhost', FILTER_SANITIZE_STRING);
    if (empty($_POST['db_name'])) {
        $errors[] = "Database name is required.";
    } else {
        $dbName = filter_var($_POST['db_name'], FILTER_SANITIZE_STRING);
    }
    if (empty($_POST['db_user'])) {
        $errors[] = "Database username is required.";
    } else {
        $dbUser = filter_var($_POST['db_user'], FILTER_SANITIZE_STRING);
    }
    if (empty($_POST['db_pass'])) {
        $errors[] = "Database password is required.";
    } else {
        $dbPass = $_POST['db_pass']; // Passwords should not be sanitized
    }

    // Favicon
    if (isset($_FILES['favicon']) && $_FILES['favicon']['error'] === UPLOAD_ERR_OK) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $_FILES['favicon']['tmp_name']);
        finfo_close($finfo);
        if (!in_array($mime, ['image/png', 'image/jpeg'])) {
            $errors[] = "Favicon must be a PNG or JPG file.";
        } else {
            $size = getimagesize($_FILES['favicon']['tmp_name']);
            if ($size[0] !== $size[1] || !in_array($size[0], [32, 64])) {
                $errors[] = "Favicon must be 32x32 or 64x64 pixels.";
            } else {
                $faviconExt = $mime === 'image/png' ? 'png' : 'jpg';
                if (!move_uploaded_file($_FILES['favicon']['tmp_name'], $basePath . "favicon.$faviconExt")) {
                    $errors[] = "Failed to upload favicon.";
                } else {
                    chmod($basePath . "favicon.$faviconExt", 0644);
                    logMessage("Favicon uploaded to /$installDir/favicon.$faviconExt", 'success');
                }
            }
        }
    } else {
        $errors[] = "Favicon is required.";
    }

    // Logo
    if (isset($_FILES['logo']) && $_FILES['logo']['error'] === UPLOAD_ERR_OK) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $_FILES['logo']['tmp_name']);
        finfo_close($finfo);
        if (!in_array($mime, ['image/png', 'image/jpeg'])) {
            $errors[] = "Logo must be a PNG or JPG file.";
        } else {
            $size = getimagesize($_FILES['logo']['tmp_name']);
            if ($size[0] < 100 || $size[0] > 300 || $size[1] < 30 || $size[1] > 100) {
                $errors[] = "Logo must be between 100x30 and 300x100 pixels.";
            } else {
                $logoExt = $mime === 'image/png' ? 'png' : 'jpg';
                if (!move_uploaded_file($_FILES['logo']['tmp_name'], $basePath . "logo.$logoExt")) {
                    $errors[] = "Failed to upload logo.";
                } else {
                    chmod($basePath . "logo.$logoExt", 0644);
                    logMessage("Logo uploaded to /$installDir/logo.$logoExt", 'success');
                }
            }
        }
    } else {
        $errors[] = "Logo is required.";
    }

    // Validate database connection
    if (empty($errors)) {
        $dbTest = new mysqli($dbHost, $dbUser, $dbPass, $dbName);
        if ($dbTest->connect_error) {
            $errors[] = "Database connection failed: " . $dbTest->connect_error . ". Please verify credentials in your hosting control panel.";
        } else {
            $dbTest->close();
        }
    }

    if (empty($errors)) {
        // Proceed with installation
        debugLog("Form submission valid, proceeding with installation");
    }
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !empty($errors)) {
    // Show form
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PACS Installation Setup</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background-color: #f8f9fa; }
            .container { max-width: 600px; margin: auto; }
            h1 { text-align: center; }
            .alert { margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>PACS Installation Setup</h1>
            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger">
                    <?php foreach ($errors as $error): ?>
                        <p><?php echo htmlspecialchars($error); ?></p>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            <form method="post" enctype="multipart/form-data">
                <div class="mb-3">
                    <label for="hospital_name" class="form-label">Hospital Name</label>
                    <input type="text" name="hospital_name" id="hospital_name" class="form-control" placeholder="Enter hospital name" value="<?php echo htmlspecialchars($hospitalName); ?>" required>
                    <small class="form-text text-muted">Max 100 characters, displayed in page titles.</small>
                </div>
                <div class="mb-3">
                    <label for="domain" class="form-label">Domain</label>
                    <input type="text" name="domain" id="domain" class="form-control" placeholder="e.g., pacs.example.com" value="<?php echo htmlspecialchars($domain); ?>" required>
                    <small class="form-text text-muted">Enter the domain or subdomain where PACS will be hosted (e.g., pacs.example.com).</small>
                </div>
                <div class="mb-3">
                    <label for="install_dir" class="form-label">Installation Directory</label>
                    <input type="text" name="install_dir" id="install_dir" class="form-control" placeholder="e.g., public_html/pacs" value="<?php echo htmlspecialchars($installDir); ?>" required>
                    <small class="form-text text-muted">Path relative to /home1/<?php echo get_current_user(); ?>/, e.g., public_html/pacs.</small>
                </div>
                <div class="mb-3">
                    <label for="db_host" class="form-label">Database Host</label>
                    <input type="text" name="db_host" id="db_host" class="form-control" placeholder="e.g., localhost" value="<?php echo htmlspecialchars($dbHost); ?>" required>
                    <small class="form-text text-muted">Usually 'localhost' for shared hosting.</small>
                </div>
                <div class="mb-3">
                    <label for="db_name" class="form-label">Database Name</label>
                    <input type="text" name="db_name" id="db_name" class="form-control" placeholder="e.g., user_pacs" value="<?php echo htmlspecialchars($dbName); ?>" required>
                    <small class="form-text text-muted">Create in hosting control panel > MySQL Databases.</small>
                </div>
                <div class="mb-3">
                    <label for="db_user" class="form-label">Database Username</label>
                    <input type="text" name="db_user" id="db_user" class="form-control" placeholder="e.g., user_pacs" value="<?php echo htmlspecialchars($dbUser); ?>" required>
                    <small class="form-text text-muted">Create in hosting control panel > MySQL Databases.</small>
                </div>
                <div class="mb-3">
                    <label for="db_pass" class="form-label">Database Password</label>
                    <input type="password" name="db_pass" id="db_pass" class="form-control" placeholder="Database password" value="<?php echo htmlspecialchars($dbPass); ?>" required>
                    <small class="form-text text-muted">Password for the database user.</small>
                </div>
                <div class="mb-3">
                    <label for="favicon" class="form-label">Favicon (PNG or JPG, 32x32 or 64x64 pixels)</label>
                    <input type="file" name="favicon" id="favicon" class="form-control" accept="image/png,image/jpeg" required>
                </div>
                <div class="mb-3">
                    <label for="logo" class="form-label">Site Logo (PNG or JPG, 100x30 to 300x100 pixels)</label>
                    <input type="file" name="logo" id="logo" class="form-control" accept="image/png,image/jpeg" required>
                </div>
                <div class="text-center">
                    <button type="submit" class="btn btn-primary">Proceed with Installation</button>
                </div>
            </form>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    <?php
    ob_end_flush();
    exit;
}

// Define base path
$basePath = $homeDir . $installDir . '/';
$dwvDir = 'dwv';
$dicomStorageDir = 'dicom-storage';
$cssDir = 'css';
$sessionDir = 'sessions';
$nanodicomDir = 'nanodicom';

// Step 1: Create directories
debugLog("Creating directories in $basePath");
foreach ([$basePath, $basePath . $dwvDir, $basePath . $dicomStorageDir, $basePath . $cssDir, $basePath . $sessionDir, $basePath . $nanodicomDir] as $dir) {
    if (!file_exists($dir)) {
        if (mkdir($dir, $dir === $basePath . $sessionDir ? 0700 : 0755, true)) {
            logMessage("Created $dir", 'success');
        } else {
            logMessage("Failed to create $dir", 'error');
        }
    }
}
chmod($basePath . $sessionDir, 0700);

// Step 2: Download DWV Viewer (v0.11.0)
debugLog("Attempting DWV download");
$dwvZipUrl = 'https://github.com/ivmartel/dwv/archive/refs/tags/v0.11.0.zip';
$dwvZipPath = $basePath . 'dwv.zip';
if (ini_get('allow_url_fopen') && extension_loaded('zip')) {
    logMessage("Attempting to download DWV v0.11.0 from $dwvZipUrl...", 'success');
    if (file_put_contents($dwvZipPath, file_get_contents($dwvZipUrl))) {
        $zip = new ZipArchive;
        if ($zip->open($dwvZipPath) === true) {
            $zip->extractTo($basePath . $dwvDir);
            $zip->close();
            $extractedDir = glob($basePath . $dwvDir . '/dwv-*')[0];
            $viewerDir = $extractedDir . '/viewers';
            if (is_dir($viewerDir)) {
                $files = scandir($viewerDir);
                foreach ($files as $file) {
                    if ($file !== '.' && $file !== '..') {
                        rename($viewerDir . '/' . $file, $basePath . $dwvDir . '/' . $file);
                    }
                }
            }
            if (function_exists('exec')) {
                exec("rm -rf " . escapeshellarg($extractedDir) . " " . escapeshellarg($dwvZipPath));
                logMessage("DWV Viewer extracted to $dwvDir", 'success');
            } else {
                unlink($dwvZipPath);
                logMessage("DWV Viewer extracted, but cleanup may need manual removal of $extractedDir", 'success');
            }
        } else {
            logMessage("Failed to extract DWV zip", 'error');
        }
    } else {
        logMessage("Failed to download DWV. Please manually upload from https://github.com/ivmartel/dwv/releases/tag/v0.11.0 to /$installDir/dwv/", 'error');
    }
} else {
    logMessage("allow_url_fopen or zip extension not enabled. Manually upload DWV from https://github.com/ivmartel/dwv/releases/tag/v0.11.0 to /$installDir/dwv/", 'error');
}

// Step 3: Create style.css
debugLog("Creating style.css");
$styleCss = '/* General App Styles */
body { background-color: #f8f9fa; }
.container { max-width: 600px; margin-top: 70px; }
.card { border-radius: 15px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
.btn { border-radius: 25px; padding: 10px 30px; }
.form-control { border-radius: 10px; }
.list-group-item { border-radius: 10px; margin-bottom: 10px; }

/* Navbar Styles */
.navbar { box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.navbar-brand { font-weight: bold; }
.navbar-brand img.logo { max-height: 40px; width: auto; }
.nav-link { border-radius: 20px; margin: 0 5px; transition: background-color 0.3s; }
.nav-link:hover { background-color: rgba(0,0,0,0.05); }
.navbar-toggler { border-radius: 10px; }

/* Alerts and Progress */
.alert { margin-bottom: 20px; }
.progress { height: 20px; margin-bottom: 20px; }
.progress-bar { transition: width 0.3s ease-in-out; }

/* Mobile Responsiveness */
@media (max-width: 576px) {
    .container { max-width: 100%; padding: 0 15px; margin-top: 60px; }
    .btn { padding: 8px 20px; font-size: 0.875rem; width: 100%; }
    .card { margin: 10px; }
    .navbar-nav .nav-link { text-align: center; margin: 5px 0; }
    .navbar-brand img.logo { max-height: 30px; }
}
@media (min-width: 577px) and (max-width: 768px) {
    .container { max-width: 90%; }
    .btn { padding: 10px 25px; }
}
@media (min-width: 769px) {
    .container { max-width: 600px; }
}
.btn-delete { background-color: #dc3545; color: white; }
.btn-delete:hover { background-color: #c82333; }
';
writeFile($basePath . 'css/style.css', $styleCss);

// Step 4: Create config.php
debugLog("Creating config.php");
$configScript = '<?php
define("DB_HOST", "' . addslashes($dbHost) . '");
define("DB_USER", "' . addslashes($dbUser) . '");
define("DB_PASS", "' . addslashes($dbPass) . '");
define("DB_NAME", "' . addslashes($dbName) . '");
define("DOMAIN", "' . addslashes($domain) . '");
define("PACS_PATH", "' . addslashes($basePath) . '");
define("DICOM_STORAGE", "dicom-storage");
define("DWV_PATH", "dwv");
define("NANODICOM_PATH", PACS_PATH . "nanodicom");
define("ADMIN_USER", "admin");
define("ADMIN_PASS", "docentelasmercedes");
define("PUBLIC_USER", "user");
define("PUBLIC_PASS", "1234");
define("HOSPITAL_NAME", "' . addslashes($hospitalName) . '");
define("FAVICON_EXT", "' . $faviconExt . '");
define("LOGO_EXT", "' . $logoExt . '");
?>';
writeFile($basePath . 'config.php', $configScript);

// Step 5: Create session.php
debugLog("Creating session.php");
$sessionScript = '<?php
require __DIR__ . "/config.php";
ini_set("session.save_path", PACS_PATH . "sessions");
session_start();
?>';
writeFile($basePath . 'session.php', $sessionScript);

// Step 6: Create login.php
debugLog("Creating login.php");
$loginScript = '<?php
require __DIR__ . "/config.php";
ini_set("display_errors", 0);
ini_set("log_errors", 1);
ini_set("error_log", PACS_PATH . "login_error.log");
require __DIR__ . "/session.php";
$debug = [];
$debug[] = "Session started: " . (session_id() ? "Yes" : "No");
$success = "";
$error = "";
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $debug[] = "POST received: " . print_r($_POST, true);
    if (empty($_POST["username"]) || empty($_POST["password"])) {
        $error = "Username and password are required";
        $debug[] = "Missing username or password";
    } else {
        $username = $_POST["username"];
        $password = $_POST["password"];
        $debug[] = "Username: $username, Password: [hidden]";
        if ($username === ADMIN_USER && $password === ADMIN_PASS) {
            $_SESSION["role"] = "admin";
            $success = "Admin login successful, redirecting...";
            $debug[] = "Admin login successful, redirecting to /index.php";
            header("Refresh: 2; url=/index.php");
        } elseif ($username === PUBLIC_USER && $password === PUBLIC_PASS) {
            $_SESSION["role"] = "user";
            $success = "User login successful, redirecting...";
            $debug[] = "User login successful, redirecting to /search.php";
            header("Refresh: 2; url=/search.php");
        } else {
            $error = "Invalid credentials";
            $debug[] = "Login failed: Invalid credentials";
        }
    }
} else {
    $debug[] = "Not a POST request";
}
file_put_contents(PACS_PATH . "login_debug.txt", date("Y-m-d H:i:s") . "\n" . implode("\n", $debug) . "\n\n", FILE_APPEND);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars(HOSPITAL_NAME); ?> - PACS Login</title>
    <link rel="icon" href="/favicon.<?php echo FAVICON_EXT; ?>">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="/css/style.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <div class="container-fluid">
            <a class="navbar-brand" href="/"><img src="/logo.<?php echo LOGO_EXT; ?>" alt="<?php echo htmlspecialchars(HOSPITAL_NAME); ?>" class="logo"></a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link active" href="/login.php">Login</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container">
        <div class="card p-4">
            <h2 class="text-center mb-4">PACS Login</h2>
            <?php if ($success): ?>
                <div class="alert alert-success"><?php echo $success; ?></div>
            <?php endif; ?>
            <?php if ($error): ?>
                <div class="alert alert-danger"><?php echo $error; ?></div>
            <?php endif; ?>
            <form method="post" action="/login.php">
                <div class="mb-3">
                    <input type="text" name="username" class="form-control" placeholder="Username (admin or user)" required>
                </div>
                <div class="mb-3">
                    <input type="password" name="password" class="form-control" placeholder="Password" required>
                </div>
                <div class="text-center">
                    <button type="submit" class="btn btn-primary">Login</button>
                </div>
            </form>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>';
writeFile($basePath . 'login.php', $loginScript);

// Step 7: Create index.php
debugLog("Creating index.php");
$indexScript = <<<EOD
<?php
require __DIR__ . "/config.php";
ini_set("display_errors", 0);
ini_set("log_errors", 1);
ini_set("error_log", PACS_PATH . "login_error.log");
require __DIR__ . "/session.php";
if (!isset(\$_SESSION["role"]) || \$_SESSION["role"] !== "admin") {
    header("Location: /login.php");
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars(HOSPITAL_NAME); ?> - DICOM Upload</title>
    <link rel="icon" href="/favicon.{$faviconExt}">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="/css/style.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <div class="container-fluid">
            <a class="navbar-brand" href="/"><img src="/logo.{$logoExt}" alt="<?php echo htmlspecialchars(HOSPITAL_NAME); ?>" class="logo"></a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/search.php">Search</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/dwv/viewers/mobile/">View (DWV)</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="/index.php">Upload</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/delete.php">Delete Files</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout.php">Logout</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container">
        <div class="card p-4">
            <h2 class="text-center mb-4">Upload DICOM File</h2>
            <div id="uploadMessage" class="alert d-none"></div>
            <div id="progressBar" class="progress d-none">
                <div class="progress-bar" role="progressbar" style="width: 0%;" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</div>
            </div>
            <form id="uploadForm" action="/upload.php" method="post" enctype="multipart/form-data">
                <div class="mb-3">
                    <input type="file" name="dicom" id="dicomFile" accept=".dcm" class="form-control" required>
                </div>
                <div class="text-center">
                    <button type="submit" id="submitBtn" class="btn btn-primary" disabled>Upload</button>
                </div>
            </form>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const dicomFileInput = document.getElementById("dicomFile");
        const submitBtn = document.getElementById("submitBtn");
        const uploadForm = document.getElementById("uploadForm");
        const messageDiv = document.getElementById("uploadMessage");
        const progressBar = document.getElementById("progressBar");
        const progressBarInner = progressBar.querySelector(".progress-bar");

        function showMessage(message, type) {
            messageDiv.textContent = message;
            messageDiv.className = `alert alert-\${type} mt-3`;
            messageDiv.classList.remove("d-none");
        }

        function updateProgress(percent) {
            progressBar.classList.remove("d-none");
            progressBarInner.style.width = `\${percent}%`;
            progressBarInner.textContent = `\${percent}%`;
            progressBarInner.setAttribute("aria-valuenow", percent);
            if (percent === 100) {
                setTimeout(() => progressBar.classList.add("d-none"), 1000);
            }
        }

        dicomFileInput.addEventListener("change", function() {
            const file = this.files[0];
            submitBtn.disabled = !file;
        });

        uploadForm.addEventListener("submit", async function(e) {
            e.preventDefault();
            const file = dicomFileInput.files[0]; // Fixed index from [1] to [0]
            if (!file) {
                showMessage("No file selected.", "danger");
                return;
            }
            updateProgress(0);
            const formData = new FormData(this);
            try {
                updateProgress(10);
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 120000); // 120s timeout
                const response = await fetch("/upload.php", {
                    method: "POST",
                    body: formData,
                    signal: controller.signal
                });
                clearTimeout(timeoutId);
                updateProgress(50);
                if (!response.ok) {
                    throw new Error(`HTTP error! Status: \${response.status} \${response.statusText}`);
                }
                const data = await response.json();
                updateProgress(100);
                showMessage(data.message, data.status === "success" ? "success" : "danger");
                if (data.status === "success") {
                    setTimeout(() => location.reload(), 2000);
                } else {
                    console.error("Upload failed:", data.message);
                }
            } catch (error) {
                updateProgress(0);
                const errorMsg = error.name === "AbortError" ? "Upload request timed out after 120 seconds." : `Error uploading file: \${error.message}`;
                showMessage(errorMsg, "danger");
                console.error("Upload error:", error);
            }
        });
    </script>
</body>
</html>
EOD;
writeFile($basePath . 'index.php', $indexScript);

// Step 8: Create search.php
debugLog("Creating search.php");
$searchScript = '<?php
require __DIR__ . "/config.php";
ini_set("display_errors", 0);
ini_set("log_errors", 1);
ini_set("error_log", PACS_PATH . "login_error.log");
require __DIR__ . "/session.php";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars(HOSPITAL_NAME); ?> - Search DICOM Files</title>
    <link rel="icon" href="/favicon.<?php echo FAVICON_EXT; ?>">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="/css/style.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <div class="container-fluid">
            <a class="navbar-brand" href="/"><img src="/logo.<?php echo LOGO_EXT; ?>" alt="<?php echo htmlspecialchars(HOSPITAL_NAME); ?>" class="logo"></a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link active" href="/search.php">Search</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/dwv/viewers/mobile/">View (DWV)</a>
                    </li>
                    <?php if ($_SESSION["role"] === "admin"): ?>
                        <li class="nav-item">
                            <a class="nav-link" href="/index.php">Upload</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/delete.php">Delete Files</a>
                        </li>
                    <?php endif; ?>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout.php">Logout</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container">
        <div class="card p-4">
            <h2 class="text-center mb-4">Search DICOM Files</h2>
            <form method="get" action="/search.php">
                <div class="mb-3">
                    <input type="text" name="query" placeholder="Search by Patient Name, ID, Modality, etc." class="form-control" value="<?php echo isset($_GET[\'query\']) ? htmlspecialchars($_GET[\'query\']) : \'\'; ?>">
                </div>
                <div class="mb-3">
                    <label for="sort" class="form-label">Sort By</label>
                    <select name="sort" id="sort" class="form-control">
                        <option value="study_date" <?php echo isset($_GET[\'sort\']) && $_GET[\'sort\'] === \'study_date\' ? \'selected\' : \'\'; ?>>Study Date</option>
                        <option value="uploaded_at" <?php echo isset($_GET[\'sort\']) && $_GET[\'sort\'] === \'uploaded_at\' ? \'selected\' : \'\'; ?>>Upload Date</option>
                    </select>
                </div>
                <div class="text-center">
                    <button type="submit" class="btn btn-primary">Search</button>
                </div>
            </form>
            <?php
            if (isset($_GET["query"]) && !empty($_GET["query"])) {
                $db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
                if ($db->connect_error) {
                    echo \'<div class="alert alert-danger mt-3">Database connection failed: \' . $db->connect_error . \'</div>\';
                    file_put_contents(PACS_PATH . "login_debug.txt", date("Y-m-d H:i:s") . ": Search DB error: " . $db->connect_error . "\n", FILE_APPEND);
                    exit;
                }
                $query = "%" . $db->real_escape_string($_GET["query"]) . "%";
                $sort = isset($_GET["sort"]) && in_array($_GET["sort"], ["study_date", "uploaded_at"]) ? $_GET["sort"] : "study_date";
                $sortColumn = $sort === "study_date" ? "study_date" : "uploaded_at";
                $orderBy = $sort === "study_date" ? "IFNULL(STR_TO_DATE(study_date, \'%Y%m%d\'), uploaded_at) DESC, uploaded_at DESC" : "uploaded_at DESC";
                $stmt = $db->prepare("SELECT filename, patient_name, patient_id, study_date, uploaded_at, modality, institution_name, study_description, series_description, body_part_examined FROM dicom_files WHERE patient_name LIKE ? OR patient_id LIKE ? OR modality LIKE ? OR institution_name LIKE ? OR study_description LIKE ? OR series_description LIKE ? OR body_part_examined LIKE ? ORDER BY $orderBy");
                $stmt->bind_param("sssssss", $query, $query, $query, $query, $query, $query, $query);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($result->num_rows > 0) {
                    echo \'<h3 class="mt-4">Results:</h3><ul class="list-group">\';
                    while ($row = $result->fetch_assoc()) {
                        $dwvUrl = "https://" . DOMAIN . "/dwv/viewers/mobile/?input=https://" . DOMAIN . "/dicom-storage/{$row[\'filename\']}";
                        $studyDate = $row[\'study_date\'] ?: \'Unknown\';
                        $uploadedAt = $row[\'uploaded_at\'] ?: \'Unknown\';
                        $modality = $row[\'modality\'] ?: \'Unknown\';
                        $institutionName = $row[\'institution_name\'] ?: \'Unknown\';
                        $studyDescription = $row[\'study_description\'] ?: \'Unknown\';
                        $seriesDescription = $row[\'series_description\'] ?: \'Unknown\';
                        $bodyPartExamined = $row[\'body_part_examined\'] ?: \'Unknown\';
                        echo "<li class=\'list-group-item\'>
                            <div><strong>Patient:</strong> {$row[\'patient_name\']} (ID: {$row[\'patient_id\']})</div>
                            <div><strong>Study Date:</strong> $studyDate</div>
                            <div><strong>Uploaded:</strong> $uploadedAt</div>
                            <div><strong>Modality:</strong> $modality</div>
                            <div><strong>Institution:</strong> $institutionName</div>
                            <div><strong>Study Description:</strong> $studyDescription</div>
                            <div><strong>Series Description:</strong> $seriesDescription</div>
                            <div><strong>Body Part Examined:</strong> $bodyPartExamined</div>
                            <div><a href=\'$dwvUrl\' target=\'_blank\'>View in DWV</a></div>
                        </li>";
                    }
                    echo \'</ul>\';
                } else {
                    echo \'<div class="alert alert-info mt-3">No results found.</div>\';
                }
                $stmt->close();
                $db->close();
            }
            ?>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>';
writeFile($basePath . 'search.php', $searchScript);

// Step 9: Create delete.php
debugLog("Creating delete.php");
$deleteScript = '<?php
require __DIR__ . "/config.php";
ini_set("display_errors", 0);
ini_set("log_errors", 1);
ini_set("error_log", PACS_PATH . "login_error.log");
require __DIR__ . "/session.php";
if (!isset($_SESSION["role"]) || $_SESSION["role"] !== "admin") {
    header("Location: /login.php");
    exit;
}
$success = "";
$error = "";
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["delete_file"])) {
    $fileName = $_POST["delete_file"];
    $targetPath = PACS_PATH . DICOM_STORAGE . "/" . $fileName;
    file_put_contents(PACS_PATH . "login_debug.txt", date("Y-m-d H:i:s") . ": Delete attempt: $fileName\n", FILE_APPEND);
    if (!file_exists($targetPath)) {
        $error = "File not found: $fileName";
        file_put_contents(PACS_PATH . "login_debug.txt", date("Y-m-d H:i:s") . ": Delete failed: File not found\n", FILE_APPEND);
    } elseif (unlink($targetPath)) {
        $db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if ($db->connect_error) {
            $error = "Database connection failed: " . $db->connect_error;
            file_put_contents(PACS_PATH . "login_debug.txt", date("Y-m-d H:i:s") . ": Delete DB error: " . $db->connect_error . "\n", FILE_APPEND);
        } else {
            $stmt = $db->prepare("DELETE FROM dicom_files WHERE filename = ?");
            $stmt->bind_param("s", $fileName);
            $stmt->execute();
            $stmt->close();
            $db->close();
            $success = "File deleted successfully: $fileName";
            file_put_contents(PACS_PATH . "login_debug.txt", date("Y-m-d H:i:s") . ": Delete success: $fileName\n", FILE_APPEND);
        }
    } else {
        $error = "Failed to delete file: $fileName";
        file_put_contents(PACS_PATH . "login_debug.txt", date("Y-m-d H:i:s") . ": Delete failed: File unlink error\n", FILE_APPEND);
    }
}
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($db->connect_error) {
    $error = "Database connection failed: " . $db->connect_error;
    file_put_contents(PACS_PATH . "login_debug.txt", date("Y-m-d H:i:s") . ": Delete DB connect error: " . $db->connect_error . "\n", FILE_APPEND);
} else {
    $files = $db->query("SELECT filename FROM dicom_files ORDER BY uploaded_at DESC");
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars(HOSPITAL_NAME); ?> - Delete PACS Files</title>
    <link rel="icon" href="/favicon.<?php echo FAVICON_EXT; ?>">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="/css/style.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <div class="container-fluid">
            <a class="navbar-brand" href="/"><img src="/logo.<?php echo LOGO_EXT; ?>" alt="<?php echo htmlspecialchars(HOSPITAL_NAME); ?>" class="logo"></a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/search.php">Search</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/dwv/viewers/mobile/">View (DWV)</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/index.php">Upload</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="/delete.php">Delete Files</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout.php">Logout</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container">
        <div class="card p-4">
            <h2 class="text-center mb-4">Delete PACS Files</h2>
            <?php if ($success): ?>
                <div class="alert alert-success"><?php echo $success; ?></div>
            <?php endif; ?>
            <?php if ($error): ?>
                <div class="alert alert-danger"><?php echo $error; ?></div>
            <?php endif; ?>
            <form method="post">
                <div class="mb-3">
                    <select name="delete_file" class="form-control" required>
                        <option value="">Select File to Delete</option>
                        <?php if (isset($files)): while ($row = $files->fetch_assoc()): ?>
                            <option value="<?php echo htmlspecialchars($row[\'filename\']); ?>"><?php echo htmlspecialchars($row[\'filename\']); ?></option>
                        <?php endwhile; $files->close(); endif; ?>
                    </select>
                </div>
                <div class="text-center">
                    <button type="submit" class="btn btn-delete">Delete File</button>
                </div>
            </form>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>';
writeFile($basePath . 'delete.php', $deleteScript);

// Step 10: Create upload.php
debugLog("Creating upload.php");
$uploadScript = '<?php
require __DIR__ . "/config.php";
ini_set("display_errors", 0);
ini_set("log_errors", 1);
ini_set("error_log", PACS_PATH . "login_error.log");
require __DIR__ . "/session.php";
header("Content-Type: application/json");

try {
    if (!isset($_SESSION["role"]) || $_SESSION["role"] !== "admin") {
        throw new Exception("Unauthorized access: Admin role required");
    }

    $uploadDir = PACS_PATH . DICOM_STORAGE . "/";
    $response = ["status" => "error", "message" => ""];
    file_put_contents(PACS_PATH . "login_debug.txt", date("Y-m-d H:i:s") . ": Upload attempt\n", FILE_APPEND);

    // Check if upload directory is writable
    if (!is_writable($uploadDir)) {
        throw new Exception("Upload directory is not writable: " . $uploadDir);
    }

    // Check PHP upload errors
    if ($_SERVER["REQUEST_METHOD"] !== "POST" || !isset($_FILES["dicom"])) {
        throw new Exception("No file uploaded or invalid request");
    }

    if ($_FILES["dicom"]["error"] !== UPLOAD_ERR_OK) {
        $uploadErrors = [
            UPLOAD_ERR_INI_SIZE => "File size exceeds server limit (upload_max_filesize)",
            UPLOAD_ERR_FORM_SIZE => "File size exceeds form limit",
            UPLOAD_ERR_PARTIAL => "File was only partially uploaded",
            UPLOAD_ERR_NO_FILE => "No file was uploaded",
            UPLOAD_ERR_NO_TMP_DIR => "Missing temporary directory",
            UPLOAD_ERR_CANT_WRITE => "Failed to write file to disk",
            UPLOAD_ERR_EXTENSION => "A PHP extension stopped the file upload"
        ];
        $errorCode = $_FILES["dicom"]["error"];
        throw new Exception("File upload error: " . ($uploadErrors[$errorCode] ?? "Unknown error code: " . $errorCode));
    }

    // Validate file extension
    $originalFileName = basename($_FILES["dicom"]["name"]);
    if (pathinfo($originalFileName, PATHINFO_EXTENSION) !== "dcm") {
        throw new Exception("Only .dcm files are allowed");
    }

    // Generate unique filename
    $fileName = $originalFileName;
    $baseName = pathinfo($originalFileName, PATHINFO_FILENAME);
    $extension = pathinfo($originalFileName, PATHINFO_EXTENSION);
    $counter = 1;
    while (file_exists($uploadDir . $fileName)) {
        $fileName = $baseName . "_" . $counter . "." . $extension;
        $counter++;
    }
    $targetPath = $uploadDir . $fileName;
    file_put_contents(PACS_PATH . "login_debug.txt", date("Y-m-d H:i:s") . ": Uploading file: $fileName\n", FILE_APPEND);

    // Move uploaded file
    if (!move_uploaded_file($_FILES["dicom"]["tmp_name"], $targetPath)) {
        throw new Exception("Failed to move uploaded file to: " . $targetPath);
    }

    // Parse DICOM metadata
    require_once NANODICOM_PATH . "/nanodicom.php";
    $metadata = parseDicomMetadata($targetPath);

    // Connect to database
    $db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($db->connect_error) {
        throw new Exception("Database connection failed: " . $db->connect_error);
    }

    // Prepare metadata for database
    $metadata["patientName"] = is_string($metadata["patientName"]) ? $metadata["patientName"] : "";
    $metadata["patientId"] = is_string($metadata["patientId"]) ? $metadata["patientId"] : "";
    $metadata["studyDate"] = is_string($metadata["studyDate"]) ? $metadata["studyDate"] : "";
    $metadata["modality"] = is_string($metadata["modality"]) ? $metadata["modality"] : "";
    $metadata["institutionName"] = is_string($metadata["institutionName"]) ? $metadata["institutionName"] : "";
    $metadata["studyDescription"] = is_string($metadata["studyDescription"]) ? $metadata["studyDescription"] : "";
    $metadata["seriesDescription"] = is_string($metadata["seriesDescription"]) ? $metadata["seriesDescription"] : "";
    $metadata["bodyPartExamined"] = is_string($metadata["bodyPartExamined"]) ? $metadata["bodyPartExamined"] : "";

    // Insert metadata into database
    $stmt = $db->prepare("INSERT INTO dicom_files (filename, patient_name, patient_id, study_date, modality, institution_name, study_description, series_description, body_part_examined) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    if (!$stmt) {
        throw new Exception("Database prepare failed: " . $db->error);
    }
    $stmt->bind_param("sssssssss",
        $fileName,
        $metadata["patientName"],
        $metadata["patientId"],
        $metadata["studyDate"],
        $metadata["modality"],
        $metadata["institutionName"],
        $metadata["studyDescription"],
        $metadata["seriesDescription"],
        $metadata["bodyPartExamined"]
    );
    if (!$stmt->execute()) {
        throw new Exception("Database insert failed: " . $stmt->error);
    }
    $stmt->close();
    $db->close();

    $response["status"] = "success";
    $response["message"] = "File uploaded and metadata saved: $fileName";
    file_put_contents(PACS_PATH . "login_debug.txt", date("Y-m-d H:i:s") . ": Upload success: $fileName\n", FILE_APPEND);
} catch (Exception $e) {
    $response["message"] = $e->getMessage();
    file_put_contents(PACS_PATH . "login_debug.txt", date("Y-m-d H:i:s") . ": Upload failed: " . $e->getMessage() . "\n", FILE_APPEND);
}

echo json_encode($response);

function parseDicomMetadata($filePath) {
    try {
        if (!file_exists(NANODICOM_PATH . "/nanodicom.php")) {
            throw new Exception("Nanodicom library not found at " . NANODICOM_PATH . "/nanodicom.php");
        }
        $dicom = Nanodicom::factory($filePath, "simple");
        $dicom->parse([
            "PatientName",
            "PatientID",
            "StudyDate",
            "Modality",
            "InstitutionName",
            "StudyDescription",
            "SeriesDescription",
            "BodyPartExamined"
        ]);
        $rawPatientName = $dicom->value(0x0010, 0x0010);
        file_put_contents(PACS_PATH . "login_debug.txt", date("Y-m-d H:i:s") . ": Raw PatientName: " . print_r($rawPatientName, true) . "\n", FILE_APPEND);
        $patientName = is_string($rawPatientName) ? str_replace("^", " ", trim($rawPatientName)) : "Unknown";
        $metadata = [
            "patientName" => $patientName,
            "patientId" => $dicom->value(0x0010, 0x0020) ?? "Unknown",
            "studyDate" => $dicom->value(0x0008, 0x0020) ?? "Unknown",
            "modality" => $dicom->value(0x0008, 0x0060) ?? "Unknown",
            "institutionName" => $dicom->value(0x0008, 0x0080) ?? "Unknown",
            "studyDescription" => $dicom->value(0x0008, 0x1030) ?? "Unknown",
            "seriesDescription" => $dicom->value(0x0008, 0x103E) ?? "Unknown",
            "bodyPartExamined" => $dicom->value(0x0018, 0x0015) ?? "Unknown"
        ];
        unset($dicom);
        return $metadata;
    } catch (Exception $e) {
        file_put_contents(PACS_PATH . "login_debug.txt", date("Y-m-d H:i:s") . ": Metadata parse error: " . $e->getMessage() . "\n", FILE_APPEND);
        throw $e;
    }
}
?>';
writeFile($basePath . 'upload.php', $uploadScript);

// Step 11: Create logout.php
debugLog("Creating logout.php");
$logoutScript = '<?php
require __DIR__ . "/config.php";
ini_set("display_errors", 0);
ini_set("log_errors", 1);
ini_set("error_log", PACS_PATH . "login_error.log");
require __DIR__ . "/session.php";
session_destroy();
header("Location: /login.php");
exit;
?>';
writeFile($basePath . 'logout.php', $logoutScript);

// Step 12: Set up MySQL database
debugLog("Setting up database");
$db = new mysqli($dbHost, $dbUser, $dbPass, $dbName);
if ($db->connect_error) {
    logMessage("Failed to connect to MySQL: " . $db->connect_error . ". Please verify database credentials in your hosting control panel.", 'error');
} else {
    $sql = "CREATE TABLE IF NOT EXISTS dicom_files (
        id INT AUTO_INCREMENT PRIMARY KEY,
        filename VARCHAR(255) NOT NULL,
        patient_name VARCHAR(512),
        patient_id VARCHAR(255),
        study_date VARCHAR(50),
        modality VARCHAR(50),
        institution_name VARCHAR(255),
        study_description VARCHAR(255),
        series_description VARCHAR(255),
        body_part_examined VARCHAR(255),
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )";
    if ($db->query($sql) === true) {
        logMessage("Database table dicom_files created or already exists", 'success');
    } else {
        logMessage("Failed to create table: " . $db->error, 'error');
    }
    $db->close();
}

// Step 13: Output logs and instructions
ob_end_clean();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PACS Installation Log</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f8f9fa; }
        .container { max-width: 800px; margin: auto; }
        h1 { text-align: center; }
        .log { margin: 10px 0; padding: 10px; border-radius: 5px; }
        .success { color: #28a745; background-color: #d4edda; }
        .error { color: #dc3545; background-color: #f8d7da; }
        a { color: #007bff; text-decoration: underline; }
        a:hover { color: #0056b3; }
        ul { margin-top: 20px; }
        li { margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>PACS Installation Log</h1>
        <?php foreach ($logs as $log): ?>
            <div class="log <?php echo $log['type']; ?>">
                <?php echo $log['message']; ?>
            </div>
        <?php endforeach; ?>
        <h2>Next Steps</h2>
        <ul>
            <li>Enable HTTPS in your hosting control panel > SSL/TLS > Run AutoSSL or Let’s Encrypt for <?php echo htmlspecialchars($domain); ?></li>
            <li>Verify /<?php echo htmlspecialchars($installDir); ?>/config.php (database: <?php echo htmlspecialchars($dbName); ?>, public user: user/1234, hospital name: <?php echo htmlspecialchars($hospitalName); ?>)</li>
            <li>Verify /<?php echo htmlspecialchars($installDir); ?>/sessions/ exists and is chmod 700</li>
            <li>Verify favicon at /<?php echo htmlspecialchars($installDir); ?>/favicon.<?php echo $faviconExt; ?> and logo at /<?php echo htmlspecialchars($installDir); ?>/logo.<?php echo $logoExt; ?></li>
            <li>Verify Nanodicom library:
                <ul>
                    <li>Confirm /<?php echo htmlspecialchars($installDir); ?>/nanodicom/nanodicom.php and /<?php echo htmlspecialchars($installDir); ?>/nanodicom/dicom/ exist</li>
                    <li>Ensure /<?php echo htmlspecialchars($installDir); ?>/nanodicom/ is chmod 755 and files are chmod 644</li>
                </ul>
            </li>
            <li>If DWV was not downloaded correctly, manually:
                <ul>
                    <li>Download v0.11.0 from <a href="https://github.com/ivmartel/dwv/releases/tag/v0.11.0" target="_blank">https://github.com/ivmartel/dwv/releases/tag/v0.11.0</a></li>
                    <li>Upload viewers/ contents to /<?php echo htmlspecialchars($installDir); ?>/dwv/</li>
                </ul>
            </li>
            <li>Set permissions in File Manager:
                <ul>
                    <li>chmod 755 /<?php echo htmlspecialchars($installDir); ?>/, /<?php echo htmlspecialchars($installDir); ?>/dicom-storage/, /<?php echo htmlspecialchars($installDir); ?>/dwv/, /<?php echo htmlspecialchars($installDir); ?>/css/, /<?php echo htmlspecialchars($installDir); ?>/nanodicom/</li>
                    <li>chmod 700 /<?php echo htmlspecialchars($installDir); ?>/sessions/</li>
                    <li>chmod 644 /<?php echo htmlspecialchars($installDir); ?>/*.php, /<?php echo htmlspecialchars($installDir); ?>/css/style.css, /<?php echo htmlspecialchars($installDir); ?>/favicon.<?php echo $faviconExt; ?>, /<?php echo htmlspecialchars($installDir); ?>/logo.<?php echo $logoExt; ?>, /<?php echo htmlspecialchars($installDir); ?>/nanodicom/*.php, /<?php echo htmlspecialchars($installDir); ?>/nanodicom/dicom/*</li>
                </ul>
            </li>
            <li>Verify PHP settings in hosting control panel > PHP Settings:
                <ul>
                    <li>upload_max_filesize: 32M</li>
                    <li>post_max_size: 32M</li>
                    <li>max_execution_time: 300</li>
                </ul>
            </li>
            <li>Verify domain/subdomain: <a href="https://<?php echo $domain; ?>" target="_blank"><?php echo htmlspecialchars($domain); ?></a> points to /home1/<?php echo get_current_user(); ?>/<?php echo htmlspecialchars($installDir); ?>/</li>
            <li>Access:
                <ul>
                    <li>Login: <a href="https://<?php echo $domain; ?>/login.php" target="_blank">https://<?php echo $domain; ?>/login.php</a> (admin/docentelasmercedes or user/1234)</li>
                    <li>Upload (admin): <a href="https://<?php echo $domain; ?>/index.php" target="_blank">https://<?php echo $domain; ?>/index.php</a></li>
                    <li>Search: <a href="https://<?php echo $domain; ?>/search.php" target="_blank">https://<?php echo $domain; ?>/search.php</a></li>
                    <li>View (DWV): <a href="https://<?php echo $domain; ?>/dwv/viewers/mobile/" target="_blank">https://<?php echo $domain; ?>/dwv/viewers/mobile/</a></li>
                    <li>Delete (admin): <a href="https://<?php echo $domain; ?>/delete.php" target="_blank">https://<?php echo $domain; ?>/delete.php</a></li>
                </ul>
            </li>
            <li>Test with sample DICOM from <a href="https://www.dicomlibrary.com" target="_blank">https://www.dicomlibrary.com</a></li>
            <li>Delete /<?php echo htmlspecialchars($installDir); ?>/install_pacs.php after installation for security</li>
            <li>Check /home1/<?php echo get_current_user(); ?>/install_log.txt, /<?php echo htmlspecialchars($installDir); ?>/login_debug.txt, and /<?php echo htmlspecialchars($installDir); ?>/login_error.log for debugging</li>
        </ul>
    </div>
</body>
</html>
<?php
debugLog("Installation completed, logs written");
?>
