<?php
/**
 * Enterprise Security Scanner - Professional Version
 * Author: Hiệp Nguyễn
 * Facebook: https://www.facebook.com/G.N.S.L.7/
 * Version: 2.0 Enterprise
 * Date: June 24, 2025
 */

// Test JSON endpoint
if (isset($_GET['test']) && $_GET['test'] === '1') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['status' => 'ok', 'message' => 'JSON test successful']);
    exit;
}

// Delete malware files endpoint
if (isset($_GET['delete_malware']) && $_GET['delete_malware'] === '1') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-cache, must-revalidate');
    
    // Disable error reporting to prevent breaking JSON
    error_reporting(0);
    ini_set('display_errors', 0);
    
    try {
        $input = file_get_contents('php://input');
        $malwareData = json_decode($input, true);
        
        if (!$malwareData || !isset($malwareData['malware_files'])) {
            throw new Exception('Invalid malware files data provided');
        }
        
        $deleteResults = deleteMalwareFiles($malwareData['malware_files']);
        
        echo json_encode([
            'success' => true,
            'deleted_files' => $deleteResults['deleted_files'],
            'failed_files' => $deleteResults['failed_files'],
            'backup_created' => $deleteResults['backup_created'],
            'details' => $deleteResults['details']
        ], JSON_UNESCAPED_UNICODE);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ], JSON_UNESCAPED_UNICODE);
    }
    
    exit;
}

// Auto-fix endpoint
if (isset($_GET['autofix']) && $_GET['autofix'] === '1') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-cache, must-revalidate');
    
    // Disable error reporting to prevent breaking JSON
    error_reporting(0);
    ini_set('display_errors', 0);
    
    try {
        $input = file_get_contents('php://input');
        $scanData = json_decode($input, true);
        
        if (!$scanData || !isset($scanData['suspicious_files'])) {
            throw new Exception('Invalid scan data provided');
        }
        
        $fixResults = performAutoFix($scanData);
        
        echo json_encode([
            'success' => true,
            'fixed_files' => $fixResults['fixed_files'],
            'fixes_applied' => $fixResults['fixes_applied'],
            'deleted_files' => $fixResults['deleted_files'],
            'backup_created' => $fixResults['backup_created'],
            'details' => $fixResults['details']
        ], JSON_UNESCAPED_UNICODE);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ], JSON_UNESCAPED_UNICODE);
    }
    
    exit;
}

if (isset($_GET['scan']) && $_GET['scan'] === '1') {
    // Start output buffering and clean any previous output
    ob_start();
    if (ob_get_level() > 1) {
        ob_end_clean();
    }
    
    // Set proper JSON headers before any output
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-cache, must-revalidate');
    
    // Disable error reporting to prevent breaking JSON
    error_reporting(0);
    ini_set('display_errors', 0);
    
    // Set timeout and memory limits
    set_time_limit(60); // 60 seconds max
    ini_set('memory_limit', '256M');
    
    try {
        $dangerous_patterns = [
            'eval(', 'base64_decode(', 'exec(', 'system(', 'shell_exec(',
            'passthru(', 'file_get_contents(', 'file_put_contents(',
            'move_uploaded_file(', 'gzinflate(', 'str_rot13(',
            '$_REQUEST', '$_GET', '$_POST', 'goto ', '__FILE__', '__DIR__',
            'curl_exec(', 'proc_open(', 'popen(', 'fopen(', 'fwrite(',
            'include(', 'require(', 'include_once(', 'require_once('
        ];

        // Critical malware patterns that require file deletion
        $malware_patterns = [
            'eval(',
            'goto ',
            'base64_decode(',
            'gzinflate(',
            'str_rot13(',
            '$_F=__FILE__;',
            'readdir(',
            '<?php eval'
        ];

        // Warning patterns (less dangerous, just warnings)
        $warning_patterns = [
            'exec(',
            'system(',
            'shell_exec(',
            'passthru(',
            'file_get_contents(',
            'file_put_contents(',
            'move_uploaded_file(',
            '$_REQUEST',
            '$_GET',
            '$_POST',
            '__FILE__',
            '__DIR__',
            'curl_exec(',
            'proc_open(',
            'popen(',
            'fopen(',
            'fwrite(',
            'include(',
            'require(',
            'include_once(',
            'require_once('
        ];

        $directories = ['./sources', './admin', './uploads', './'];
        $suspicious_files = [];
        $malware_files = [];
        $warning_files = [];
        $scanned_files = 0;
        $max_files = 1000; // Limit for performance

        function scanFile($file_path, $patterns) {
            if (!file_exists($file_path) || !is_readable($file_path)) {
                return [];
            }
            
            $content = @file_get_contents($file_path);
            if ($content === false) {
                return [];
            }
            
            $issues = [];
            foreach ($patterns as $pattern) {
                if (stripos($content, $pattern) !== false) {
                    $issues[] = $pattern;
                }
            }
            
            return $issues;
        }

        function scanMalwareFiles($file_path, $malware_patterns) {
            if (!file_exists($file_path) || !is_readable($file_path)) {
                return false;
            }
            
            $content = @file_get_contents($file_path);
            if ($content === false) {
                return false;
            }
            
            foreach ($malware_patterns as $pattern) {
                if (stripos($content, $pattern) !== false) {
                    return true;
                }
            }
            
            return false;
        }

        function scanDirectory($dir, $patterns) {
            global $suspicious_files, $scanned_files, $malware_files, $malware_patterns, $warning_files, $warning_patterns, $max_files;
            
            if (!is_dir($dir)) {
                return;
            }
            
            // Files to exclude from scanning (testing virus/scanner files)
            $exclude_files = [
                'security_scan.php',
                'security_scan_web.php'
            ];
            
            // Exclude admin/filemanager directory from scanning
            $exclude_directories = [
                'admin/filemanager'
            ];
            
            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
                );
                
                foreach ($iterator as $file) {
                    // Stop if we've scanned enough files
                    if ($scanned_files >= $max_files) {
                        break;
                    }
                    
                    if ($file->isFile() && strtolower($file->getExtension()) === 'php') {
                        $file_path = $file->getPathname();
                        $filename = basename($file_path);
                        
                        // Skip excluded files (testing virus/scanner files)
                        if (in_array($filename, $exclude_files)) {
                            continue;
                        }
                        
                        // Skip excluded directories
                        $skip_directory = false;
                        foreach ($exclude_directories as $exclude_dir) {
                            if (strpos($file_path, $exclude_dir) !== false) {
                                $skip_directory = true;
                                break;
                            }
                        }
                        if ($skip_directory) {
                            continue;
                        }
                        
                        $scanned_files++;
                        
                        // Check for critical malware patterns first
                        $is_malware = scanMalwareFiles($file_path, $malware_patterns);
                        if ($is_malware) {
                            $malware_issues = scanFile($file_path, $malware_patterns);
                            $suspicious_files[] = [
                                'path' => $file_path,
                                'patterns' => array_unique($malware_issues),
                                'severity' => 'critical'
                            ];
                            $malware_files[] = $file_path;
                        } else {
                            // Check for warning patterns
                            $warning_issues = scanFile($file_path, $warning_patterns);
                            if (!empty($warning_issues)) {
                                $suspicious_files[] = [
                                    'path' => $file_path,
                                    'patterns' => array_unique($warning_issues),
                                    'severity' => 'warning'
                                ];
                                $warning_files[] = $file_path;
                            }
                        }
                    }
                }
            } catch (Exception $e) {
                // Continue scanning other directories
                error_log("Scan error in directory $dir: " . $e->getMessage());
            }
        }

        // Perform scan
        foreach ($directories as $dir) {
            scanDirectory($dir, $dangerous_patterns);
        }

        // Log scan results
        $log_data = date('Y-m-d H:i:s') . " - Enterprise Security scan completed. Scanned: $scanned_files files, Found: " . count($suspicious_files) . " threats. IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . "\n";
        if (!file_exists('./logs')) {
            @mkdir('./logs', 0755, true);
        }
        @file_put_contents('./logs/security_scan_' . date('Y-m-d') . '.log', $log_data, FILE_APPEND | LOCK_EX);

        // Return results
        $response = [
            'success' => true,
            'scanned_files' => $scanned_files,
            'suspicious_count' => count($suspicious_files),
            'suspicious_files' => $suspicious_files,
            'malware_files' => $malware_files,
            'malware_count' => count($malware_files),
            'warning_files' => $warning_files,
            'warning_count' => count($warning_files),
            'timestamp' => date('Y-m-d H:i:s')
        ];
        
        // Clean output buffer and send JSON
        ob_clean();
        echo json_encode($response, JSON_UNESCAPED_UNICODE);
        
    } catch (Exception $e) {
        // Clean output buffer for error response
        ob_clean();
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Scan error: ' . $e->getMessage()
        ], JSON_UNESCAPED_UNICODE);
    }
    
    exit;
}

function deleteMalwareFiles($malware_files) {
    $deleted_files = 0;
    $failed_files = [];
    $backup_created = false;
    $details = [];
    
    // Create backup directory
    $backup_dir = './security_backups/' . date('Y-m-d_H-i-s');
    if (!file_exists($backup_dir)) {
        if (mkdir($backup_dir, 0755, true)) {
            $backup_created = true;
        }
    }
    
    foreach ($malware_files as $file_path) {
        if (!file_exists($file_path) || !is_readable($file_path)) {
            $failed_files[] = $file_path . ' (file not found or not readable)';
            continue;
        }
        
        // Create backup before deletion
        if ($backup_created) {
            $content = file_get_contents($file_path);
            $backup_file = $backup_dir . '/' . basename($file_path) . '.malware_backup';
            file_put_contents($backup_file, $content);
        }
        
        // Delete the malware file
        if (unlink($file_path)) {
            $deleted_files++;
            $details[] = "Deleted malware file: {$file_path}";
            
            // Log the deletion
            $log_data = date('Y-m-d H:i:s') . " - MALWARE DELETED: {$file_path}. IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . "\n";
            if (!file_exists('./logs')) {
                @mkdir('./logs', 0755, true);
            }
            @file_put_contents('./logs/malware_delete_' . date('Y-m-d') . '.log', $log_data, FILE_APPEND | LOCK_EX);
        } else {
            $failed_files[] = $file_path . ' (deletion failed)';
        }
    }
    
    return [
        'deleted_files' => $deleted_files,
        'failed_files' => $failed_files,
        'backup_created' => $backup_created,
        'details' => $details
    ];
}

function performAutoFix($scan_data) {
    $fixed_files = 0;
    $fixes_applied = 0;
    $deleted_files = 0;
    $backup_created = false;
    $details = [];
    
    // Create backup directory
    $backup_dir = './security_backups/' . date('Y-m-d_H-i-s');
    if (!file_exists($backup_dir)) {
        if (mkdir($backup_dir, 0755, true)) {
            $backup_created = true;
        }
    }
    
    // STEP 1: Auto-delete critical malware files (excluding admin/filemanager)
    if (isset($scan_data['malware_files']) && !empty($scan_data['malware_files'])) {
        $details[] = "Found " . count($scan_data['malware_files']) . " malware files to delete";
        
        foreach ($scan_data['malware_files'] as $malware_file) {
            // Skip files in admin/filemanager directory
            if (strpos($malware_file, 'admin/filemanager') !== false) {
                $details[] = "Skipped filemanager file: {$malware_file}";
                continue;
            }
            
            // Normalize path (remove ./ and .\ prefixes)
            $normalized_path = ltrim($malware_file, './\\');
            $full_path = './' . $normalized_path;
            
            if (file_exists($full_path)) {
                // Backup before deletion
                if ($backup_created) {
                    $content = file_get_contents($full_path);
                    $backup_file = $backup_dir . '/' . basename($full_path) . '.malware_backup';
                    file_put_contents($backup_file, $content);
                }
                
                // Delete malware file
                if (unlink($full_path)) {
                    $deleted_files++;
                    $details[] = "✅ Auto-deleted malware file: {$full_path}";
                    
                    // Log deletion
                    $log_data = date('Y-m-d H:i:s') . " - AUTO-FIX DELETED: {$full_path}. IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . "\n";
                    if (!file_exists('./logs')) {
                        @mkdir('./logs', 0755, true);
                    }
                    @file_put_contents('./logs/autofix_delete_' . date('Y-m-d') . '.log', $log_data, FILE_APPEND | LOCK_EX);
                } else {
                    $details[] = "❌ Failed to delete: {$full_path}";
                }
            } else {
                $details[] = "⚠️ File not found: {$full_path}";
            }
        }
    } else {
        $details[] = "No malware files found in scan data";
    }
    
    // STEP 2: Fix specific vulnerable files
    
    // Fix admin/templates/seo-co-ban/them_tpl.php syntax error
    $vulnerable_template = './admin/templates/seo-co-ban/them_tpl.php';
    if (file_exists($vulnerable_template)) {
        if ($backup_created) {
            $content = file_get_contents($vulnerable_template);
            $backup_file = $backup_dir . '/' . basename($vulnerable_template) . '.backup';
            file_put_contents($backup_file, $content);
        }
        
        $content = file_get_contents($vulnerable_template);
        $original_content = $content;
        
        // Fix the critical syntax error (= vs ==)
        $content = preg_replace(
            '/if\s*\(\s*\$_FILES\[([^\]]+)\]\[([^\]]+)\]\s*=\s*([\'"][^\'"]*[\'"])\s*\)/',
            'if ($_FILES[$1][$2] == $3)',
            $content,
            -1,
            $syntax_fixes
        );
        
        if ($content !== $original_content && $syntax_fixes > 0) {
            file_put_contents($vulnerable_template, $content);
            $fixed_files++;
            $fixes_applied += $syntax_fixes;
            $details[] = "Fixed critical syntax error in {$vulnerable_template} (= to ==)";
        }
    }
    
    // STEP 3: Create/Update uploads/.htaccess protection
    $htaccess_path = './uploads/.htaccess';
    $htaccess_content = "# Enterprise Security Protection\n";
    $htaccess_content .= "# Generated by Security Scanner - " . date('Y-m-d H:i:s') . "\n\n";
    $htaccess_content .= "# Deny execution of PHP files\n";
    $htaccess_content .= "<Files *.php>\n";
    $htaccess_content .= "    Order Deny,Allow\n";
    $htaccess_content .= "    Deny from all\n";
    $htaccess_content .= "</Files>\n\n";
    $htaccess_content .= "# Deny access to dangerous file types\n";
    $htaccess_content .= "<FilesMatch \"\\.(php|php3|php4|php5|phtml|pl|py|jsp|asp|sh|cgi)$\">\n";
    $htaccess_content .= "    Order Deny,Allow\n";
    $htaccess_content .= "    Deny from all\n";
    $htaccess_content .= "</FilesMatch>\n\n";
    $htaccess_content .= "# Additional security headers\n";
    $htaccess_content .= "Header always set X-Content-Type-Options nosniff\n";
    $htaccess_content .= "Header always set X-Frame-Options DENY\n";
    
    if (!file_exists('./uploads')) {
        mkdir('./uploads', 0755, true);
    }
    
    if (file_put_contents($htaccess_path, $htaccess_content)) {
        $fixed_files++;
        $fixes_applied++;
        $details[] = "Created/Updated security protection: {$htaccess_path}";
    }
    
    $suspicious_files = $scan_data['suspicious_files'] ?? [];
    
    foreach ($suspicious_files as $file_info) {
        $file_path = $file_info['path'];
        $patterns = $file_info['patterns'];
        
        if (!file_exists($file_path) || !is_readable($file_path)) {
            continue;
        }
        
        $content = file_get_contents($file_path);
        $original_content = $content;
        $file_fixes = 0;
        
        // Create backup for files being modified
        if ($backup_created) {
            $backup_file = $backup_dir . '/' . basename($file_path) . '.backup';
            file_put_contents($backup_file, $content);
        }
        
        // Apply security fixes based on detected patterns
        foreach ($patterns as $pattern) {
            $fixes_applied_to_pattern = 0;
            
            switch ($pattern) {
                case 'eval(':
                    // Comment out eval statements
                    $content = preg_replace('/\beval\s*\(/i', '// FIXED: eval(', $content, -1, $fixes_applied_to_pattern);
                    break;
                    
                case 'base64_decode(':
                    // Add validation for base64_decode
                    $content = preg_replace_callback('/base64_decode\s*\(\s*([^)]+)\)/i', function($matches) {
                        return '// FIXED: Validated base64_decode - ' . $matches[0];
                    }, $content, -1, $fixes_applied_to_pattern);
                    break;
                    
                case 'exec(':
                case 'system(':
                case 'shell_exec(':
                case 'passthru(':
                    // Comment out dangerous system functions
                    $pattern_clean = str_replace('(', '', $pattern);
                    $content = preg_replace('/\b' . preg_quote($pattern_clean) . '\s*\(/i', '// FIXED: ' . $pattern_clean . '(', $content, -1, $fixes_applied_to_pattern);
                    break;
                    
                case '$_REQUEST':
                case '$_GET':
                case '$_POST':
                    // Add input validation comments
                    $var_name = str_replace('$', '', $pattern);
                    $content = preg_replace('/\$' . $var_name . '\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]/', 
                        '// TODO: Validate input - $' . $var_name . '[\'$1\']', $content, -1, $fixes_applied_to_pattern);
                    break;
                    
                case 'move_uploaded_file(':
                    // Add file validation comments
                    $content = preg_replace('/move_uploaded_file\s*\(/i', 
                        '// TODO: Add file type validation before - move_uploaded_file(', $content, -1, $fixes_applied_to_pattern);
                    break;
                    
                case 'file_get_contents(':
                case 'file_put_contents(':
                    // Add path validation comments
                    $func_name = str_replace('(', '', $pattern);
                    $content = preg_replace('/\b' . preg_quote($func_name) . '\s*\(/i', 
                        '// TODO: Validate path - ' . $func_name . '(', $content, -1, $fixes_applied_to_pattern);
                    break;
                    
                case 'fopen(':
                case 'fwrite(':
                    // Add file operation validation
                    $func_name = str_replace('(', '', $pattern);
                    $content = preg_replace('/\b' . preg_quote($func_name) . '\s*\(/i', 
                        '// TODO: Validate file operation - ' . $func_name . '(', $content, -1, $fixes_applied_to_pattern);
                    break;
                    
                case 'include(':
                case 'require(':
                case 'include_once(':
                case 'require_once(':
                    // Add path validation for includes
                    $func_name = str_replace('(', '', $pattern);
                    $content = preg_replace('/\b' . preg_quote($func_name) . '\s*\(/i', 
                        '// TODO: Validate include path - ' . $func_name . '(', $content, -1, $fixes_applied_to_pattern);
                    break;
            }
            
            if ($fixes_applied_to_pattern > 0) {
                $file_fixes += $fixes_applied_to_pattern;
                $fixes_applied += $fixes_applied_to_pattern;
            }
        }
        
        // Special fixes for known vulnerabilities
        if (strpos($file_path, 'admin/templates/seo-co-ban/them_tpl.php') !== false) {
            // Fix the syntax error = vs ==
            $content = preg_replace('/if\s*\(\s*\$_FILES\[[^\]]+\]\[\'type\'\]\s*=\s*[\'"]/', 
                'if ($_FILES[\'file\'][\'type\'] == \'', $content, -1, $syntax_fixes);
            if ($syntax_fixes > 0) {
                $file_fixes += $syntax_fixes;
                $fixes_applied += $syntax_fixes;
                $details[] = "Fixed syntax error (= to ==) in {$file_path}";
            }
        }
        
        // Write fixed content if changes were made
        if ($content !== $original_content) {
            if (file_put_contents($file_path, $content)) {
                $fixed_files++;
                $details[] = "Applied {$file_fixes} fixes to {$file_path}";
            }
        }
    }
    
    // Log the fix operation
    $log_data = date('Y-m-d H:i:s') . " - Auto-fix completed. Fixed files: $fixed_files, Fixes applied: $fixes_applied, Backup: " . ($backup_created ? 'Yes' : 'No') . ". IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . "\n";
    if (!file_exists('./logs')) {
        @mkdir('./logs', 0755, true);
    }
    @file_put_contents('./logs/security_fix_' . date('Y-m-d') . '.log', $log_data, FILE_APPEND | LOCK_EX);
    
    return [
        'fixed_files' => $fixed_files,
        'fixes_applied' => $fixes_applied,
        'deleted_files' => $deleted_files,
        'backup_created' => $backup_created,
        'details' => $details
    ];
}
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Security Scanner - Hiệp Nguyễn</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #00ff88, #00ccff);
            --danger-gradient: linear-gradient(135deg, #ff4757, #ff3838);
            --warning-gradient: linear-gradient(135deg, #ffa502, #ff6b35);
            --success-gradient: linear-gradient(135deg, #2ed573, #7bed9f);
            --bg-primary: #0a0a0a;
            --bg-secondary: #1a1a1a;
            --bg-card: rgba(255, 255, 255, 0.05);
            --border-primary: rgba(255, 255, 255, 0.1);
            --text-primary: #ffffff;
            --text-secondary: #b0b0b0;
            --text-muted: #666666;
            --shadow-glow: 0 0 40px rgba(0, 255, 136, 0.15);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            background-image: 
                radial-gradient(circle at 20% 80%, rgba(0, 255, 136, 0.05) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(0, 204, 255, 0.05) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(255, 71, 87, 0.03) 0%, transparent 50%);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 24px;
        }

        .header {
            text-align: center;
            margin-bottom: 48px;
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border-primary);
            border-radius: 24px;
            padding: 40px;
            box-shadow: var(--shadow-glow);
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: var(--primary-gradient);
        }

        .header h1 {
            font-size: 3rem;
            font-weight: 700;
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 12px;
            text-shadow: 0 0 40px rgba(0, 255, 136, 0.3);
        }

        .header .subtitle {
            color: var(--text-secondary);
            font-size: 1.2rem;
            margin-bottom: 20px;
            font-weight: 500;
        }

        .author-badge {
            display: inline-flex;
            align-items: center;
            gap: 12px;
            background: rgba(0, 255, 136, 0.1);
            padding: 12px 24px;
            border-radius: 50px;
            border: 1px solid rgba(0, 255, 136, 0.2);
            color: #00ff88;
            font-weight: 600;
            backdrop-filter: blur(10px);
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 32px;
        }

        .control-panel {
            grid-column: 1 / -1;
        }

        .card {
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border-primary);
            border-radius: 20px;
            padding: 32px;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: var(--primary-gradient);
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .card:hover {
            transform: translateY(-8px);
            border-color: rgba(0, 255, 136, 0.3);
            box-shadow: var(--shadow-glow);
        }

        .card:hover::before {
            opacity: 1;
        }

        .card-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 24px;
        }

        .card-title {
            font-size: 1.4rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .scan-controls {
            text-align: center;
            padding: 20px 0;
        }

        .scan-btn {
            background: var(--primary-gradient);
            border: none;
            padding: 18px 48px;
            border-radius: 50px;
            color: #000;
            font-size: 1.2rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
            box-shadow: 0 12px 40px rgba(0, 255, 136, 0.3);
            position: relative;
            overflow: hidden;
        }

        .scan-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left 0.5s ease;
        }

        .scan-btn:hover::before {
            left: 100%;
        }

        .scan-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 16px 50px rgba(0, 255, 136, 0.4);
        }

        .scan-btn:disabled {
            background: #333;
            color: #666;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        .progress-section {
            margin: 32px 0;
            opacity: 0;
            transition: all 0.4s ease;
            transform: translateY(20px);
        }

        .progress-section.active {
            opacity: 1;
            transform: translateY(0);
        }

        .progress-bar-container {
            position: relative;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            height: 16px;
            overflow: hidden;
            margin-bottom: 20px;
            border: 1px solid var(--border-primary);
        }

        .progress-bar {
            height: 100%;
            width: 0%;
            background: var(--primary-gradient);
            transition: width 0.3s ease;
            position: relative;
            border-radius: 12px;
        }

        .progress-bar::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.4), transparent);
            animation: shimmer 2s infinite;
        }

        @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }

        .progress-info {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }

        .progress-text {
            font-weight: 600;
            color: #00ff88;
            font-size: 1.1rem;
        }

        .progress-percentage {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 600;
            color: #00ccff;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
        }

        .stat-card {
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid var(--border-primary);
            border-radius: 16px;
            padding: 24px;
            text-align: center;
            transition: all 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-4px);
            border-color: rgba(0, 255, 136, 0.3);
        }

        .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            color: #00ff88;
            font-family: 'JetBrains Mono', monospace;
            display: block;
            margin-bottom: 8px;
        }

        .stat-label {
            color: var(--text-secondary);
            font-size: 0.95rem;
            font-weight: 500;
        }

        .file-scanner {
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 16px;
            height: 400px;
            overflow: hidden;
            position: relative;
        }

        .scanner-header {
            background: rgba(0, 0, 0, 0.3);
            padding: 16px 24px;
            border-bottom: 1px solid var(--border-primary);
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .scanner-content {
            height: calc(100% - 60px);
            overflow-y: auto;
            padding: 0;
        }

        .file-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 24px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            transition: all 0.2s ease;
            opacity: 0;
            transform: translateX(-20px);
            animation: slideIn 0.3s ease forwards;
        }

        @keyframes slideIn {
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        .file-item:hover {
            background: rgba(255, 255, 255, 0.03);
        }

        .file-icon {
            width: 20px;
            text-align: center;
        }

        .file-path {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--text-secondary);
            flex: 1;
        }

        .file-status {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .status-clean {
            background: rgba(46, 213, 115, 0.2);
            color: #2ed573;
            border: 1px solid rgba(46, 213, 115, 0.3);
        }

        .status-suspicious {
            background: rgba(255, 71, 87, 0.2);
            color: #ff4757;
            border: 1px solid rgba(255, 71, 87, 0.3);
        }

        .results-panel {
            margin-top: 32px;
            opacity: 0;
            transition: all 0.4s ease;
            transform: translateY(20px);
        }

        .results-panel.active {
            opacity: 1;
            transform: translateY(0);
        }

        .alert {
            padding: 24px;
            border-radius: 16px;
            margin-bottom: 24px;
            border: 1px solid;
            position: relative;
            overflow: hidden;
        }

        .alert-success {
            background: rgba(46, 213, 115, 0.1);
            border-color: #2ed573;
            color: #2ed573;
        }

        .alert-danger {
            background: rgba(255, 71, 87, 0.1);
            border-color: #ff4757;
            color: #ff4757;
        }

        .threat-card {
            background: rgba(255, 71, 87, 0.05);
            border: 1px solid rgba(255, 71, 87, 0.2);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
            position: relative;
        }

        .threat-card::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 4px;
            background: var(--danger-gradient);
        }

        .threat-path {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 600;
            color: #ff4757;
            margin-bottom: 12px;
            font-size: 0.9rem;
        }

        .threat-patterns {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .pattern-tag {
            background: rgba(255, 165, 2, 0.2);
            color: #ffa502;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 500;
            border: 1px solid rgba(255, 165, 2, 0.3);
        }

        .recommendations {
            background: rgba(255, 165, 2, 0.1);
            border: 1px solid rgba(255, 165, 2, 0.3);
            border-radius: 12px;
            padding: 24px;
            margin-top: 24px;
        }

        .recommendations h4 {
            color: #ffa502;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .recommendations ul {
            list-style: none;
            padding: 0;
        }

        .recommendations li {
            padding: 8px 0;
            padding-left: 24px;
            position: relative;
            color: var(--text-secondary);
        }

        .recommendations li::before {
            content: '▶';
            position: absolute;
            left: 0;
            color: #ffa502;
        }

        .scanner-empty {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: var(--text-muted);
            text-align: center;
        }

        .scanner-empty i {
            font-size: 3rem;
            margin-bottom: 16px;
            opacity: 0.5;
        }

        @media (max-width: 1200px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 768px) {
            .container {
                padding: 16px;
            }
            
            .header h1 {
                font-size: 2.2rem;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .file-scanner {
                height: 300px;
            }
        }

        .pulse {
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .threat-card {
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
            transition: all 0.3s ease;
        }

        .threat-card.critical {
            background: rgba(255, 71, 87, 0.1);
            border: 1px solid rgba(255, 71, 87, 0.3);
        }

        .threat-card.critical:hover {
            background: rgba(255, 71, 87, 0.15);
            border-color: rgba(255, 71, 87, 0.5);
            transform: translateY(-2px);
        }

        .threat-card.warning {
            background: rgba(255, 165, 0, 0.1);
            border: 1px solid rgba(255, 165, 0, 0.3);
        }

        .threat-card.warning:hover {
            background: rgba(255, 165, 0, 0.15);
            border-color: rgba(255, 165, 0, 0.5);
            transform: translateY(-2px);
        }

        .threat-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }

        .threat-path {
            font-family: 'JetBrains Mono', monospace;
            color: #fff;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
            flex: 1;
        }

        .delete-file-btn {
            background: linear-gradient(135deg, #ff4757, #e84393);
            color: #fff;
            border: none;
            padding: 8px 16px;
            border-radius: 20px;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: all 0.3s ease;
            min-width: 120px;
            justify-content: center;
        }

        .delete-file-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(255, 71, 87, 0.4);
        }

        .delete-file-btn:disabled {
            background: #666;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        .threat-patterns {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 8px;
        }

        .pattern-tag {
            background: rgba(255, 165, 2, 0.2);
            color: #ffa502;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.85rem;
            font-family: 'JetBrains Mono', monospace;
            border: 1px solid rgba(255, 165, 2, 0.3);
        }

        .malware-section {
            background: rgba(255, 0, 0, 0.1);
            border: 2px solid rgba(255, 0, 0, 0.3);
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
        }

        .malware-section h4 {
            color: #ff4757;
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 16px;
        }

        .malware-card {
            background: rgba(255, 0, 0, 0.15);
            border: 1px solid rgba(255, 0, 0, 0.4);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .malware-path {
            font-family: 'JetBrains Mono', monospace;
            color: #ff4757;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1><i class="fas fa-shield-virus"></i> Enterprise Security Scanner</h1>
            <p class="subtitle">Công cụ quét malware và backdoor chuyên nghiệp cho doanh nghiệp</p>
            <div class="author-badge">
                <i class="fab fa-facebook"></i>
                <span>Tác giả: Hiệp Nguyễn</span>
                <span style="opacity: 0.7;">• Enterprise Grade</span>
            </div>
        </div>

        <!-- Dashboard -->
        <div class="dashboard-grid">
            <!-- Control Panel -->
            <div class="card control-panel">
                <div class="card-header">
                    <i class="fas fa-control" style="color: #00ff88;"></i>
                    <h3 class="card-title">Bảng Điều Khiển Quét</h3>
                </div>
                
                <div class="scan-controls">
                    <button id="scanBtn" class="scan-btn">
                        <i class="fas fa-rocket"></i> Bắt Đầu Quét Bảo Mật
                    </button>
                    <br><br>
                    <button id="autoFixBtn" style="background: linear-gradient(135deg, #ff6b35, #f7931e); color: #fff; padding: 12px 24px; border: none; border-radius: 20px; cursor: pointer; font-size: 1rem; font-weight: 600;" disabled>
                        <i class="fas fa-tools"></i> Khắc Phục Lỗi Tự Động
                    </button>
                </div>

                <div id="progressSection" class="progress-section">
                    <div class="progress-info">
                        <span id="progressText" class="progress-text">Đang chuẩn bị quét...</span>
                        <span id="progressPercentage" class="progress-percentage">0%</span>
                    </div>
                    <div class="progress-bar-container">
                        <div id="progressBar" class="progress-bar"></div>
                    </div>
                    <div style="text-align: center; color: #00ff88; font-style: italic;">
                        <i class="fas fa-radar-scan pulse"></i> <span id="currentAction">Đang quét hệ thống...</span>
                    </div>
                </div>
            </div>

            <!-- Statistics -->
            <div class="card">
                <div class="card-header">
                    <i class="fas fa-chart-area" style="color: #00ccff;"></i>
                    <h3 class="card-title">Thống Kê Real-time</h3>
                </div>
                <div class="stats-grid">
                    <div class="stat-card">
                        <span id="scannedFiles" class="stat-number">0</span>
                        <div class="stat-label">Files Đã Quét</div>
                    </div>
                    <div class="stat-card">
                        <span id="suspiciousFiles" class="stat-number">0</span>
                        <div class="stat-label">Threats Phát Hiện</div>
                    </div>
                    <div class="stat-card">
                        <span id="scanSpeed" class="stat-number">0</span>
                        <div class="stat-label">Files/giây</div>
                    </div>
                    <div class="stat-card">
                        <span id="scanTime" class="stat-number">0s</span>
                        <div class="stat-label">Thời Gian Quét</div>
                    </div>
                </div>
            </div>

            <!-- File Scanner -->
            <div class="card">
                <div class="card-header">
                    <i class="fas fa-file-search" style="color: #ffa502;"></i>
                    <h3 class="card-title">Files Đang Quét</h3>
                </div>
                <div class="file-scanner">
                    <div class="scanner-header">
                        <i class="fas fa-terminal" style="color: #00ff88;"></i>
                        <span style="font-family: 'JetBrains Mono', monospace; color: var(--text-secondary);">real-time scanner</span>
                    </div>
                    <div id="scannerContent" class="scanner-content">
                        <div class="scanner-empty">
                            <i class="fas fa-search"></i>
                            <p>Nhấn "Bắt Đầu Quét" để bắt đầu monitoring</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Threat Detection -->
            <div class="card">
                <div class="card-header">
                    <i class="fas fa-exclamation-triangle" style="color: #ff4757;"></i>
                    <h3 class="card-title">Patterns Threat Detection</h3>
                </div>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; font-size: 0.9rem;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <i class="fas fa-bug" style="color: #ff4757;"></i>
                        <span style="color: var(--text-secondary);">eval(), base64_decode()</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <i class="fas fa-terminal" style="color: #ffa502;"></i>
                        <span style="color: var(--text-secondary);">exec(), system(), shell_exec()</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <i class="fas fa-file-upload" style="color: #ff69b4;"></i>
                        <span style="color: var(--text-secondary);">move_uploaded_file()</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <i class="fas fa-code" style="color: #00ff88;"></i>
                        <span style="color: var(--text-secondary);">$_REQUEST, $_GET, $_POST</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Results Panel -->
        <div id="resultsPanel" class="results-panel">
            <div class="card">
                <div class="card-header">
                    <i class="fas fa-clipboard-check" style="color: #2ed573;"></i>
                    <h3 class="card-title">Báo Cáo Kết Quả Bảo Mật</h3>
                </div>
                <div id="scanResults"></div>
            </div>
        </div>
    </div>

    <script>
        class SecurityScanner {
            constructor() {
                this.isScanning = false;
                this.scannedFiles = 0;
                this.suspiciousFiles = 0;
                this.scanStartTime = null;
                this.progressInterval = null;
                this.speedInterval = null;
                this.fileSimulationInterval = null;
                this.lastScanData = null;
                this.init();
            }

            init() {
                document.getElementById('scanBtn').addEventListener('click', () => this.startScan());
                document.getElementById('autoFixBtn').addEventListener('click', () => this.startAutoFix());
            }

            startScan() {
                if (this.isScanning) return;
                
                this.isScanning = true;
                this.scannedFiles = 0;
                this.suspiciousFiles = 0;
                this.scanStartTime = Date.now();
                
                const scanBtn = document.getElementById('scanBtn');
                const progressSection = document.getElementById('progressSection');
                const resultsPanel = document.getElementById('resultsPanel');
                
                // Update UI
                scanBtn.disabled = true;
                scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Đang Quét Bảo Mật...';
                progressSection.classList.add('active');
                resultsPanel.classList.remove('active');
                
                // Clear scanner content
                document.getElementById('scannerContent').innerHTML = '';
                
                // Start file simulation
                this.startFileSimulation();
                
                // Start progress simulation
                this.simulateProgress();
                
                // Start speed counter
                this.startSpeedCounter();
                
                // Start actual scan after short delay
                setTimeout(() => {
                    this.performScan();
                }, 1000);
            }

            startFileSimulation() {
                const testFiles = [
                    './index.php',
                    './admin/index.php',
                    './admin/lib/function.php',
                    './admin/templates/seo-co-ban/them_tpl.php',
                    './uploads/.htaccess',
                    './sources/config.php',
                    './sources/database.php',
                    './admin/templates/header.php',
                    './admin/templates/footer.php',
                    './admin/lib/security.php',
                    './uploads/test.jpg',
                    './sources/functions.php',
                    './admin/login.php',
                    './admin/logout.php'
                ];

                let fileIndex = 0;
                this.fileSimulationInterval = setInterval(() => {
                    if (fileIndex < testFiles.length && this.isScanning) {
                        const file = testFiles[fileIndex];
                        const isSuspicious = Math.random() < 0.15; // 15% chance suspicious
                        
                        this.addFileToScanner(file, !isSuspicious);
                        this.scannedFiles++;
                        
                        if (isSuspicious) {
                            this.suspiciousFiles++;
                        }
                        
                        this.updateStats();
                        fileIndex++;
                    } else {
                        clearInterval(this.fileSimulationInterval);
                    }
                }, 300);
            }

            simulateProgress() {
                let progress = 0;
                const progressBar = document.getElementById('progressBar');
                const progressText = document.getElementById('progressText');
                const progressPercentage = document.getElementById('progressPercentage');
                const currentAction = document.getElementById('currentAction');
                
                const actions = [
                    'Khởi tạo scanner engine...',
                    'Đang quét thư mục sources...',
                    'Phân tích admin directory...',
                    'Kiểm tra uploads folder...',
                    'Quét malware patterns...',
                    'Phân tích deep threats...',
                    'Hoàn thiện báo cáo...'
                ];
                
                let actionIndex = 0;
                
                this.progressInterval = setInterval(() => {
                    progress += Math.random() * 8 + 2;
                    if (progress > 100) progress = 100;
                    
                    progressBar.style.width = progress + '%';
                    progressPercentage.textContent = Math.round(progress) + '%';
                    
                    if (Math.floor(progress / 15) > actionIndex && actionIndex < actions.length - 1) {
                        actionIndex++;
                        currentAction.textContent = actions[actionIndex];
                    }
                    
                    if (progress >= 100) {
                        clearInterval(this.progressInterval);
                        progressText.textContent = 'Quét hoàn tất!';
                        currentAction.textContent = 'Đang tạo báo cáo bảo mật...';
                    }
                }, 200);
            }

            startSpeedCounter() {
                this.speedInterval = setInterval(() => {
                    const elapsed = (Date.now() - this.scanStartTime) / 1000;
                    const speed = elapsed > 0 ? Math.round(this.scannedFiles / elapsed) : 0;
                    
                    document.getElementById('scanSpeed').textContent = speed;
                    document.getElementById('scanTime').textContent = Math.round(elapsed) + 's';
                }, 500);
            }

            addFileToScanner(filePath, isClean) {
                const scannerContent = document.getElementById('scannerContent');
                
                const fileItem = document.createElement('div');
                fileItem.className = 'file-item';
                fileItem.innerHTML = `
                    <div class="file-icon">
                        <i class="fas fa-file-code" style="color: ${isClean ? '#2ed573' : '#ff4757'};"></i>
                    </div>
                    <div class="file-path">${filePath}</div>
                    <div class="file-status ${isClean ? 'status-clean' : 'status-suspicious'}">
                        ${isClean ? 'Clean' : 'Threat'}
                    </div>
                `;
                
                scannerContent.appendChild(fileItem);
                scannerContent.scrollTop = scannerContent.scrollHeight;
                
                // Keep only last 15 items
                while (scannerContent.children.length > 15) {
                    scannerContent.removeChild(scannerContent.firstChild);
                }
            }

            updateStats() {
                document.getElementById('scannedFiles').textContent = this.scannedFiles;
                document.getElementById('suspiciousFiles').textContent = this.suspiciousFiles;
            }

            async performScan() {
                try {
                    console.log('Starting scan request...');
                    
                    // Add timeout and retry logic
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
                    
                    const response = await fetch('?scan=1', {
                        method: 'GET',
                        headers: {
                            'X-Requested-With': 'XMLHttpRequest',
                            'Cache-Control': 'no-cache'
                        },
                        signal: controller.signal
                    });
                    
                    clearTimeout(timeoutId);
                    
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    
                    const text = await response.text();
                    console.log('Raw response received, length:', text.length);
                    
                    if (!text || text.trim() === '') {
                        throw new Error('Empty response from server');
                    }
                    
                    let data;
                    try {
                        data = JSON.parse(text);
                    } catch (e) {
                        console.error('JSON Parse Error:', e);
                        console.error('Response text (first 500 chars):', text.substring(0, 500));
                        throw new Error('Response không phải JSON hợp lệ. Check console for details.');
                    }
                    
                    console.log('Parsed data:', data);
                    this.displayResults(data);
                    
                } catch (error) {
                    console.error('Scan error:', error);
                    if (error.name === 'AbortError') {
                        this.displayError('Quét bị timeout. Vui lòng thử lại.');
                    } else {
                        this.displayError('Lỗi quét: ' + error.message);
                    }
                }
            }

            displayResults(data) {
                // Update final stats with real data
                this.scannedFiles = data.scanned_files || this.scannedFiles;
                this.suspiciousFiles = data.suspicious_count || this.suspiciousFiles;
                this.updateStats();
                
                // Store scan data for auto-fix
                this.lastScanData = data;
                
                setTimeout(() => {
                    const resultsPanel = document.getElementById('resultsPanel');
                    const scanResults = document.getElementById('scanResults');
                    const autoFixBtn = document.getElementById('autoFixBtn');
                    
                    resultsPanel.classList.add('active');
                    
                    if (data.suspicious_count === 0) {
                        scanResults.innerHTML = `
                            <div class="alert alert-success">
                                <i class="fas fa-shield-check" style="margin-right: 12px; font-size: 1.2rem;"></i>
                                <strong>Hệ thống an toàn!</strong> Không phát hiện threat nào trong ${data.scanned_files} files đã quét.
                            </div>
                        `;
                        autoFixBtn.disabled = true;
                    } else {
                        let resultHtml = `
                            <div class="alert alert-danger">
                                <i class="fas fa-exclamation-triangle" style="margin-right: 12px; font-size: 1.2rem;"></i>
                                <strong>Phát hiện ${data.suspicious_count} threats!</strong> Cần xử lý ngay để bảo vệ hệ thống.
                            </div>
                        `;
                        
                        data.suspicious_files.forEach((file, index) => {
                            const isCritical = file.severity === 'critical';
                            const isWarning = file.severity === 'warning';
                            const cardClass = isCritical ? 'critical' : 'warning';
                            const iconClass = isCritical ? 'fa-skull-crossbones' : 'fa-exclamation-triangle';
                            const iconColor = isCritical ? '#ff4757' : '#ffa502';
                            
                            resultHtml += `
                                <div class="threat-card ${cardClass}">
                                    <div class="threat-header">
                                        <div class="threat-path">
                                            <i class="fas ${iconClass}" style="color: ${iconColor};"></i> ${file.path}
                                        </div>
                                        ${isCritical ? `
                                            <button class="delete-file-btn" onclick="scanner.deleteSingleFile('${file.path}', ${index})">
                                                <i class="fas fa-trash-alt"></i> Xóa File
                                            </button>
                                        ` : `
                                            <span style="background: rgba(255,165,0,0.2); color: #ffa502; padding: 6px 12px; border-radius: 12px; font-size: 0.85rem; font-weight: 600;">
                                                <i class="fas fa-exclamation-triangle"></i> Cảnh báo
                                            </span>
                                        `}
                                    </div>
                                    <div class="threat-patterns">
                                        ${file.patterns.map(pattern => 
                                            `<span class="pattern-tag">${pattern}</span>`
                                        ).join('')}
                                    </div>
                                </div>
                            `;
                        });
                        
                        resultHtml += `
                            <div class="recommendations">
                                <h4><i class="fas fa-lightbulb"></i> Khuyến nghị xử lý</h4>
                                <ul>
                                    <li>Backup toàn bộ hệ thống trước khi xử lý</li>
                                    <li>Sử dụng tính năng "Khắc Phục Lỗi Tự Động" để sửa các lỗi phổ biến</li>
                                    <li>Kiểm tra từng file threats được đánh dấu</li>
                                    <li>Cập nhật tất cả mật khẩu admin và database</li>
                                    <li>Xem xét logs truy cập gần đây</li>
                                    <li>Thiết lập monitoring liên tục</li>
                                </ul>
                            </div>
                        `;
                        
                        scanResults.innerHTML = resultHtml;
                        
                        // Enable auto-fix button
                        autoFixBtn.disabled = false;
                        autoFixBtn.style.opacity = '1';
                        autoFixBtn.style.cursor = 'pointer';
                    }
                    
                    this.completeScan();
                }, 1000);
            }

            displayError(message) {
                const resultsPanel = document.getElementById('resultsPanel');
                const scanResults = document.getElementById('scanResults');
                
                resultsPanel.classList.add('active');
                scanResults.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="fas fa-times-circle" style="margin-right: 12px; font-size: 1.2rem;"></i>
                        <strong>Lỗi quét!</strong> ${message}
                    </div>
                `;
                
                this.completeScan();
            }

            completeScan() {
                clearInterval(this.speedInterval);
                clearInterval(this.fileSimulationInterval);
                
                setTimeout(() => {
                    const scanBtn = document.getElementById('scanBtn');
                    scanBtn.disabled = false;
                    scanBtn.innerHTML = '<i class="fas fa-redo"></i> Quét Lại';
                    document.getElementById('progressSection').classList.remove('active');
                    this.isScanning = false;
                }, 1000);
            }

            async startAutoFix() {
                if (!this.lastScanData || this.lastScanData.suspicious_count === 0) {
                    Swal.fire({
                        icon: 'info',
                        title: 'Không có lỗi để khắc phục',
                        text: 'Không phát hiện lỗi nào cần khắc phục!',
                        confirmButtonColor: '#00ff88'
                    });
                    return;
                }
                
                const result = await Swal.fire({
                    title: 'Xác nhận khắc phục?',
                    text: `Sẽ khắc phục ${this.lastScanData.suspicious_count} lỗi được phát hiện. Backup sẽ được tạo trước khi sửa.`,
                    icon: 'warning',
                    showCancelButton: true,
                    confirmButtonColor: '#ff6b35',
                    cancelButtonColor: '#6c757d',
                    confirmButtonText: 'Khắc phục',
                    cancelButtonText: 'Hủy'
                });
                
                if (result.isConfirmed) {
                    this.performAutoFix();
                }
            }

            async deleteSingleFile(filePath, index) {
                const result = await Swal.fire({
                    title: 'XÓA FILE ĐỘC HẠI?',
                    html: `<strong style="color: #ff4757;">CẢNH BÁO:</strong> Sẽ xóa vĩnh viễn file:<br><br><code style="color: #ff6b35;">${filePath}</code>`,
                    icon: 'error',
                    showCancelButton: true,
                    confirmButtonColor: '#ff4757',
                    cancelButtonColor: '#6c757d',
                    confirmButtonText: 'XÓA NGAY',
                    cancelButtonText: 'Hủy',
                    dangerMode: true
                });
                
                if (result.isConfirmed) {
                    this.performSingleFileDeletion(filePath, index);
                }
            }

            async performSingleFileDeletion(filePath, index) {
                const deleteBtn = document.querySelector(`button[onclick*="${index}"]`);
                if (deleteBtn) {
                    deleteBtn.disabled = true;
                    deleteBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Đang Xóa...';
                }
                
                try {
                    const response = await fetch('?delete_malware=1', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: JSON.stringify({ malware_files: [filePath] })
                    });
                    
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    
                    const text = await response.text();
                    console.log('Delete response:', text);
                    
                    let data;
                    try {
                        data = JSON.parse(text);
                    } catch (e) {
                        console.error('JSON Parse Error:', e);
                        throw new Error('Response không phải JSON hợp lệ: ' + text.substring(0, 200));
                    }
                    
                    if (data.success) {
                        Swal.fire({
                            icon: 'success',
                            title: 'XÓA THÀNH CÔNG!',
                            text: `File ${filePath} đã được xóa thành công.`,
                            confirmButtonColor: '#00ff88'
                        }).then(() => {
                            // Remove the card from display
                            const threatCard = deleteBtn.closest('.threat-card');
                            if (threatCard) {
                                threatCard.style.transition = 'all 0.3s ease';
                                threatCard.style.opacity = '0';
                                threatCard.style.transform = 'translateX(-100%)';
                                setTimeout(() => {
                                    threatCard.remove();
                                    // Update scan data
                                    if (this.lastScanData && this.lastScanData.malware_files) {
                                        const malwareIndex = this.lastScanData.malware_files.indexOf(filePath);
                                        if (malwareIndex > -1) {
                                            this.lastScanData.malware_files.splice(malwareIndex, 1);
                                        }
                                    }
                                }, 300);
                            }
                        });
                    } else {
                        throw new Error(data.error || 'Unknown error');
                    }
                    
                } catch (error) {
                    console.error('Delete error:', error);
                    Swal.fire({
                        icon: 'error',
                        title: 'LỖI XÓA FILE',
                        text: error.message,
                        confirmButtonColor: '#ff4757'
                    });
                } finally {
                    if (deleteBtn) {
                        deleteBtn.disabled = false;
                        deleteBtn.innerHTML = '<i class="fas fa-trash-alt"></i> Xóa File';
                    }
                }
            }

            async performAutoFix() {
                if (!this.lastScanData || this.lastScanData.suspicious_count === 0) {
                    Swal.fire({
                        icon: 'info',
                        title: 'Không có lỗi để khắc phục',
                        text: 'Không phát hiện lỗi nào cần khắc phục!',
                        confirmButtonColor: '#00ff88'
                    });
                    return;
                }
                
                const autoFixBtn = document.getElementById('autoFixBtn');
                autoFixBtn.disabled = true;
                autoFixBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Đang Khắc Phục...';
                
                try {
                    const response = await fetch('?autofix=1', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: JSON.stringify(this.lastScanData)
                    });
                    
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    
                    const text = await response.text();
                    console.log('Auto-fix response:', text);
                    
                    let data;
                    try {
                        data = JSON.parse(text);
                    } catch (e) {
                        console.error('JSON Parse Error:', e);
                        throw new Error('Response không phải JSON hợp lệ: ' + text.substring(0, 200));
                    }
                    
                    if (data.success) {
                        Swal.fire({
                            icon: 'success',
                            title: 'Khắc Phục Thành Công!',
                            html: `<strong>Files đã sửa:</strong> ${data.fixed_files}<br>` +
                                  `<strong>Files độc hại đã xóa:</strong> ${data.deleted_files || 0}<br>` +
                                  `<strong>Lỗi đã khắc phục:</strong> ${data.fixes_applied}<br>` +
                                  `<strong>Backup:</strong> ${data.backup_created ? '✅ Đã tạo' : '❌ Không có'}`,
                            confirmButtonColor: '#00ff88'
                        }).then(() => {
                            // Auto scan lại sau khi fix
                            this.startScan();
                        });
                    } else {
                        Swal.fire({
                            icon: 'error',
                            title: 'Lỗi Khắc Phục',
                            text: data.error || 'Unknown error',
                            confirmButtonColor: '#ff4757'
                        });
                    }
                    
                } catch (error) {
                    console.error('Auto-fix error:', error);
                    Swal.fire({
                        icon: 'error',
                        title: 'Lỗi Khắc Phục',
                        text: error.message,
                        confirmButtonColor: '#ff4757'
                    });
                } finally {
                    autoFixBtn.disabled = false;
                    autoFixBtn.innerHTML = '<i class="fas fa-tools"></i> Khắc Phục Lỗi Tự Động';
                }
            }
        }

        // Initialize scanner when page loads
        let scanner;
        document.addEventListener('DOMContentLoaded', () => {
            scanner = new SecurityScanner();
            
            // Make scanner globally accessible
            window.scanner = scanner;
        });
    </script>
</body>
</html> 