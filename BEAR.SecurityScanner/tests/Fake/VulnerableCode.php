<?php

declare(strict_types=1);

namespace BEAR\SecurityScanner\Fake;

/**
 * This file contains intentionally vulnerable code for testing the security scanner
 * DO NOT use this code in production!
 */
class VulnerableCode
{
    // SQL Injection vulnerabilities
    public function sqlInjectionDirect(): void
    {
        // Direct use of user input in SQL query
        $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
    }

    public function sqlInjectionConcat(): void
    {
        // Concatenated user input in SQL
        $pdo = new \PDO('sqlite::memory:');
        $pdo->query("SELECT * FROM users WHERE name = '" . $_POST['name'] . "'");
    }

    // XSS vulnerabilities
    public function xssDirectOutput(): void
    {
        // Direct output of user input
        echo $_GET['message'];
    }

    public function xssShortTag(): string
    {
        // Short echo tag with user input (simulated)
        return '<?= $_GET["name"] ?>';
    }

    // Command Injection vulnerabilities
    public function commandInjectionExec(): void
    {
        // Direct use of user input in exec
        exec("ls " . $_GET['path']);
    }

    public function commandInjectionBacktick(): void
    {
        // Backtick with user input
        $output = `cat $_POST[file]`;
    }

    // Path Traversal vulnerabilities
    public function pathTraversalInclude(): void
    {
        // User input in include
        include($_GET['page']);
    }

    public function pathTraversalFileOps(): void
    {
        // User input in file operations
        $content = file_get_contents($_POST['file']);
    }

    // Dangerous functions
    public function dangerousEval(): void
    {
        // Eval with user input
        eval($_POST['code']);
    }

    public function dangerousUnserialize(): void
    {
        // Unserialize without allowed_classes
        $data = unserialize($_COOKIE['data']);
    }

    // Session vulnerabilities
    public function sessionFixation(): void
    {
        // Session ID from user input
        session_id($_GET['session_id']);
    }

    // Remote File Inclusion vulnerabilities
    public function rfiIncludeUserInput(): void
    {
        // User input directly in include - RFI/LFI vulnerability
        include($_GET['template']);
    }

    public function rfiRequireUserInput(): void
    {
        // User input in require
        require($_REQUEST['module']);
    }

    public function rfiFileGetContentsUrl(): void
    {
        // User-controlled URL in file_get_contents - SSRF/RFI
        $content = file_get_contents($_GET['url']);
    }
}
