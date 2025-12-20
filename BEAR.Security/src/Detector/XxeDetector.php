<?php

declare(strict_types=1);

namespace BEAR\Security\Detector;

/**
 * Detects XML External Entity (XXE) vulnerabilities
 */
final class XxeDetector extends AbstractDetector
{
    /** @var array<string, array{pattern: string, severity: string, description: string, recommendation: string}> */
    protected array $patterns = [
        'XXE_SIMPLEXML_USER_INPUT' => [
            'pattern' => '/simplexml_load_string\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i',
            'severity' => 'CRITICAL',
            'description' => 'XXE vulnerability - parsing user-controlled XML with simplexml_load_string',
            'recommendation' => 'Disable external entities: libxml_disable_entity_loader(true) or use LIBXML_NOENT',
        ],
        'XXE_SIMPLEXML_VAR' => [
            'pattern' => '/simplexml_load_string\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)/i',
            'severity' => 'MEDIUM',
            'description' => 'Potential XXE - simplexml_load_string with variable input',
            'recommendation' => 'Disable external entities before parsing XML from untrusted sources',
        ],
        'XXE_DOMDOCUMENT_LOAD' => [
            'pattern' => '/\$[a-zA-Z_][a-zA-Z0-9_]*\s*->\s*load(XML|HTML)\s*\(\s*\$_(GET|POST|REQUEST)/i',
            'severity' => 'CRITICAL',
            'description' => 'XXE vulnerability - DOMDocument loading user-controlled XML',
            'recommendation' => 'Use $doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD) to disable entities',
        ],
        'XXE_XMLREADER' => [
            'pattern' => '/XMLReader::open\s*\(\s*\$_(GET|POST|REQUEST)/i',
            'severity' => 'CRITICAL',
            'description' => 'XXE vulnerability - XMLReader with user-controlled input',
            'recommendation' => 'Disable external entities before parsing',
        ],
        'XXE_ENTITY_LOADER_ENABLED' => [
            'pattern' => '/libxml_disable_entity_loader\s*\(\s*false\s*\)/i',
            'severity' => 'HIGH',
            'description' => 'External entity loader explicitly enabled - XXE risk',
            'recommendation' => 'Keep entity loader disabled: libxml_disable_entity_loader(true)',
        ],
    ];

    public function getName(): string
    {
        return 'XxeDetector';
    }
}
