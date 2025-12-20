<?php

declare(strict_types=1);

namespace BEAR\Security\Ai;

use BEAR\Security\Vulnerability;
use RuntimeException;

use function array_map;
use function count;
use function curl_close;
use function curl_exec;
use function curl_init;
use function curl_setopt;
use function getenv;
use function is_string;
use function json_decode;
use function json_encode;

use const CURLOPT_HTTPHEADER;
use const CURLOPT_POST;
use const CURLOPT_POSTFIELDS;
use const CURLOPT_RETURNTRANSFER;
use const CURLOPT_URL;
use const JSON_THROW_ON_ERROR;

/**
 * Claude API-based security auditor
 */
final class ClaudeAuditor implements AuditorInterface
{
    private const API_URL = 'https://api.anthropic.com/v1/messages';
    private const MODEL = 'claude-sonnet-4-20250514';
    private const MAX_TOKENS = 8192;

    private string $apiKey;
    private PromptBuilder $promptBuilder;
    private FileCollector $fileCollector;
    private TokenTracker $tokenTracker;

    public function __construct(?string $apiKey = null)
    {
        $key = $apiKey ?? getenv('ANTHROPIC_API_KEY');
        if (! is_string($key) || $key === '') {
            throw new RuntimeException('ANTHROPIC_API_KEY environment variable is required');
        }

        $this->apiKey = $key;
        $this->promptBuilder = new PromptBuilder();
        $this->fileCollector = new FileCollector();
        $this->tokenTracker = new TokenTracker();
    }

    public function audit(string $projectPath): AuditResult
    {
        $files = $this->fileCollector->collect($projectPath);
        $prompt = $this->promptBuilder->build($files);

        $response = $this->callApi($prompt);
        $parsed = $this->promptBuilder->parseResponse($response['content']);

        $vulnerabilities = array_map(
            static fn (array $v) => new Vulnerability(
                $v['type'],
                $v['severity'],
                $v['file'],
                $v['line'],
                $v['description'],
                $v['code'] ?? '',
                '',
            ),
            $parsed['vulnerabilities'],
        );

        $filesAnalyzed = [];
        foreach ($files as $path => $content) {
            $filesAnalyzed[$path] = 'analyzed';
        }

        return new AuditResult(
            $vulnerabilities,
            $this->tokenTracker,
            $filesAnalyzed,
            [],
        );
    }

    /**
     * @return array{content: string, input_tokens: int, output_tokens: int}
     */
    private function callApi(string $prompt): array
    {
        $payload = [
            'model' => self::MODEL,
            'max_tokens' => self::MAX_TOKENS,
            'messages' => [
                ['role' => 'user', 'content' => $prompt],
            ],
        ];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, self::API_URL);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload, JSON_THROW_ON_ERROR));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'x-api-key: ' . $this->apiKey,
            'anthropic-version: 2023-06-01',
        ]);

        $response = curl_exec($ch);
        curl_close($ch);

        if (! is_string($response)) {
            throw new RuntimeException('API request failed');
        }

        /** @var array{content: array<array{text: string}>, usage: array{input_tokens: int, output_tokens: int}} $data */
        $data = json_decode($response, true, 512, JSON_THROW_ON_ERROR);

        $inputTokens = $data['usage']['input_tokens'] ?? 0;
        $outputTokens = $data['usage']['output_tokens'] ?? 0;

        $this->tokenTracker->record('api_call', $inputTokens, $outputTokens);

        return [
            'content' => $data['content'][0]['text'] ?? '',
            'input_tokens' => $inputTokens,
            'output_tokens' => $outputTokens,
        ];
    }
}
