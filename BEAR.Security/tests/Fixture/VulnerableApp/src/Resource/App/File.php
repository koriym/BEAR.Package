<?php

declare(strict_types=1);

namespace MyVendor\VulnerableApp\Resource\App;

use BEAR\Resource\ResourceObject;

/**
 * Path Traversal and RFI vulnerabilities
 */
class File extends ResourceObject
{
    /**
     * VULNERABILITY: Path Traversal (A01)
     * Detectable by: SAST PathTraversalDetector
     */
    public function onGet(string $path): static
    {
        // BAD: No path validation
        $content = file_get_contents('/var/data/' . $_GET['path']);
        $this->body = ['content' => $content];

        return $this;
    }

    /**
     * VULNERABILITY: Remote File Inclusion / SSRF (A10)
     * Detectable by: SAST RemoteFileInclusionDetector
     */
    public function onPost(string $url): static
    {
        // BAD: Fetching arbitrary URL
        $data = file_get_contents($_POST['url']);
        $this->body = ['data' => $data];

        return $this;
    }
}
