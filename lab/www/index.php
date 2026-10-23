<?php
// Deliberately disclose runtime version for this isolated, non-exploit demonstration.
header('X-Powered-By: PHP/' . PHP_VERSION);
header('Content-Type: text/plain; charset=utf-8');
echo "PHP2Shell checker lab\n";
echo "PHP version: " . PHP_VERSION . "\n";
echo "This endpoint does not process uploads or execute commands.\n";
