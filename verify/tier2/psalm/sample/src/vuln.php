<?php

// Known-vulnerable sample for the Tier-2 verification harness.
// Psalm --taint-analysis should report TaintedSql: $_GET (taint source) flows
// unsanitized into mysqli::query (SQL sink).
function handle(mysqli $db): void
{
    $id = $_GET['id'];
    $db->query("SELECT * FROM users WHERE id = " . $id);
}
