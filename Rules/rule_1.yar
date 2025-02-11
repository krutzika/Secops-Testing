rule ZeroValueFunctionPlaceholder {
  meta:
    rule_id = "ZVFP-001"
    description = "Detects zero-value function placeholders in event data"
  events:
    // Even though $ph is used in the match section, there is no
    // implicit filtering of zero values for $ph, because $ph is assigned to a function.
    $ph = re.capture($e.principal.hostname, "some-regex")

  match:
    $ph over 5m

  condition:
    $e
}
