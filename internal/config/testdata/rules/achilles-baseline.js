// Tests for the JavaScript rules in configs/rules/achilles-baseline.yaml (opengrep --test).
function calc(expr) {
  // ruleid: achilles.javascript.dangerous-eval
  const a = eval(expr);
  // ok: achilles.javascript.dangerous-eval
  const b = JSON.parse(expr);
  return [a, b];
}
