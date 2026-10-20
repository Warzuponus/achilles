{runs: [{tool: {driver: {name: "bandit", rules: []}},
  results: [.results[] | {ruleId: .test_id,
    locations: [{physicalLocation: {artifactLocation: {uri: .filename}}}],
    properties: {cwe: ["CWE-\(.issue_cwe.id)"]}}]}]}
