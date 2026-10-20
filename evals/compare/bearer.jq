{runs: [{tool: {driver: {name: "bearer", rules: []}},
  results: [.[][] | {ruleId: .id,
    locations: [{physicalLocation: {artifactLocation: {uri: .filename}}}],
    properties: {cwe: [.cwe_ids[] | "CWE-" + .]}}]}]}
