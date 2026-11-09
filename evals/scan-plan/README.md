# Scan plan check on real repositories

Does the scan plan (`--plan-out`, `--profile full`) skip a scanner that had
something to find? Checked on 2026-11-09 against 19 open-source repositories, by
comparing what the plan skipped with what each skipped scanner reports when it is
run anyway (the `--all-tools` run). No model call is needed for any of it.

## Method

1. Shallow-clone each repository at its default branch.
2. Run `achilles --profile full --plan-out plan.json <repo>` and read the
   `scan plan skips` lines.
3. For every skip, run that scanner directly on the repository, the way
   `configs/tools.yaml` runs it, and look at what it reports.

Scanners used for step 3: Checkov 3.2.533 (pip), Bandit 1.9.4 (pip),
Find Security Bugs CLI 1.14.0, Psalm 5.26.1. A skip is wrong when the scanner
reports something in the project's own code or configuration.

## Repositories

| Language | Repositories |
|---|---|
| Go | gin-gonic/gin, go-gitea/gitea, kubernetes/kube-state-metrics, hashicorp/terraform-provider-aws |
| Python | pallets/flask, we45/Vulnerable-Flask-App |
| JavaScript / TypeScript | juice-shop/juice-shop |
| Java | WebGoat/WebGoat, spring-projects/spring-petclinic |
| PHP | digininja/DVWA, nextcloud/server, sebastianbergmann/phpunit |
| Ruby | OWASP/railsgoat, rails/rails, mastodon/mastodon |
| C# | jerryhoff/WebGoat.NET, dotnet/eShop |
| C | madler/zlib |
| Terraform | bridgecrewio/terragoat |

No map was truncated, including the largest (gitea, nextcloud/server, rails,
terraform-provider-aws), so the plan made every decision it could.

## Results

| Repository | Skipped | Run anyway | Verdict |
|---|---|---|---|
| gin | Checkov | 1 finding: CKV2_GHA_1 (workflow without top-level read-only permissions) in `.github/workflows/codeql.yml` | **wrong skip, fixed** |
| zlib | Checkov | 6 findings: CKV2_GHA_1 in six workflows | **wrong skip, fixed** |
| flask | Checkov | 0 findings, but it audited the workflows | wrong skip (had input), fixed |
| phpunit | Checkov | 0 findings, but it audited the workflows | wrong skip (had input), fixed |
| WebGoat.NET | Checkov | 0 findings, nothing to read | right |
| DVWA | Psalm | cannot run: Achilles passes `--config=<root>/psalm.xml` and there is none | right |
| phpunit | Psalm | cannot run, same reason | right |
| DVWA | Bandit | 1 finding: B101 `assert` in `tests/test_url.py` (the only Python file) | right (test-only) |
| juice-shop | Bandit | 0 findings (Python only under `test/files/`) | right |
| WebGoat | FindSecBugs | 14 findings, all in `.mvn/wrapper/maven-wrapper.jar` | right (Maven's wrapper, not the project) |
| spring-petclinic | FindSecBugs | 15 findings, all in `gradle/wrapper/gradle-wrapper.jar` | right (Gradle's wrapper) |
| terraform-provider-aws | FindSecBugs | 535 findings, all in a test-fixture jar of Apache Flink, Commons and Guava | right (third-party test fixture) |

Every other repository had no skip.

## The miss and the fix

Checkov's only precondition was an infrastructure-as-code file, but Checkov also
audits CI pipelines (GitHub Actions, GitLab CI, Azure Pipelines, Bitbucket
Pipelines, CircleCI) and OpenAPI documents. A repository with workflows and no
IaC lost those findings. An OpenAPI document from nextcloud/server, scanned on its
own, gives CKV_OPENAPI_3, CKV_OPENAPI_4 and CKV_OPENAPI_21, so it counts too.

The plan now keeps Checkov when any of these is present: IaC (also `.tf.json`, and
Dockerfiles or Terraform inside build directories such as `build/package/`), a
GitHub workflow, another CI pipeline Checkov audits (not a Jenkinsfile, which it has
no checks for), or an OpenAPI/Swagger document. Re-run with the fix, gin, zlib,
flask and phpunit keep Checkov and every other decision is unchanged. Covered by
`TestDecideTools_CheckovInputs` in `cmd/achilles/toolplan_test.go`.

## Not changed, worth knowing

- **Psalm** only runs with `psalm.xml` at the root. Many PHP projects commit
  `psalm.xml.dist` instead; Psalm itself reads that, but Achilles' arguments do
  not, so the plan is right to skip it. Teaching the Psalm invocation about
  `psalm.xml.dist` would let it run on more projects.
- **FindSecBugs**, when run on an unbuilt Java project, analyzes the checked-in
  build wrapper jars and reports their code. Building the project first is still
  the way to scan it.
