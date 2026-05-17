# SecureFlow AI — Evaluation Report

## Aggregate

| Metric | Value |
|---|---|
| scenarios | 35 |
| recall | 0.61 |
| precision | 0.29 |
| decisions correct | 23/35 |
| total TP/FP/FN | 23/55/15 |
| avg latency | 9.1s |
| tokens (in/out) | 0/0 |
| patches verified | 0/0 |

## Per-scenario breakdown

| Scenario | Pipeline | Decision | TP | FP | FN | Recall | Precision | Latency | Tokens (in/out) |
|---|---|---|---|---|---|---|---|---|---|
| scenario_01_hardcoded_secret | scanners_only | ❌ FAIL ✓ | 1 | 1 | 1 | 0.50 | 0.50 | 9.6s | 0/0 |
| scenario_02_missing_authz | scanners_only | ✅ PASS ✗ (expected WARN) | 0 | 0 | 2 | 0.00 | 0.00 | 6.8s | 0/0 |
| scenario_03_vulnerable_dep | scanners_only | ❌ FAIL ✓ | 2 | 37 | 0 | 1.00 | 0.05 | 69.6s | 0/0 |
| scenario_04_sqli_diff | scanners_only | ❌ FAIL ✓ | 1 | 2 | 0 | 1.00 | 0.33 | 7.5s | 0/0 |
| scenario_05_command_injection | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 7.1s | 0/0 |
| scenario_06_ssrf | scanners_only | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 7.4s | 0/0 |
| scenario_07_weak_crypto | scanners_only | ✅ PASS ✗ (expected WARN) | 1 | 0 | 0 | 1.00 | 1.00 | 7.0s | 0/0 |
| scenario_08_path_traversal | scanners_only | ✅ PASS ✗ (expected FAIL) | 0 | 0 | 1 | 0.00 | 0.00 | 7.8s | 0/0 |
| scenario_09_safe_subprocess_fp | scanners_only | ✅ PASS ✓ | 0 | 0 | 0 | 0.00 | 0.00 | 8.0s | 0/0 |
| scenario_10_insecure_deser | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 7.9s | 0/0 |
| scenario_11_xss | scanners_only | ❌ FAIL ✓ | 1 | 2 | 0 | 1.00 | 0.33 | 7.3s | 0/0 |
| scenario_12_open_redirect | scanners_only | ⚠️ WARN ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 7.2s | 0/0 |
| scenario_13_yaml_unsafe | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 7.2s | 0/0 |
| scenario_14_business_logic_payment | scanners_only | ✅ PASS ✗ (expected WARN) | 0 | 0 | 1 | 0.00 | 0.00 | 7.1s | 0/0 |
| scenario_15_iam_wildcard | scanners_only | ✅ PASS ✗ (expected WARN) | 0 | 0 | 1 | 0.00 | 0.00 | 6.8s | 0/0 |
| scenario_16_jwt_alg_none | scanners_only | ⚠️ WARN ✗ (expected FAIL) | 0 | 1 | 1 | 0.00 | 0.00 | 7.0s | 0/0 |
| scenario_17_private_key | scanners_only | ⚠️ WARN ✗ (expected FAIL) | 1 | 0 | 0 | 1.00 | 1.00 | 6.7s | 0/0 |
| scenario_18_sha1_pwd | scanners_only | ⚠️ WARN ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 6.8s | 0/0 |
| scenario_19_ssl_verify_false | scanners_only | ✅ PASS ✗ (expected WARN) | 0 | 1 | 1 | 0.00 | 0.00 | 7.2s | 0/0 |
| scenario_20_xxe | scanners_only | ✅ PASS ✗ (expected FAIL) | 0 | 0 | 1 | 0.00 | 0.00 | 7.1s | 0/0 |
| scenario_iac_dockerfile_root | scanners_only | ⚠️ WARN ✓ | 0 | 1 | 1 | 0.00 | 0.00 | 8.3s | 0/0 |
| scenario_iac_tf_public_s3 | scanners_only | ❌ FAIL ✗ (expected WARN) | 0 | 3 | 2 | 0.00 | 0.00 | 7.0s | 0/0 |
| scenario_js_sqli | scanners_only | ⚠️ WARN ✗ (expected FAIL) | 0 | 1 | 1 | 0.00 | 0.00 | 7.0s | 0/0 |
| scenario_pi_01_comment_override | scanners_only | ❌ FAIL ✓ | 1 | 2 | 0 | 1.00 | 0.33 | 7.1s | 0/0 |
| scenario_pi_02_fake_review | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 7.0s | 0/0 |
| scenario_pi_03_role_injection | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 6.8s | 0/0 |
| scenario_pi_04_authority_claim | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 7.2s | 0/0 |
| scenario_tm_new_admin_route | scanners_only | ✅ PASS ✗ (expected WARN) | 0 | 0 | 1 | 0.00 | 0.00 | 7.4s | 0/0 |
| scenario_tm_new_file_upload | scanners_only | ❌ FAIL ✓ | 0 | 1 | 1 | 0.00 | 0.00 | 7.0s | 0/0 |
| scenario_xlang_csharp_sqli | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 7.3s | 0/0 |
| scenario_xlang_go_sqli | scanners_only | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 7.4s | 0/0 |
| scenario_xlang_java_xxe | scanners_only | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 7.4s | 0/0 |
| scenario_xlang_php_sqli | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 6.9s | 0/0 |
| scenario_xlang_ruby_cmdi | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 7.2s | 0/0 |
| scenario_xlang_ts_cmdi | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 7.8s | 0/0 |

## Scanner / agent errors

- **scenario_01_hardcoded_secret** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_02_missing_authz** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_03_vulnerable_dep** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_04_sqli_diff** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_05_command_injection** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_06_ssrf** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_07_weak_crypto** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_08_path_traversal** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_09_safe_subprocess_fp** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_10_insecure_deser** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_11_xss** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_12_open_redirect** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_13_yaml_unsafe** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_14_business_logic_payment** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_15_iam_wildcard** / `scanners_only` / `checkov` — FileNotFoundError: [WinError 2] The system cannot find the file specified
- **scenario_16_jwt_alg_none** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_17_private_key** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_18_sha1_pwd** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_19_ssl_verify_false** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_20_xxe** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_iac_dockerfile_root** / `scanners_only` / `checkov` — FileNotFoundError: [WinError 2] The system cannot find the file specified
- **scenario_iac_tf_public_s3** / `scanners_only` / `checkov` — FileNotFoundError: [WinError 2] The system cannot find the file specified
- **scenario_js_sqli** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_pi_01_comment_override** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_pi_02_fake_review** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_pi_03_role_injection** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_pi_04_authority_claim** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_tm_new_admin_route** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_tm_new_file_upload** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_csharp_sqli** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_go_sqli** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_java_xxe** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_php_sqli** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_ruby_cmdi** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_ts_cmdi** / `scanners_only` / `checkov` — skipped: no IaC files changed
