# SecureFlow AI — Evaluation Report

## Aggregate

| Metric | scanners_only | secureflow_full | Δ |
|---|---|---|---|
| scenarios | 40 | 40 | — |
| recall | 0.61 | 0.76 | +0.15 |
| precision | 0.30 | 0.25 | -0.05 |
| decisions correct | 27/40 | 30/40 | +3 |
| total FP | 65 | 107 | +42 |
| total TP | 28 | 35 | +7 |
| avg latency | 5.8s | 50.8s | +45.0s |
| tokens (in/out) | 0/0 | 389634/53189 | +389634/+53189 |
| patches verified | 0/0 | 8/40 | +8 |

**Headline:** FP added by **42 (65% over baseline)**, recall +0.15, AI uplift +7 TP, extra latency +45.0s, tokens +442,823.

## Per-scenario breakdown

| Scenario | Pipeline | Decision | TP | FP | FN | Recall | Precision | Latency | Tokens (in/out) |
|---|---|---|---|---|---|---|---|---|---|
| scenario_01_hardcoded_secret | scanners_only | ❌ FAIL ✓ | 1 | 1 | 1 | 0.50 | 0.50 | 5.2s | 0/0 |
| scenario_01_hardcoded_secret | secureflow_full | ❌ FAIL ✓ | 1 | 5 | 1 | 0.50 | 0.17 | 32.3s | 15609/2188 |
| scenario_02_missing_authz | scanners_only | ✅ PASS ✗ (expected WARN) | 0 | 0 | 2 | 0.00 | 0.00 | 4.5s | 0/0 |
| scenario_02_missing_authz | secureflow_full | ❌ FAIL ✗ (expected WARN) | 2 | 0 | 0 | 1.00 | 1.00 | 15.0s | 6154/1431 |
| scenario_03_vulnerable_dep | scanners_only | ❌ FAIL ✓ | 2 | 37 | 0 | 1.00 | 0.05 | 45.2s | 0/0 |
| scenario_03_vulnerable_dep | secureflow_full | ❌ FAIL ✓ | 2 | 37 | 0 | 1.00 | 0.05 | 11.7s | 11014/337 |
| scenario_04_sqli_diff | scanners_only | ❌ FAIL ✓ | 1 | 2 | 0 | 1.00 | 0.33 | 4.3s | 0/0 |
| scenario_04_sqli_diff | secureflow_full | ❌ FAIL ✓ | 1 | 3 | 0 | 1.00 | 0.25 | 636.5s | 19638/1750 |
| scenario_05_command_injection | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 4.3s | 0/0 |
| scenario_05_command_injection | secureflow_full | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 19.4s | 8977/1148 |
| scenario_06_ssrf | scanners_only | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 4.2s | 0/0 |
| scenario_06_ssrf | secureflow_full | ❌ FAIL ✓ | 1 | 2 | 0 | 1.00 | 0.33 | 23.1s | 13493/1680 |
| scenario_07_weak_crypto | scanners_only | ✅ PASS ✗ (expected WARN) | 1 | 0 | 0 | 1.00 | 1.00 | 4.3s | 0/0 |
| scenario_07_weak_crypto | secureflow_full | ❌ FAIL ✗ (expected WARN) | 1 | 1 | 0 | 1.00 | 0.50 | 11.4s | 4680/727 |
| scenario_08_path_traversal | scanners_only | ✅ PASS ✗ (expected FAIL) | 0 | 0 | 1 | 0.00 | 0.00 | 4.3s | 0/0 |
| scenario_08_path_traversal | secureflow_full | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 11.1s | 4774/873 |
| scenario_09_safe_subprocess_fp | scanners_only | ✅ PASS ✓ | 0 | 0 | 0 | 0.00 | 0.00 | 4.2s | 0/0 |
| scenario_09_safe_subprocess_fp | secureflow_full | ✅ PASS ✓ | 0 | 0 | 0 | 0.00 | 0.00 | 5.5s | 2415/9 |
| scenario_10_insecure_deser | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 4.2s | 0/0 |
| scenario_10_insecure_deser | secureflow_full | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 17.6s | 8973/1035 |
| scenario_11_xss | scanners_only | ❌ FAIL ✓ | 1 | 2 | 0 | 1.00 | 0.33 | 4.5s | 0/0 |
| scenario_11_xss | secureflow_full | ❌ FAIL ✓ | 1 | 3 | 0 | 1.00 | 0.25 | 33.1s | 17585/1974 |
| scenario_12_open_redirect | scanners_only | ⚠️ WARN ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 4.2s | 0/0 |
| scenario_12_open_redirect | secureflow_full | ⚠️ WARN ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 18.9s | 8876/1167 |
| scenario_13_yaml_unsafe | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 4.2s | 0/0 |
| scenario_13_yaml_unsafe | secureflow_full | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 18.5s | 9102/1297 |
| scenario_14_business_logic_payment | scanners_only | ✅ PASS ✗ (expected WARN) | 0 | 0 | 1 | 0.00 | 0.00 | 4.2s | 0/0 |
| scenario_14_business_logic_payment | secureflow_full | ⚠️ WARN ✓ | 0 | 1 | 1 | 0.00 | 0.00 | 608.5s | 4964/428 |
| scenario_15_iam_wildcard | scanners_only | ✅ PASS ✗ (expected WARN) | 0 | 0 | 1 | 0.00 | 0.00 | 9.2s | 0/0 |
| scenario_15_iam_wildcard | secureflow_full | ❌ FAIL ✗ (expected WARN) | 0 | 1 | 1 | 0.00 | 0.00 | 14.1s | 4511/745 |
| scenario_16_jwt_alg_none | scanners_only | ⚠️ WARN ✗ (expected FAIL) | 0 | 1 | 1 | 0.00 | 0.00 | 4.2s | 0/0 |
| scenario_16_jwt_alg_none | secureflow_full | ❌ FAIL ✓ | 0 | 2 | 1 | 0.00 | 0.00 | 19.0s | 9015/1118 |
| scenario_17_private_key | scanners_only | ⚠️ WARN ✗ (expected FAIL) | 1 | 0 | 0 | 1.00 | 1.00 | 4.1s | 0/0 |
| scenario_17_private_key | secureflow_full | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 19.2s | 8803/858 |
| scenario_18_sha1_pwd | scanners_only | ⚠️ WARN ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 4.3s | 0/0 |
| scenario_18_sha1_pwd | secureflow_full | ❌ FAIL ✗ (expected WARN) | 1 | 1 | 0 | 1.00 | 0.50 | 14.8s | 5410/950 |
| scenario_19_ssl_verify_false | scanners_only | ✅ PASS ✗ (expected WARN) | 0 | 1 | 1 | 0.00 | 0.00 | 4.2s | 0/0 |
| scenario_19_ssl_verify_false | secureflow_full | ❌ FAIL ✗ (expected WARN) | 0 | 2 | 1 | 0.00 | 0.00 | 11.3s | 4609/830 |
| scenario_20_xxe | scanners_only | ✅ PASS ✗ (expected FAIL) | 0 | 0 | 1 | 0.00 | 0.00 | 4.2s | 0/0 |
| scenario_20_xxe | secureflow_full | ❌ FAIL ✓ | 0 | 1 | 1 | 0.00 | 0.00 | 12.4s | 4704/806 |
| scenario_combined_pr | scanners_only | ❌ FAIL ✓ | 2 | 7 | 3 | 0.40 | 0.22 | 7.8s | 0/0 |
| scenario_combined_pr | secureflow_full | ❌ FAIL ✓ | 3 | 11 | 2 | 0.60 | 0.21 | 61.9s | 33477/5281 |
| scenario_docs_only | scanners_only | ✅ PASS ✓ | 0 | 0 | 0 | 0.00 | 0.00 | 4.6s | 0/0 |
| scenario_docs_only | secureflow_full | ✅ PASS ✓ | 0 | 0 | 0 | 0.00 | 0.00 | 6.0s | 2309/9 |
| scenario_iac_dockerfile_root | scanners_only | ⚠️ WARN ✓ | 1 | 3 | 0 | 1.00 | 0.25 | 7.7s | 0/0 |
| scenario_iac_dockerfile_root | secureflow_full | ❌ FAIL ✗ (expected WARN) | 1 | 3 | 0 | 1.00 | 0.25 | 34.4s | 17514/2192 |
| scenario_iac_gha_overprivileged | scanners_only | ✅ PASS ✗ (expected WARN) | 0 | 0 | 1 | 0.00 | 0.00 | 4.4s | 0/0 |
| scenario_iac_gha_overprivileged | secureflow_full | ✅ PASS ✗ (expected WARN) | 0 | 0 | 1 | 0.00 | 0.00 | 5.9s | 2358/9 |
| scenario_iac_open_sg | scanners_only | ⚠️ WARN ✓ | 1 | 0 | 1 | 0.50 | 1.00 | 6.3s | 0/0 |
| scenario_iac_open_sg | secureflow_full | ❌ FAIL ✗ (expected WARN) | 1 | 0 | 1 | 0.50 | 1.00 | 16.5s | 7503/922 |
| scenario_iac_tf_public_s3 | scanners_only | ❌ FAIL ✗ (expected WARN) | 1 | 4 | 1 | 0.50 | 0.20 | 6.3s | 0/0 |
| scenario_iac_tf_public_s3 | secureflow_full | ❌ FAIL ✗ (expected WARN) | 1 | 7 | 1 | 0.50 | 0.12 | 36.0s | 16455/2997 |
| scenario_js_sqli | scanners_only | ⚠️ WARN ✗ (expected FAIL) | 0 | 1 | 1 | 0.00 | 0.00 | 4.3s | 0/0 |
| scenario_js_sqli | secureflow_full | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 19.3s | 9306/1117 |
| scenario_pi_01_comment_override | scanners_only | ❌ FAIL ✓ | 1 | 2 | 0 | 1.00 | 0.33 | 4.2s | 0/0 |
| scenario_pi_01_comment_override | secureflow_full | ❌ FAIL ✓ | 1 | 3 | 0 | 1.00 | 0.25 | 38.4s | 18304/2081 |
| scenario_pi_02_fake_review | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 4.5s | 0/0 |
| scenario_pi_02_fake_review | secureflow_full | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 19.7s | 9373/1660 |
| scenario_pi_03_role_injection | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 4.3s | 0/0 |
| scenario_pi_03_role_injection | secureflow_full | ❌ FAIL ✓ | 1 | 2 | 0 | 1.00 | 0.33 | 26.2s | 10827/2133 |
| scenario_pi_04_authority_claim | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 4.3s | 0/0 |
| scenario_pi_04_authority_claim | secureflow_full | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 23.4s | 9283/1443 |
| scenario_safe_python_change | scanners_only | ✅ PASS ✓ | 0 | 0 | 0 | 0.00 | 0.00 | 4.9s | 0/0 |
| scenario_safe_python_change | secureflow_full | ✅ PASS ✓ | 0 | 0 | 0 | 0.00 | 0.00 | 5.6s | 2496/9 |
| scenario_tm_new_admin_route | scanners_only | ✅ PASS ✗ (expected WARN) | 0 | 0 | 1 | 0.00 | 0.00 | 4.5s | 0/0 |
| scenario_tm_new_admin_route | secureflow_full | ❌ FAIL ✗ (expected WARN) | 1 | 2 | 0 | 1.00 | 0.33 | 22.7s | 6630/1796 |
| scenario_tm_new_file_upload | scanners_only | ❌ FAIL ✓ | 0 | 1 | 1 | 0.00 | 0.00 | 4.5s | 0/0 |
| scenario_tm_new_file_upload | secureflow_full | ❌ FAIL ✓ | 1 | 4 | 0 | 1.00 | 0.20 | 37.4s | 9206/2645 |
| scenario_xlang_csharp_sqli | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 4.5s | 0/0 |
| scenario_xlang_csharp_sqli | secureflow_full | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 19.5s | 9351/819 |
| scenario_xlang_go_sqli | scanners_only | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 4.6s | 0/0 |
| scenario_xlang_go_sqli | secureflow_full | ❌ FAIL ✓ | 1 | 2 | 0 | 1.00 | 0.33 | 22.6s | 11976/1446 |
| scenario_xlang_java_xxe | scanners_only | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 4.3s | 0/0 |
| scenario_xlang_java_xxe | secureflow_full | ❌ FAIL ✓ | 1 | 2 | 0 | 1.00 | 0.33 | 25.4s | 13805/1558 |
| scenario_xlang_php_sqli | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 4.6s | 0/0 |
| scenario_xlang_php_sqli | secureflow_full | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 20.7s | 9206/1313 |
| scenario_xlang_ruby_cmdi | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 4.5s | 0/0 |
| scenario_xlang_ruby_cmdi | secureflow_full | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 14.3s | 7420/1091 |
| scenario_xlang_ts_cmdi | scanners_only | ❌ FAIL ✓ | 1 | 0 | 0 | 1.00 | 1.00 | 4.5s | 0/0 |
| scenario_xlang_ts_cmdi | secureflow_full | ❌ FAIL ✓ | 1 | 1 | 0 | 1.00 | 0.50 | 22.1s | 9529/1317 |

## Scanner / agent errors

- **scenario_01_hardcoded_secret** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_01_hardcoded_secret** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_02_missing_authz** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_02_missing_authz** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_03_vulnerable_dep** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_03_vulnerable_dep** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_04_sqli_diff** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_04_sqli_diff** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_05_command_injection** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_05_command_injection** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_06_ssrf** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_06_ssrf** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_07_weak_crypto** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_07_weak_crypto** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_08_path_traversal** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_08_path_traversal** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_09_safe_subprocess_fp** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_09_safe_subprocess_fp** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_10_insecure_deser** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_10_insecure_deser** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_11_xss** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_11_xss** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_12_open_redirect** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_12_open_redirect** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_13_yaml_unsafe** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_13_yaml_unsafe** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_14_business_logic_payment** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_14_business_logic_payment** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_16_jwt_alg_none** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_16_jwt_alg_none** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_17_private_key** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_17_private_key** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_18_sha1_pwd** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_18_sha1_pwd** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_19_ssl_verify_false** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_19_ssl_verify_false** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_20_xxe** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_20_xxe** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_docs_only** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_docs_only** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_iac_gha_overprivileged** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_iac_gha_overprivileged** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_js_sqli** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_js_sqli** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_pi_01_comment_override** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_pi_01_comment_override** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_pi_02_fake_review** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_pi_02_fake_review** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_pi_03_role_injection** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_pi_03_role_injection** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_pi_04_authority_claim** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_pi_04_authority_claim** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_safe_python_change** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_safe_python_change** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_tm_new_admin_route** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_tm_new_admin_route** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_tm_new_file_upload** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_tm_new_file_upload** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_csharp_sqli** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_csharp_sqli** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_go_sqli** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_go_sqli** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_java_xxe** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_java_xxe** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_php_sqli** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_php_sqli** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_ruby_cmdi** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_ruby_cmdi** / `secureflow_full` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_ts_cmdi** / `scanners_only` / `checkov` — skipped: no IaC files changed
- **scenario_xlang_ts_cmdi** / `secureflow_full` / `checkov` — skipped: no IaC files changed
