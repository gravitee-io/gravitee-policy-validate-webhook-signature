# 1.0.0 (2026-09-22)


### Bug Fixes

* compare signatures in constant time ([ae196bb](https://github.com/gravitee-io/gravitee-policy-validate-webhook-signature/commit/ae196bbffc1db08988a3c8a3e479a09708bf437d))
* join additional header values with the configured delimiter ([51b32ee](https://github.com/gravitee-io/gravitee-policy-validate-webhook-signature/commit/51b32ee5a78ba8b1121b105a331fc21a3702db8f))
* null-check the signature header instead of comparing it by identity ([e213327](https://github.com/gravitee-io/gravitee-policy-validate-webhook-signature/commit/e213327ed454ed0a823fe1a727ba0c0d147f9432))
* reject the request when the signature cannot be computed ([68cceb6](https://github.com/gravitee-io/gravitee-policy-validate-webhook-signature/commit/68cceb685b5f10437af39ad559947df4a73620a6))
* stop logging the secret and the request body ([77eb608](https://github.com/gravitee-io/gravitee-policy-validate-webhook-signature/commit/77eb608437c10771bfa6d3368d7d257fe80888ae))


### Features

* add optional timestamp-based replay protection ([7f2e1d8](https://github.com/gravitee-io/gravitee-policy-validate-webhook-signature/commit/7f2e1d8b79a32f345661033138032935eb800598))
