/**
 * Copyright (C) 2025 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.webhook_signature_validator.configuration;

import lombok.Getter;
import lombok.Setter;

/**
 * @author Brent HUNTER (brent.hunter at graviteesource.com)
 * @author GraviteeSource Team
 */
@Getter
@Setter
public class TimestampValidityConfiguration {

  // Optional - When enabled, this policy requires a timestamp (epoch seconds) header, includes it in the
  // recomputed HMAC, and rejects the request if the timestamp is missing, malformed, or outside the allowed age/skew
  private boolean enabled;

  private String sourceTimestampHeader;

  // Delimiter placed between the timestamp header value and the rest of the signed content
  private String delimiter;

  // Maximum age (in seconds) a timestamp may have before the request is considered a replay
  private long maxSignatureAge;

  // Tolerance (in seconds) allowed for a timestamp that is ahead of the gateway's clock
  private long clockSkew;
}
