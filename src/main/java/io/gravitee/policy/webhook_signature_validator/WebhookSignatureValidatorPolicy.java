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
package io.gravitee.policy.webhook_signature_validator;

import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.stream.BufferedReadWriteStream;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.gateway.api.stream.SimpleReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequestContent;
import io.gravitee.policy.webhook_signature_validator.configuration.WebhookSignatureValidatorPolicyConfiguration;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;

/**
 * @author Brent HUNTER (brent.hunter at graviteesource.com)
 * @author GraviteeSource Team
 */
@Slf4j
public class WebhookSignatureValidatorPolicy {

  private static final String WEBHOOK_SIGNATURE_INVALID_SIGNATURE =
    "WEBHOOK_SIGNATURE_INVALID_SIGNATURE";
  private static final String WEBHOOK_SIGNATURE_NOT_FOUND =
    "WEBHOOK_SIGNATURE_NOT_FOUND";
  private static final String WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID =
    "WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID";
  private static final String WEBHOOK_SIGNATURE_TIMESTAMP_NOT_FOUND =
    "WEBHOOK_SIGNATURE_TIMESTAMP_NOT_FOUND";
  private static final String WEBHOOK_SIGNATURE_TIMESTAMP_INVALID =
    "WEBHOOK_SIGNATURE_TIMESTAMP_INVALID";
  private static final String WEBHOOK_SIGNATURE_TIMESTAMP_EXPIRED =
    "WEBHOOK_SIGNATURE_TIMESTAMP_EXPIRED";
  private static final String WEBHOOK_SIGNATURE_TIMESTAMP_IN_FUTURE =
    "WEBHOOK_SIGNATURE_TIMESTAMP_IN_FUTURE";
  private static final String WEBHOOK_SIGNATURE_GENERATION_FAILED =
    "WEBHOOK_SIGNATURE_GENERATION_FAILED";

  /**
   * Policy configuration
   */
  private final WebhookSignatureValidatorPolicyConfiguration configuration;

  public WebhookSignatureValidatorPolicy(
    final WebhookSignatureValidatorPolicyConfiguration configuration
  ) {
    this.configuration = configuration;
  }

  @OnRequestContent
  public ReadWriteStream<Buffer> onRequestContent(
    Request request,
    Response response,
    ExecutionContext context,
    PolicyChain chain
  ) {
    log.info("Executing WebhookSignatureValidatorPolicy...");

    String secret = context
      .getTemplateEngine()
      .getValue(configuration.getSecret(), String.class);
    String algorithm = configuration.getAlgorithm();

    return new BufferedReadWriteStream() {
      Buffer buffer = Buffer.buffer();

      @Override
      public SimpleReadWriteStream<Buffer> write(Buffer content) {
        buffer.appendBuffer(content);
        return this;
      }

      @Override
      public void end() {
        String sourceSigHeader = null;
        List<String> addedHeaders = null;
        String headersDelimiter = null;

        // Get HTTP body payload
        String data = buffer.toString();

        try {
          sourceSigHeader = context
            .getTemplateEngine()
            .getValue(configuration.getSourceSignatureHeader(), String.class);
          log.debug("Supplied HMAC Signature: {}", sourceSigHeader);
          if (sourceSigHeader == null || sourceSigHeader.isBlank()) {
            chain.failWith(
              PolicyResult.failure(
                WEBHOOK_SIGNATURE_NOT_FOUND,
                401,
                "Webhook Signature Not Found"
              )
            );
            return;
          }
        } catch (Exception e) {
          chain.failWith(
            PolicyResult.failure(
              WEBHOOK_SIGNATURE_NOT_FOUND,
              401,
              "Webhook Signature Not Found"
            )
          );
          return;
        }

        log.debug(
          "Config> Does the Signature validation require additional headers?: {}",
          configuration.getSchemeType().isEnabled()
        ); // true|false
        if (configuration.getSchemeType().isEnabled()) {
          addedHeaders = new ArrayList<>(
            configuration.getSchemeType().getHeaders()
          );

          headersDelimiter = configuration
            .getSchemeType()
            .getHeadersDelimiter();
          log.debug("Config> headersDelimiter: {}", headersDelimiter);

          if (addedHeaders.size() > 0) {
            int i = 0;
            while (i < addedHeaders.size()) {
              log.debug(
                "Config> Additional header(s): {} = {}",
                addedHeaders.get(i),
                request.headers().get(addedHeaders.get(i))
              );
              if (request.headers().get(addedHeaders.get(i)) == null) {
                chain.failWith(
                  PolicyResult.failure(
                    WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID,
                    401,
                    "A required webhook header value is invalid or missing"
                  )
                );
                return;
              }
              i++;
            }
          } else {
            chain.failWith(
              PolicyResult.failure(
                WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID,
                401,
                "Webhook additional headers not valid or not found"
              )
            );
            return;
          }
        }

        log.debug("Config> Secret: {}", secret);
        log.debug("Config> Algorithm: {}", algorithm);
        log.debug("Config> Request Body: {}", buffer.toString());

        // Optionally, prefix any additional headers to HTTP body
        if (configuration.getSchemeType().isEnabled()) {
          int i = 0;
          String tmpData = "";
          while (i < addedHeaders.size()) {
            log.debug(
              "Prefixing HTTP header '{}' ({}) to HTTP body...",
              addedHeaders.get(i),
              request.headers().get(addedHeaders.get(i))
            );
            tmpData +=
              request.headers().get(addedHeaders.get(i)) + headersDelimiter;
            i++;
          }
          data = tmpData + data;
        }

        // Optionally, verify the freshness of a signed timestamp header (replay protection)
        if (configuration.getTimestampValidity().isEnabled()) {
          String sourceTimestampHeader = configuration
            .getTimestampValidity()
            .getSourceTimestampHeader();
          String timestampValue = request.headers().get(sourceTimestampHeader);

          if (timestampValue == null || timestampValue.isBlank()) {
            chain.failWith(
              PolicyResult.failure(
                WEBHOOK_SIGNATURE_TIMESTAMP_NOT_FOUND,
                401,
                "Webhook Signature Timestamp Not Found"
              )
            );
            return;
          }

          long timestampSeconds;
          try {
            timestampSeconds = Long.parseLong(timestampValue.trim());
          } catch (NumberFormatException e) {
            chain.failWith(
              PolicyResult.failure(
                WEBHOOK_SIGNATURE_TIMESTAMP_INVALID,
                401,
                "Webhook Signature Timestamp Invalid"
              )
            );
            return;
          }

          long age = Instant.now().getEpochSecond() - timestampSeconds;
          log.debug(
            "Config> Timestamp age: {}s (maxSignatureAge={}s, clockSkew={}s)",
            age,
            configuration.getTimestampValidity().getMaxSignatureAge(),
            configuration.getTimestampValidity().getClockSkew()
          );

          if (age > configuration.getTimestampValidity().getMaxSignatureAge()) {
            chain.failWith(
              PolicyResult.failure(
                WEBHOOK_SIGNATURE_TIMESTAMP_EXPIRED,
                401,
                "Webhook Signature Timestamp Expired"
              )
            );
            return;
          }

          if (age < -configuration.getTimestampValidity().getClockSkew()) {
            chain.failWith(
              PolicyResult.failure(
                WEBHOOK_SIGNATURE_TIMESTAMP_IN_FUTURE,
                401,
                "Webhook Signature Timestamp Is Too Far In The Future"
              )
            );
            return;
          }

          data =
            timestampValue +
            configuration.getTimestampValidity().getDelimiter() +
            data;
        }

        log.debug("Config> Configuration retrieval completed.");

        log.debug("Final data (for signature creation): {}", data);

        // Generate and Validate HMAC Signature...
        String generatedSignature = generateHmacSignature(
          data,
          secret,
          algorithm
        );

        if (generatedSignature == null) {
          log.error(
            "Unable to compute the expected HMAC signature - check the configured secret and algorithm"
          );
          chain.failWith(
            PolicyResult.failure(
              WEBHOOK_SIGNATURE_GENERATION_FAILED,
              401,
              "Unable To Compute Webhook Signature"
            )
          );
          return;
        }

        if (!signaturesMatch(generatedSignature, sourceSigHeader)) {
          log.error("Signature is NOT valid!");
          chain.failWith(
            PolicyResult.failure(
              WEBHOOK_SIGNATURE_INVALID_SIGNATURE,
              401,
              "Invalid Webhook Signature"
            )
          );
          return;
        }
        log.debug("Signature is valid.");
        chain.doNext(request, response);
      }
    };
  }

  // Method to generate HMAC signature
  private String generateHmacSignature(
    String data,
    String secretKey,
    String algorithm
  ) {
    try {
      // Create a SecretKeySpec from the key
      SecretKeySpec secretKeySpec = new SecretKeySpec(
        secretKey.getBytes("UTF-8"),
        algorithm
      );

      // Initialize the Mac instance with the specified algorithm
      Mac mac = Mac.getInstance(algorithm);
      mac.init(secretKeySpec);

      // Generate the HMAC hash of the data
      byte[] hmacHash = mac.doFinal(data.getBytes("UTF-8"));

      log.debug(
        "Generated HMAC signature: {}",
        Base64.getEncoder().encodeToString(hmacHash)
      );

      // Return the Base64 encoded HMAC signature
      return Base64.getEncoder().encodeToString(hmacHash);
    } catch (Exception ex) {
      log.error("Exception occurred while generating HMAC signature!");
      log.error(ex.getMessage());
      //request.metrics().setMessage(ex.getMessage());
      return null;
    }
  }

  // Method to compare two HMAC signatures in constant time, to avoid leaking timing
  // information about how many leading bytes matched
  private boolean signaturesMatch(
    String generatedSignature,
    String providedSignature
  ) {
    return MessageDigest.isEqual(
      generatedSignature.getBytes(StandardCharsets.UTF_8),
      providedSignature.getBytes(StandardCharsets.UTF_8)
    );
  }
}
