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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.webhook_signature_validator.configuration.SchemeTypeConfiguration;
import io.gravitee.policy.webhook_signature_validator.configuration.TimestampValidityConfiguration;
import io.gravitee.policy.webhook_signature_validator.configuration.WebhookSignatureValidatorPolicyConfiguration;
import java.time.Instant;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class WebhookSignatureValidatorPolicyTest {

  private static final String SECRET_EXPR = "secretExpr";
  private static final String SECRET = "mySecret";
  private static final String SIGNATURE_HEADER_EXPR = "signatureHeaderExpr";

  @Mock
  private Request request;

  @Mock
  private Response response;

  @Mock
  private PolicyChain chain;

  @Mock
  private ExecutionContext context;

  @Mock
  private TemplateEngine templateEngine;

  @Mock
  private HttpHeaders requestHeaders;

  private WebhookSignatureValidatorPolicyConfiguration configuration;

  @BeforeEach
  void setUp() {
    configuration = new WebhookSignatureValidatorPolicyConfiguration();
    configuration.setSourceSignatureHeader(SIGNATURE_HEADER_EXPR);
    configuration.setAlgorithm("HmacSHA256");
    configuration.setSecret(SECRET_EXPR);

    when(context.getTemplateEngine()).thenReturn(templateEngine);
    when(templateEngine.getValue(SECRET_EXPR, String.class)).thenReturn(SECRET);
  }

  private void run(String body, String signatureHeaderValue) {
    when(templateEngine.getValue(SIGNATURE_HEADER_EXPR, String.class))
      .thenReturn(signatureHeaderValue);

    ReadWriteStream<Buffer> stream = new WebhookSignatureValidatorPolicy(
      configuration
    )
      .onRequestContent(request, response, context, chain);
    stream.write(Buffer.buffer(body));
    stream.end();
  }

  private static String hmac(String data, String secret, String algorithm) {
    try {
      Mac mac = Mac.getInstance(algorithm);
      mac.init(new SecretKeySpec(secret.getBytes("UTF-8"), algorithm));
      return java.util.Base64
        .getEncoder()
        .encodeToString(mac.doFinal(data.getBytes("UTF-8")));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  void shouldFailWhenSignatureHeaderMissing() {
    run("{\"event\":\"test\"}", null);

    verify(chain, never()).doNext(request, response);
    verify(chain)
      .failWith(
        argThat(result ->
          result.statusCode() == 401 &&
          result.key().equals("WEBHOOK_SIGNATURE_NOT_FOUND")
        )
      );
  }

  @Test
  void shouldFailWhenSignatureHeaderBlank() {
    run("{\"event\":\"test\"}", "   ");

    verify(chain, never()).doNext(request, response);
    verify(chain)
      .failWith(
        argThat(result ->
          result.statusCode() == 401 &&
          result.key().equals("WEBHOOK_SIGNATURE_NOT_FOUND")
        )
      );
  }

  @Test
  void shouldValidateCorrectSignature() {
    String body = "{\"event\":\"test\"}";
    run(body, hmac(body, SECRET, "HmacSHA256"));

    verify(chain).doNext(request, response);
    verify(chain, never()).failWith(any(PolicyResult.class));
  }

  @Test
  void shouldFailWhenSignatureIncorrect() {
    run("{\"event\":\"test\"}", "not-the-right-signature");

    verify(chain, never()).doNext(request, response);
    verify(chain)
      .failWith(
        argThat(result ->
          result.statusCode() == 401 &&
          result.key().equals("WEBHOOK_SIGNATURE_INVALID_SIGNATURE")
        )
      );
  }

  @Test
  void shouldValidateWithAdditionalHeadersAndDelimiter() {
    SchemeTypeConfiguration schemeType = new SchemeTypeConfiguration();
    schemeType.setEnabled(true);
    schemeType.setHeaders(List.of("X-Header-1", "X-Header-2"));
    schemeType.setHeadersDelimiter(".");
    configuration.setSchemeType(schemeType);

    when(request.headers()).thenReturn(requestHeaders);
    when(requestHeaders.get("X-Header-1")).thenReturn("value1");
    when(requestHeaders.get("X-Header-2")).thenReturn("value2");

    String body = "{\"event\":\"test\"}";
    String signedContent = "value1.value2." + body;
    run(body, hmac(signedContent, SECRET, "HmacSHA256"));

    verify(chain).doNext(request, response);
    verify(chain, never()).failWith(any(PolicyResult.class));
  }

  @Test
  void shouldFailWhenAdditionalHeaderMissing() {
    SchemeTypeConfiguration schemeType = new SchemeTypeConfiguration();
    schemeType.setEnabled(true);
    schemeType.setHeaders(List.of("X-Header-1"));
    schemeType.setHeadersDelimiter(".");
    configuration.setSchemeType(schemeType);

    when(request.headers()).thenReturn(requestHeaders);
    when(requestHeaders.get("X-Header-1")).thenReturn(null);

    run("{\"event\":\"test\"}", "irrelevant-signature");

    verify(chain, never()).doNext(request, response);
    verify(chain)
      .failWith(
        argThat(result ->
          result.statusCode() == 401 &&
          result.key().equals("WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID")
        )
      );
  }

  @Test
  void shouldFailWhenAdditionalHeadersEnabledButNoneConfigured() {
    SchemeTypeConfiguration schemeType = new SchemeTypeConfiguration();
    schemeType.setEnabled(true);
    schemeType.setHeaders(List.of());
    configuration.setSchemeType(schemeType);

    run("{\"event\":\"test\"}", "irrelevant-signature");

    verify(chain, never()).doNext(request, response);
    verify(chain)
      .failWith(
        argThat(result ->
          result.statusCode() == 401 &&
          result.key().equals("WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID")
        )
      );
  }

  @Test
  void shouldValidateWithFreshTimestamp() {
    TimestampValidityConfiguration timestampValidity =
      new TimestampValidityConfiguration();
    timestampValidity.setEnabled(true);
    timestampValidity.setSourceTimestampHeader("X-HMAC-Timestamp");
    timestampValidity.setDelimiter(".");
    timestampValidity.setMaxSignatureAge(300);
    timestampValidity.setClockSkew(60);
    configuration.setTimestampValidity(timestampValidity);

    String timestamp = String.valueOf(Instant.now().getEpochSecond());
    when(request.headers()).thenReturn(requestHeaders);
    when(requestHeaders.get("X-HMAC-Timestamp")).thenReturn(timestamp);

    String body = "{\"event\":\"test\"}";
    String signedContent = timestamp + "." + body;
    run(body, hmac(signedContent, SECRET, "HmacSHA256"));

    verify(chain).doNext(request, response);
    verify(chain, never()).failWith(any(PolicyResult.class));
  }

  @Test
  void shouldFailWhenTimestampMissing() {
    TimestampValidityConfiguration timestampValidity =
      new TimestampValidityConfiguration();
    timestampValidity.setEnabled(true);
    timestampValidity.setSourceTimestampHeader("X-HMAC-Timestamp");
    timestampValidity.setDelimiter(".");
    configuration.setTimestampValidity(timestampValidity);

    when(request.headers()).thenReturn(requestHeaders);
    when(requestHeaders.get("X-HMAC-Timestamp")).thenReturn(null);

    run("{\"event\":\"test\"}", "irrelevant-signature");

    verify(chain, never()).doNext(request, response);
    verify(chain)
      .failWith(
        argThat(result ->
          result.statusCode() == 401 &&
          result.key().equals("WEBHOOK_SIGNATURE_TIMESTAMP_NOT_FOUND")
        )
      );
  }

  @Test
  void shouldFailWhenTimestampMalformed() {
    TimestampValidityConfiguration timestampValidity =
      new TimestampValidityConfiguration();
    timestampValidity.setEnabled(true);
    timestampValidity.setSourceTimestampHeader("X-HMAC-Timestamp");
    timestampValidity.setDelimiter(".");
    configuration.setTimestampValidity(timestampValidity);

    when(request.headers()).thenReturn(requestHeaders);
    when(requestHeaders.get("X-HMAC-Timestamp")).thenReturn("not-a-number");

    run("{\"event\":\"test\"}", "irrelevant-signature");

    verify(chain, never()).doNext(request, response);
    verify(chain)
      .failWith(
        argThat(result ->
          result.statusCode() == 401 &&
          result.key().equals("WEBHOOK_SIGNATURE_TIMESTAMP_INVALID")
        )
      );
  }

  @Test
  void shouldFailWhenTimestampTooOld() {
    TimestampValidityConfiguration timestampValidity =
      new TimestampValidityConfiguration();
    timestampValidity.setEnabled(true);
    timestampValidity.setSourceTimestampHeader("X-HMAC-Timestamp");
    timestampValidity.setDelimiter(".");
    timestampValidity.setMaxSignatureAge(300);
    timestampValidity.setClockSkew(60);
    configuration.setTimestampValidity(timestampValidity);

    String staleTimestamp = String.valueOf(
      Instant.now().getEpochSecond() - 1000
    );
    when(request.headers()).thenReturn(requestHeaders);
    when(requestHeaders.get("X-HMAC-Timestamp")).thenReturn(staleTimestamp);

    String body = "{\"event\":\"test\"}";
    String signedContent = staleTimestamp + "." + body;
    // Even with a correctly computed signature, a stale timestamp must still be rejected.
    run(body, hmac(signedContent, SECRET, "HmacSHA256"));

    verify(chain, never()).doNext(request, response);
    verify(chain)
      .failWith(
        argThat(result ->
          result.statusCode() == 401 &&
          result.key().equals("WEBHOOK_SIGNATURE_TIMESTAMP_EXPIRED")
        )
      );
  }

  @Test
  void shouldFailWhenTimestampTooFarInFuture() {
    TimestampValidityConfiguration timestampValidity =
      new TimestampValidityConfiguration();
    timestampValidity.setEnabled(true);
    timestampValidity.setSourceTimestampHeader("X-HMAC-Timestamp");
    timestampValidity.setDelimiter(".");
    timestampValidity.setMaxSignatureAge(300);
    timestampValidity.setClockSkew(60);
    configuration.setTimestampValidity(timestampValidity);

    String futureTimestamp = String.valueOf(
      Instant.now().getEpochSecond() + 1000
    );
    when(request.headers()).thenReturn(requestHeaders);
    when(requestHeaders.get("X-HMAC-Timestamp")).thenReturn(futureTimestamp);

    String body = "{\"event\":\"test\"}";
    String signedContent = futureTimestamp + "." + body;
    run(body, hmac(signedContent, SECRET, "HmacSHA256"));

    verify(chain, never()).doNext(request, response);
    verify(chain)
      .failWith(
        argThat(result ->
          result.statusCode() == 401 &&
          result.key().equals("WEBHOOK_SIGNATURE_TIMESTAMP_EXPIRED")
        )
      );
  }

  @Test
  void shouldUseDifferentAlgorithms() {
    configuration.setAlgorithm("HmacSHA512");

    String body = "{\"event\":\"test\"}";
    run(body, hmac(body, SECRET, "HmacSHA512"));

    verify(chain).doNext(request, response);
    verify(chain, never()).failWith(any(PolicyResult.class));
  }
}
