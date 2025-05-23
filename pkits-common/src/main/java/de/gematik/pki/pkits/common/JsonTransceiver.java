/*
 * Copyright (Date see Readme), gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.pkits.common;

import kong.unirest.core.HttpRequestWithBody;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpStatus;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class JsonTransceiver {

  private static PkiCommonException sendFailed(final int status) {
    return new PkiCommonException("Send failed with HttpStatus: " + status);
  }

  private static PkiCommonException generationFailed(final UnirestException e) {
    return new PkiCommonException("Generation of request failed.", e);
  }

  public static void sendJsonViaHttp(
      final String uri, final String jsonContent, final boolean successOnly) {
    try {

      final HttpResponse<String> response =
          Unirest.post(uri)
              .header(HttpHeaders.CONTENT_TYPE, "application/json")
              .body(jsonContent)
              .asString();

      if (successOnly && (response.getStatus() != HttpStatus.SC_OK)) {
        throw sendFailed(response.getStatus());
      }
    } catch (final UnirestException e) {
      throw generationFailed(e);
    }
  }

  public static void deleteViaHttp(final String uri, final boolean successOnly) {
    try {

      final HttpResponse<String> response = Unirest.delete(uri).asString();

      if (successOnly && (response.getStatus() != HttpStatus.SC_OK)) {
        throw sendFailed(response.getStatus());
      }
    } catch (final UnirestException e) {
      throw generationFailed(e);
    }
  }

  public static void sendJsonViaHttp(final String uri, final String jsonContent) {
    sendJsonViaHttp(uri, jsonContent, true);
  }

  /**
   * Sends and receives JSON
   *
   * @param uri Receiver
   * @param jsonContent request body (JSON)
   * @return response body (JSON)
   */
  public static String txRxJsonViaHttp(final String uri, final String jsonContent) {
    try {
      final HttpRequestWithBody request = Unirest.post(uri);
      final HttpResponse<String> response =
          request.body(jsonContent).header(HttpHeaders.CONTENT_TYPE, "application/json").asString();
      if (response.getStatus() != HttpStatus.SC_OK) {
        throw sendFailed(response.getStatus());
      }
      return response.getBody();
    } catch (final UnirestException e) {
      throw generationFailed(e);
    }
  }
}
