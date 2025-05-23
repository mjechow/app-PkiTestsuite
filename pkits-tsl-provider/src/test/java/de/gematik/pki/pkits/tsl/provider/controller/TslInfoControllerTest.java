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

package de.gematik.pki.pkits.tsl.provider.controller;

import static de.gematik.pki.pkits.common.PkitsConstants.TSL_SEQNR_PARAM_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_PRIMARY_ENDPOINT;
import static de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory.IGNORE_SEQUENCE_NUMBER;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.pkits.common.JsonTransceiver;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.tsl.provider.TslConfigHolder;
import de.gematik.pki.pkits.tsl.provider.common.TslConfigurator;
import de.gematik.pki.pkits.tsl.provider.data.TslInfoRequestDto;
import de.gematik.pki.pkits.tsl.provider.data.TslInfoRequestDto.HistoryDeleteOption;
import java.nio.charset.StandardCharsets;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestException;
import org.apache.hc.core5.http.HttpStatus;
import org.assertj.core.api.Assertions;
import org.json.JSONArray;
import org.json.JSONException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@TestComponent
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(SpringExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TslInfoControllerTest {

  String tslInfoUrl;
  String tslServiceUrlPrimary;
  String tslServiceUrlBackup;
  @LocalServerPort private int localServerPort;
  @Autowired private TslConfigHolder tslConfigHolder;

  /** TslProvider has already started. */
  @BeforeAll
  void init() {
    tslInfoUrl = "http://localhost:" + localServerPort + PkitsConstants.TSL_WEBSERVER_INFO_ENDPOINT;
    tslServiceUrlPrimary = "http://localhost:" + localServerPort + TSL_XML_PRIMARY_ENDPOINT;
    tslServiceUrlBackup = "http://localhost:" + localServerPort + TSL_XML_BACKUP_ENDPOINT;
  }

  @BeforeEach
  public void before() {
    invalidateTslConfiguration();
  }

  /**
   * Get full TslRequestHistory. Send a few requests with different tslSeqNr. History should contain
   * these requests. Expected is a JSONArray of exact size. Clean history.
   */
  @Test
  void getFullTslRequestHistoryAsJson() throws JSONException {
    TslConfigurator.configureTsl(
        localServerPort, "dummy tsl content".getBytes(StandardCharsets.UTF_8));
    final int REQUEST_AMOUNT = 4;
    for (int i = 0; i < REQUEST_AMOUNT; i++) {
      sendTslDownloadRequest(i);
    }
    // IGNORE_SEQUENCE_NUMBER == FULL_HISTORY_IS_REQUESTED
    final JSONArray jsonArray = getHistoryAndClear(IGNORE_SEQUENCE_NUMBER);

    assertThat(jsonArray.length()).isEqualTo(REQUEST_AMOUNT);
  }

  /**
   * Get TslRequestHistory for a tslSeqNr. Send a few requests with same tslSeqNr. History should
   * contain these requests. Expected is a JSONArray of exact size. Clean history for this tslSeqNr.
   */
  @Test
  void getTslRequestHistoryAsJsonForSequenceNr() throws JSONException {
    TslConfigurator.configureTsl(
        localServerPort, "dummy tsl content".getBytes(StandardCharsets.UTF_8));
    final int SEQ_NR = 2;
    final int REQUEST_AMOUNT = 4;
    for (int i = 0; i < REQUEST_AMOUNT; i++) {
      sendTslDownloadRequest(SEQ_NR);
    }

    final TslInfoRequestDto tslInfoRequest =
        new TslInfoRequestDto(SEQ_NR, HistoryDeleteOption.DELETE_SEQNR_ENTRY);
    final String requestBodyAsJson = PkitsCommonUtils.createJsonContent(tslInfoRequest);
    final String responseBodyAsJson =
        JsonTransceiver.txRxJsonViaHttp(tslInfoUrl, requestBodyAsJson);
    final JSONArray jsonArray = new JSONArray(responseBodyAsJson);

    assertThat(jsonArray.length()).isEqualTo(REQUEST_AMOUNT);
  }

  /**
   * Get empty TslRequestHistory. Send a request with imaginary tslSeqNr. History should be empty.
   * Expected is a String that represents an empty array.
   */
  @Test
  void getEmptyTslRequestHistoryForImaginarySequenceNrAsJson() {
    final int tslSeqNr = 4711;
    final TslInfoRequestDto tslInfoRequest =
        new TslInfoRequestDto(tslSeqNr, HistoryDeleteOption.DELETE_NOTHING);
    final String requestBodyAsJson = PkitsCommonUtils.createJsonContent(tslInfoRequest);
    final String responseBodyAsJson =
        JsonTransceiver.txRxJsonViaHttp(tslInfoUrl, requestBodyAsJson);
    assertThat(responseBodyAsJson).isEqualTo("[]");
  }

  /**
   * Send a few requests with different tslSeqNr, delete full history via InfoRequest with used
   * tslSeqNr. Check via InfoRequest with other used tslSeqNr if history is clear.
   */
  @Test
  void deleteCompleteTslRequestHistory() throws JSONException {
    TslConfigurator.configureTsl(
        localServerPort, "dummy tsl content".getBytes(StandardCharsets.UTF_8));
    final int REQUEST_AMOUNT = 25;
    for (int i = 0; i < REQUEST_AMOUNT; i++) {
      sendTslDownloadRequest(i);
    }

    final int usedTslSeqNr = 18;
    // make sure that tslSeqNr was in request loop
    assertThat(usedTslSeqNr).isLessThan(REQUEST_AMOUNT);
    final JSONArray jsonArray1 = getHistoryAndClear(usedTslSeqNr);
    assertThat(jsonArray1.length()).isEqualTo(1);

    final int otherUsedTslSeqNr = 22;
    // make sure that tslSeqNr was in request loop
    assertThat(otherUsedTslSeqNr).isLessThan(REQUEST_AMOUNT);
    final JSONArray jsonArray2 = getHistoryAndClear(otherUsedTslSeqNr);
    assertThat(jsonArray2.length()).isZero();
  }

  private JSONArray getHistoryAndClear(final int tslSeqNr) throws JSONException {
    final TslInfoRequestDto tslInfoRequest =
        new TslInfoRequestDto(tslSeqNr, HistoryDeleteOption.DELETE_FULL_HISTORY);
    final String requestBodyAsJson = PkitsCommonUtils.createJsonContent(tslInfoRequest);
    final String responseBodyAsJson =
        JsonTransceiver.txRxJsonViaHttp(tslInfoUrl, requestBodyAsJson);
    return new JSONArray(responseBodyAsJson);
  }

  private void sendTslDownloadRequest(final int tslSeqNr) throws UnirestException {
    final HttpResponse<byte[]> response =
        Unirest.get(tslServiceUrlPrimary).queryString(TSL_SEQNR_PARAM_ENDPOINT, tslSeqNr).asBytes();
    Assertions.assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
  }

  private void invalidateTslConfiguration() {
    tslConfigHolder.setTslProviderConfigDto(null);
  }
}
