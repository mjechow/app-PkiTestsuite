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

package de.gematik.pki.pkits.ocsp.responder.controllers;

import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.ocsp.responder.data.OcspInfoRequestDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistory;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import io.swagger.v3.oas.annotations.Operation;
import java.util.Collections;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
public class OcspInfoController {

  private final OcspRequestHistory ocspRequestHistory;

  /**
   * @param ocspInfoRequest OcspInfoRequestDto
   * @return An excerpt of the history of requests
   */
  @Operation(summary = "Get history entries according to the provided info request.")
  @PostMapping(value = PkitsConstants.OCSP_WEBSERVER_INFO_ENDPOINT)
  public List<OcspRequestHistoryEntryDto> info(
      final @RequestBody OcspInfoRequestDto ocspInfoRequest) {

    log.info("received ocspInfoRequest: {}", ocspInfoRequest);

    final List<OcspRequestHistoryEntryDto> retList =
        getHistoryEntriesForPositiveTslSeqNrAndCertSerialNumber(ocspInfoRequest);

    deleteHistoryOnDemand(ocspInfoRequest);

    return Collections.unmodifiableList(retList);
  }

  private List<OcspRequestHistoryEntryDto> getHistoryEntriesForPositiveTslSeqNrAndCertSerialNumber(
      final OcspInfoRequestDto ocspInfoRequest) {

    log.info(
        "InfoRequest received for tslSeqNr {}, certSerialNr {}.",
        ocspInfoRequest.getTslSeqNr(),
        ocspInfoRequest.getCertSerialNr());

    final List<OcspRequestHistoryEntryDto> retList =
        ocspRequestHistory.getExcerpt(
            ocspInfoRequest.getTslSeqNr(), ocspInfoRequest.getCertSerialNr());

    log.info("Found history with {} entries.", retList.size());
    return retList;
  }

  private void deleteHistoryOnDemand(final OcspInfoRequestDto ocspInfoRequestDto) {
    switch (ocspInfoRequestDto.getHistoryDeleteOption()) {
      case DELETE_FULL_HISTORY -> {
        ocspRequestHistory.deleteAll();
        log.debug(
            "OCSP request FULL history: cleared (tslSeqNr {} and certSerialNr {})",
            ocspInfoRequestDto.getTslSeqNr(),
            ocspInfoRequestDto.getCertSerialNr());
      }
      case DELETE_QUERIED_HISTORY -> {
        ocspRequestHistory.deleteEntries(
            ocspInfoRequestDto.getTslSeqNr(), ocspInfoRequestDto.getCertSerialNr());
        log.debug(
            "OCSP request history: cleared tslSeqNr {} and certSerialNr {}",
            ocspInfoRequestDto.getTslSeqNr(),
            ocspInfoRequestDto.getCertSerialNr());
      }

        // HistoryDeleteOption.DELETE_NOTHING
      default -> log.debug("deleteHistoryOnDemand called without delete option.");
    }
  }
}
