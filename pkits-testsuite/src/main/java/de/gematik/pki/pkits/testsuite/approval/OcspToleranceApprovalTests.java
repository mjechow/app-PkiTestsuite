/*
 * Copyright 2024 gematik GmbH
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
 */

package de.gematik.pki.pkits.testsuite.approval;

import static de.gematik.pki.pkits.common.PkitsTestDataConstants.DEFAULT_OCSP_SIGNER;
import static de.gematik.pki.pkits.common.PkitsTestDataConstants.KEYSTORE_PASSWORD;
import static de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase.ClientCertsConfig.DEFAULT_CLIENT_CERTS_CONFIG;
import static de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.usecases.OcspResponderType.OCSP_RESP_PRECONFIGURED;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_INVALID;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_VALID;

import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.pkits.ocsp.responder.data.CertificateDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfig;
import de.gematik.pki.pkits.testsuite.common.DtoDateConfigOption;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import de.gematik.pki.pkits.testsuite.usecases.UseCaseResult;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

@Slf4j
@DisplayName("PKI OCSP tolerance approval tests.")
@Order(1)
class OcspToleranceApprovalTests extends ApprovalTestsBase {

  void verifyWithConfiguredOcspResponder(
      final Consumer<CertificateDto.CertificateDtoBuilder> certificateDtoBuilderStep,
      final UseCaseResult useCaseResult) {

    verifyWithConfiguredOcspResponder(true, certificateDtoBuilderStep, useCaseResult);
  }

  void configureOcspResponder(
      final Consumer<CertificateDto.CertificateDtoBuilder> certificateDtoBuilderStep) {

    final Path eeCertPath = getPathOfDefaultClientCert();

    final CertificateDto.CertificateDtoBuilder certificateDtoBuilder =
        CertificateDto.builder()
            .eeCert(CertReader.getX509FromP12(eeCertPath, KEYSTORE_PASSWORD))
            .issuerCert(
                CertReader.readX509(
                    DEFAULT_CLIENT_CERTS_CONFIG.getIssuerCertPathFunc().apply(this)))
            .signer(DEFAULT_OCSP_SIGNER);

    certificateDtoBuilderStep.accept(certificateDtoBuilder);

    final OcspResponderConfig config =
        OcspResponderConfig.builder()
            .certificateDtos(List.of(certificateDtoBuilder.build()))
            .build();

    TestEnvironment.configureOcspResponder(ocspResponderUri, config);
  }

  void verifyWithConfiguredOcspResponder(
      final boolean executeInitialState,
      final Consumer<CertificateDto.CertificateDtoBuilder> certificateDtoBuilderStep,
      final UseCaseResult useCaseResult) {

    if (executeInitialState) {
      initialState();
    }

    configureOcspResponder(certificateDtoBuilderStep);

    useCaseWithCert(
        DEFAULT_CLIENT_CERTS_CONFIG, useCaseResult, OCSP_RESP_PRECONFIGURED, OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TS_0302_021 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with producedAt in past within tolerance")
  void verifyOcspResponseProducedAtPastWithinTolerance() {

    final int producedAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds());

    final Consumer<CertificateDto.CertificateDtoBuilder> certificateDtoBuilderStep =
        getDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(certificateDtoBuilderStep, USECASE_VALID);
  }

  /** gematikId: UE_PKI_TS_0302_021 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with producedAt in past out of tolerance")
  void verifyOcspResponseProducedAtPastOutOfTolerance() {

    final int producedAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds());

    final Consumer<CertificateDto.CertificateDtoBuilder> certificateDtoBuilderStep =
        getDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(certificateDtoBuilderStep, USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_021 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with producedAt in future within tolerance")
  void verifyOcspResponseProducedAtFutureWithinTolerance() {

    final int producedAtDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS - ocspSettings.getTimeoutDeltaMilliseconds();

    final Consumer<CertificateDto.CertificateDtoBuilder> certificateDtoBuilderStep =
        getDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(certificateDtoBuilderStep, USECASE_VALID);

    // NOTE: if this test case fails, and we do not wait -- all the following test cases can be
    // influenced
    //   verifyOcspResponseProducedAtFutureOutOfTolerance
    //   verifyOcspResponseProducedAtFutureWithinTolerance
    //   verifyOcspResponseThisUpdateFutureOutOfTolerance
    //   verifyOcspResponseThisUpdateFutureWithinTolerance
    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + producedAtDeltaMilliseconds / 1000);
  }

  /** gematikId: UE_PKI_TS_0302_021 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with producedAt in future out of tolerance")
  void verifyOcspResponseProducedAtFutureOutOfTolerance() {

    final int producedAtDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS + ocspSettings.getTimeoutDeltaMilliseconds();

    final Consumer<CertificateDto.CertificateDtoBuilder> certificateDtoBuilderStep =
        getDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(certificateDtoBuilderStep, USECASE_INVALID);

    // NOTE: if this test case fails, and we do not wait -- all the following test cases can be
    // influenced
    //   verifyOcspResponseProducedAtFutureOutOfTolerance
    //   verifyOcspResponseProducedAtFutureWithinTolerance
    //   verifyOcspResponseThisUpdateFutureOutOfTolerance
    //   verifyOcspResponseThisUpdateFutureWithinTolerance
    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + producedAtDeltaMilliseconds / 1000);
  }

  /** gematikId: UE_PKI_TS_0302_022 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with thisUpdate in future within tolerance")
  void verifyOcspResponseThisUpdateFutureWithinTolerance() {

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS - ocspSettings.getTimeoutDeltaMilliseconds();

    final Consumer<CertificateDto.CertificateDtoBuilder> certificateDtoBuilderStep =
        getDateConfigStep(DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(certificateDtoBuilderStep, USECASE_VALID);

    // NOTE: if this test case fails, and we do not wait -- all the following test cases can be
    // influenced
    //   verifyOcspResponseProducedAtFutureOutOfTolerance
    //   verifyOcspResponseProducedAtFutureWithinTolerance
    //   verifyOcspResponseThisUpdateFutureOutOfTolerance
    //   verifyOcspResponseThisUpdateFutureWithinTolerance
    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + thisUpdateDeltaMilliseconds / 1000);
  }

  /** gematikId: UE_PKI_TS_0302_022 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with thisUpdate in future out of tolerance")
  void verifyOcspResponseThisUpdateFutureOutOfTolerance() {

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS + ocspSettings.getTimeoutDeltaMilliseconds();

    final Consumer<CertificateDto.CertificateDtoBuilder> certificateDtoBuilderStep =
        getDateConfigStep(DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(certificateDtoBuilderStep, USECASE_INVALID);

    // NOTE: if this test case fails, and we do not wait -- all the following test cases can be
    // influenced
    //   verifyOcspResponseProducedAtFutureOutOfTolerance
    //   verifyOcspResponseProducedAtFutureWithinTolerance
    //   verifyOcspResponseThisUpdateFutureOutOfTolerance
    //   verifyOcspResponseThisUpdateFutureWithinTolerance
    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + thisUpdateDeltaMilliseconds / 1000);
  }

  /** gematikId: UE_PKI_TS_0302_032 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with nextUpdate in past within tolerance")
  void verifyOcspResponseNextUpdatePastWithinTolerance() {

    final int nextUpdateAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds());

    final Consumer<CertificateDto.CertificateDtoBuilder> certificateDtoBuilderStep =
        getDateConfigStep(DtoDateConfigOption.NEXT_UPDATE, nextUpdateAtDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(certificateDtoBuilderStep, USECASE_VALID);
  }

  /** gematikId: UE_PKI_TS_0302_032 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with nextUpdate in past out of tolerance")
  void verifyOcspResponseNextUpdatePastOutOfTolerance() {

    final int nextUpdateDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds());

    final Consumer<CertificateDto.CertificateDtoBuilder> certificateDtoBuilderStep =
        getDateConfigStep(DtoDateConfigOption.NEXT_UPDATE, nextUpdateDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(certificateDtoBuilderStep, USECASE_INVALID);
  }
}