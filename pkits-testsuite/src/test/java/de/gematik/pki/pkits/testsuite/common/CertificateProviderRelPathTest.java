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

package de.gematik.pki.pkits.testsuite.common;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.nio.file.Path;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

/** CertificateProvider reads config file which contains relative paths. */
@Slf4j
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CertificateProviderRelPathTest {

  @ParameterizedTest
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = PkitsCertType.PKITS_CERT_VALID)
  void testRelPathArgumentsSourceValidCerts(final Path eeCertPath, final Path issuerCertPath) {
    log.info("\n\n Test with certificate \"{}\"\n", eeCertPath);
    assertThat(eeCertPath.toString()).contains(".p12");
    assertThat(issuerCertPath.toString()).endsWith(".pem");
  }

  @ParameterizedTest
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = PkitsCertType.PKITS_CERT_INVALID)
  void testRelPathArgumentsSourceInvalidCerts(final Path eeCertPath, final Path issuerCertPath) {
    log.info("\n\n Test with certificate \"{}\"\n", eeCertPath);
    assertThat(eeCertPath.toString()).contains(".p12");
    assertThat(issuerCertPath.toString()).endsWith(".pem");
  }
}
