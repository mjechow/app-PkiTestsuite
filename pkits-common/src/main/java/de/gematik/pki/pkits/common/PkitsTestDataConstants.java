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

import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class PkitsTestDataConstants {

  /** Password used for all p12 key store files of the test certificates. */
  public static final String KEYSTORE_PASSWORD = "00"; // NOSONAR

  public static final Path trustStoreDir =
      Path.of("./testDataTemplates/certificates/ecc/trustStore/");
  public static final Path trustStoreDirRsa =
      Path.of("./testDataTemplates/certificates/rsa/trustStore/");
  public static final Path ocspKeystoreDir =
      Path.of("./testDataTemplates/certificates/ecc/ocspKeystore/");
  public static final Path ocspKeystoreDirRsa =
      Path.of("./testDataTemplates/certificates/rsa/ocspKeystore/");
  public static final Path trustAnchorCertsDir =
      Path.of("./testDataTemplates/certificates/ecc/trustAnchor/");

  public static final Path DEFAULT_KOMP_CA_RSA =
      trustStoreDirRsa.resolve("GEM.KOMP-CA40_TEST-ONLY.pem");

  public static final Path DEFAULT_SMCB_CA_RSA =
      trustStoreDirRsa.resolve("GEM.SMCB-CA40_TEST-ONLY.pem");

  public static final Path DEFAULT_EGK_CA_RSA =
      trustStoreDirRsa.resolve("GEM.EGK-CA40_TEST-ONLY.pem");

  public static final P12Container DEFAULT_OCSP_SIGNER =
      P12Reader.getContentFromP12(
          ocspKeystoreDir.resolve("pkits_OCSP_Signer_57_ecc_TEST-ONLY.p12"), KEYSTORE_PASSWORD);
  public static final P12Container OCSP_SIGNER_NOT_IN_TSL =
      P12Reader.getContentFromP12(ocspKeystoreDir.resolve("ee_not-in-tsl.p12"), KEYSTORE_PASSWORD);
  public static final P12Container OCSP_SIGNER_DIFFERENT_KEY =
      P12Reader.getContentFromP12(
          ocspKeystoreDir.resolve("ee_different-key.p12"), KEYSTORE_PASSWORD);

  public static final P12Container OCSP_SIGNER_RSA =
      P12Reader.getContentFromP12(
          ocspKeystoreDirRsa.resolve("OCSP_Signer_egk_41_rsa_TEST-ONLY.p12"), KEYSTORE_PASSWORD);
  public static final X509Certificate CERT_UNSPECIFIED_STI =
      CertReader.readX509(trustStoreDir.resolve("SGD1_TEST-ONLY.pem"));

  public static final Path DEFAULT_KOMP_CA = trustStoreDir.resolve("GEM.KOMP-CA52_TEST-ONLY.pem");
  public static final Path ALTERNATIVE_KOMP_CA =
      trustStoreDir.resolve("GEM.KOMP-CA53_TEST-ONLY.pem");

  public static final Path DEFAULT_KOMP_CA62 = trustStoreDir.resolve("GEM.KOMP-CA62_TEST-ONLY.pem");
  public static final Path ALTERNATIVE_KOMP_CA63 =
      trustStoreDir.resolve("GEM.KOMP-CA63_TEST-ONLY.pem");

  public static final Path DEFAULT_KOMP_CA58 = trustStoreDir.resolve("GEM.KOMP-CA58_TEST-ONLY.pem");
  public static final Path ALTERNATIVE_KOMP_CA59 =
      trustStoreDir.resolve("GEM.KOMP-CA59_TEST-ONLY.pem");

  public static final Path DEFAULT_KOMP_CA11 = trustStoreDir.resolve("GEM.KOMP-CA11_TEST-ONLY.pem");
  public static final Path ALTERNATIVE_KOMP_CA33 =
      trustStoreDir.resolve("GEM.KOMP-CA33_TEST-ONLY.pem");

  public static final Path DEFAULT_SMCB_CA = trustStoreDir.resolve("GEM.SMCB-CA58-TEST-ONLY.pem");
  public static final Path ALTERNATIVE_SMCB_CA =
      trustStoreDir.resolve("GEM.SMCB-CA59-TEST-ONLY.pem");

  public static final Path DEFAULT_EGK_CA = trustStoreDir.resolve("GEM.EGK-CA52_TEST-ONLY.pem");
  public static final Path ALTERNATIVE_EGK_CA = trustStoreDir.resolve("GEM.EGK-CA53_TEST-ONLY.pem");

  /** Absolute or relative path to issue certificate. */
  public static final X509Certificate DEFAULT_TRUST_ANCHOR =
      CertReader.readX509(trustAnchorCertsDir.resolve("GEM.TSL-CA51-TEST-ONLY.pem"));

  /** Absolute or relative path to key store in p12 format to sign TSLs with. */
  public static final P12Container DEFAULT_TSL_SIGNER =
      P12Reader.getContentFromP12(
          trustAnchorCertsDir.resolve("TSL-Signing-Unit-51-TEST-ONLY.p12"), KEYSTORE_PASSWORD);

  public static final int TSL_DEFAULT_TTL_DAYS = 30;
  public static final X509Certificate ALTERNATIVE_FIRST_TRUST_ANCHOR =
      CertReader.readX509(trustAnchorCertsDir.resolve("GEM.TSL-CA52-TEST-ONLY.pem"));
  public static final X509Certificate ALTERNATIVE_SECOND_TRUST_ANCHOR =
      CertReader.readX509(trustAnchorCertsDir.resolve("GEM.TSL-CA53-TEST-ONLY.pem"));

  public static final X509Certificate EXPIRED_TRUST_ANCHOR =
      CertReader.readX509(trustAnchorCertsDir.resolve("GEM.TSL-CA54-TEST-ONLY_expired.pem"));
  public static final X509Certificate NOT_YET_VALID_TRUST_ANCHOR =
      CertReader.readX509(trustAnchorCertsDir.resolve("GEM.TSL-CA55-TEST-ONLY_not-yet-valid.pem"));
}
