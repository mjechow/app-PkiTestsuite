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

package de.gematik.pki.pkits.testsuite;

import java.nio.file.Path;

public class TestConstants {

  public static final Path CONFIG_FILE_INTTEST_DIR = Path.of("./docs/configs/inttest/");
  public static final String CONFIG_FILE_INTTEST_NAME = "pkits.yml";
  public static final Path CONFIG_FILE_INTTEST_TEMPLATE_PATH =
      CONFIG_FILE_INTTEST_DIR.resolve(CONFIG_FILE_INTTEST_NAME);
}
