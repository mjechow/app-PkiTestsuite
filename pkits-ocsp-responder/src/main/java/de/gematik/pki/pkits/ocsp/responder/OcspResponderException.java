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

package de.gematik.pki.pkits.ocsp.responder;

import java.io.Serial;

public class OcspResponderException extends RuntimeException {

  @Serial private static final long serialVersionUID = -4798322602434168514L;

  public OcspResponderException(final String message) {
    super(message);
  }

  public OcspResponderException(final String message, final Exception e) {
    super(message, e);
  }

  public OcspResponderException(final Exception e) {
    super(e);
  }
}
