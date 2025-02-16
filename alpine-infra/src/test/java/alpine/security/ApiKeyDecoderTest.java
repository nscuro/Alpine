/*
 * This file is part of Alpine.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.security;

import alpine.model.ApiKey;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ApiKeyDecoderTest {

    @Test
    void shouldDecodeNewApiKeyFormat() {
        final String rawKey = "alpine_b0Rmm_tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA";
        final ApiKey decodedKey = ApiKeyDecoder.decode(rawKey);

        assertThat(decodedKey).isNotNull();
        assertThat(decodedKey.getPublicId()).isEqualTo("b0Rmm");
        assertThat(decodedKey.getKey()).matches("^[a-z0-9]{64}$");
        assertThat(decodedKey.getClearTextKey()).isEqualTo("alpine_b0Rmm_tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA");
    }

    @Test
    void shouldDecodeLegacyApiKeyFormat() {
        final String rawKey = "tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA";
        final ApiKey decodedKey = ApiKeyDecoder.decode(rawKey);

        assertThat(decodedKey).isNotNull();
        assertThat(decodedKey.getPublicId()).isEqualTo("tl3ZW");
        assertThat(decodedKey.getKey()).matches("^[a-z0-9]{64}$");
        assertThat(decodedKey.getClearTextKey()).isEqualTo("tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA");
    }

    @Test
    void shouldDecodeLegacyApiKeyWithPrefix() {
        final String rawKey = "alpine_tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA";
        final ApiKey decodedKey = ApiKeyDecoder.decode(rawKey);

        assertThat(decodedKey).isNotNull();
        assertThat(decodedKey.getPublicId()).isEqualTo("tl3ZW");
        assertThat(decodedKey.getKey()).matches("^[a-z0-9]{64}$");
        assertThat(decodedKey.getClearTextKey()).isEqualTo("alpine_tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA");
    }

    @Test
    void shouldThrowWhenKeyIsNull() {
        assertThatExceptionOfType(InvalidApiKeyFormatException.class)
                .isThrownBy(() -> ApiKeyDecoder.decode(null))
                .withMessage("Provided API key is null");
    }

    @Test
    void shouldThrowWhenKeyHasInvalidFormat() {
        final String rawKey = "alpine_foo_bar_b0Rmm_tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA";

        assertThatExceptionOfType(InvalidApiKeyFormatException.class)
                .isThrownBy(() -> ApiKeyDecoder.decode(rawKey))
                .withMessage("Expected exactly 3 parts, but got 5");
    }

    @Test
    void shouldThrowWhenPublicIdHasInvalidFormat() {
        final String rawKey = "alpine_b0Rmm666_tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA";

        assertThatExceptionOfType(InvalidApiKeyFormatException.class)
                .isThrownBy(() -> ApiKeyDecoder.decode(rawKey))
                .withMessage("Expected public ID of exactly 5 characters, but got 8");
    }

    @Test
    void shouldThrowWhenKeyPartHasInvalidFormat() {
        final String rawKey = "alpine_b0Rmm_foobarbaz";

        assertThatExceptionOfType(InvalidApiKeyFormatException.class)
                .isThrownBy(() -> ApiKeyDecoder.decode(rawKey))
                .withMessage("Expected key of 32 or 27 characters, but got 9");
    }

}