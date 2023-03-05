/*
 * Copyright (c) 2022-2023 Zander Schwid & Co. LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package sealmod_test

import (
	"bytes"
	"crypto/rand"
	"github.com/codeallergy/sealmod"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

func TestGCMCipher(t *testing.T) {

	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)

	text := "Hello World"
	plaintext := []byte(text)

	ss := sealmod.SealService()
	gcm, err := ss.AuthenticatedCipher(sealmod.WithCipher("GCM"), sealmod.WithAESKey(key))
	require.NoError(t, err)

	ciphertext, err := gcm.Encrypt(plaintext)
	require.NoError(t, err)

	actual, err := gcm.Decrypt(ciphertext)
	require.NoError(t, err)

	require.True(t, bytes.Equal(plaintext, actual))
}

