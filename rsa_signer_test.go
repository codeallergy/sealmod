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
	"github.com/codeallergy/sealmod"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRSASigner(t *testing.T) {

	text := "Hello World"
	plaintext := []byte(text)

	ss := sealmod.SealService()
	alice, err := ss.IssueSigner("RSA", 2048)
	require.NoError(t, err)

	signature, err := alice.Sign(plaintext)
	require.NoError(t, err)

	// RSA do not need sender public key
	actual, err := alice.Verify(plaintext, signature)
	require.NoError(t, err)

	require.True(t, actual)
}
