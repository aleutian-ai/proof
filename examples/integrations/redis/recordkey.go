// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/sink"
)

// recordKeyEnv names the FILE holding the record signing key (PEM, from
// `proof keygen --alg ml-dsa-65`). Its path, never the key itself: key
// material does not belong in the environment, where it is inherited by every
// child process and shows up in crash reports and process listings.
const recordKeyEnv = "PROOF_RECORD_KEY_FILE"

// openSink opens the sink folder, signing every record when recordKeyEnv
// names a key file. The returned close function releases the key.
func openSink(dir string) (*sink.Sink, func(), error) {
	path := os.Getenv(recordKeyEnv)
	if path == "" {
		s, err := sink.Open(dir)
		return s, func() {}, err
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", recordKeyEnv, err)
	}
	alg, seed, err := keyfile.ParsePrivateKey(pem)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", recordKeyEnv, err)
	}
	defer clear(seed)
	if alg != keyfile.MLDSA65 {
		return nil, nil, fmt.Errorf("%s holds a %s key; records are signed with ML-DSA-65", recordKeyEnv, alg)
	}
	rs, err := sink.NewMLDSA65RecordSigner(seed)
	if err != nil {
		return nil, nil, err
	}
	s, err := sink.Open(dir, sink.WithRecordSigner(rs))
	if err != nil {
		rs.Close()
		return nil, nil, err
	}
	return s, func() { rs.Close() }, nil
}

// configurationError explains a commit refused because the sink's signing
// mode and this consumer's key do not match. The consumer stops: every batch
// would fail the same way, and redelivering them would loop forever.
func configurationError(err error) error {
	switch {
	case errors.Is(err, sink.ErrRecordSignerRequired):
		return fmt.Errorf("configuration error, not retried: this sink signs its records; set %s "+
			"to the record key file: %w", recordKeyEnv, err)
	case errors.Is(err, sink.ErrSinkNotSigning):
		return fmt.Errorf("configuration error, not retried: this sink holds unsigned records and "+
			"cannot start signing; unset %s (or use a new sink folder): %w", recordKeyEnv, err)
	}
	return err
}
