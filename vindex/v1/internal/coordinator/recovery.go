// Copyright 2026 The Transparency Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package coordinator implements 3-phase crash recovery, startup coordination, and pipeline orchestration.
package coordinator

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/v1/internal/tree"
)

var (
	ErrInvariantViolation = errors.New("state progression invariant violation")
	ErrRootMismatch       = fmt.Errorf("%w: MPT root does not match Output Log commitment", ErrInvariantViolation)
	ErrOutputLogCorrupted = tree.ErrOutputLogCorrupted
)

// OutputLogReader defines the methods needed to read historical Output Log entries during recovery.
type OutputLogReader interface {
	tree.OutputLogClient
	Size(ctx context.Context) (uint64, error)
	GetLeaf(ctx context.Context, idx uint64) ([]byte, error)
	Checkpoint(ctx context.Context) ([]byte, error)
}

func parseOutputLogLeaf(leafData []byte) (mapRoot [sha256.Size]byte, inCP *log.Checkpoint, rawInCP []byte, err error) {
	return tree.ParseOutputLogLeaf(leafData)
}
