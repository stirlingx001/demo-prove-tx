package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	mkvsNode "github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/config"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/connection"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/types"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/modules/evm"
)

func main() {
	ctx := context.Background()
	net := config.DefaultNetworks.All["testnet"]
	pt := net.ParaTimes.All["sapphire"]
	// NOTE: Consensus layer block number must be within the 1200-block window after the given
	//       runtime block was finalized in order for the root hashes to be available.
	consensusBlockNum := int64(24002573)                                                 // Consensus layer block number.
	blockNum := uint64(9106088)                                                          // Sapphire block number.
	txHashHex := "9e8f32ff98ca4d835281886d8e4041bce3cdce714d488c63b9202c65e1a4531a"      // SHA512/256 transaction hash
	txEthHashHex := "0xf3d49f4e387ff1f28bfa52b2464376ddcc70c56256ab963047d2e9e7398a479f" // Ethereum transaction hash

	// Establish a connection with the public Testnet gRPC node.
	conn, err := connection.Connect(ctx, net)
	cobra.CheckErr(err)

	// Step 1: Query the relevant consensus layer block to obtain a trusted consensus state root.
	//         Here we are using a simple RPC query to a full node, but in practice one would use
	//         light client verification to obtain the block header.
	cc := conn.Consensus()
	cb, err := cc.GetBlock(ctx, consensusBlockNum)
	cobra.CheckErr(err)

	consensusStateRoot := cb.StateRoot // This is derived from AppHash in the block header.
	fmt.Printf("Consensus height:          %d\n", cb.Height)
	fmt.Printf("Consensus state root hash: %s\n", consensusStateRoot.Hash)

	// Step 2: Obtain the value of the runtime I/O root for the given root from the consensus layer
	//         together with the proof.
	//
	//         The storage key format is: 0x2A H(<runtime-id>) <round>
	runtimeIdHash := pt.Namespace().Hash()
	pastRootsStorageKey := append([]byte{0x2a}, runtimeIdHash[:]...)
	var roundNumBin [8]byte
	binary.BigEndian.PutUint64(roundNumBin[:], blockNum)
	pastRootsStorageKey = append(pastRootsStorageKey, roundNumBin[:]...)

	pr, err := cc.State().SyncGet(ctx, &syncer.GetRequest{
		Tree: syncer.TreeID{
			Root:     consensusStateRoot,
			Position: consensusStateRoot.Hash,
		},
		Key:          pastRootsStorageKey,
		ProofVersion: 1,
	})
	cobra.CheckErr(err)

	// Step 3: Verify Merkle proof against the consensus state root.
	var pv syncer.ProofVerifier
	wl, err := pv.VerifyProofToWriteLog(ctx, consensusStateRoot.Hash, &pr.Proof)
	cobra.CheckErr(err)

	// Step 4: Extract the two root hashes from the verified proof. First is runtime state root
	//         at round blockNum, second is runtime I/O root at round blockNum.
	var verifiedRoots []hash.Hash
	for _, v := range wl {
		if !bytes.Equal(v.Key, pastRootsStorageKey) {
			continue
		}

		err = cbor.Unmarshal(v.Value, &verifiedRoots)
		cobra.CheckErr(err)
		break
	}

	verifiedIORootHash := verifiedRoots[1]
	fmt.Printf("Runtime height:            %d\n", blockNum)
	fmt.Printf("Runtime IO root hash:      %s\n", verifiedIORootHash)

	// Step 5: Query the transaction from the verified I/O root.
	//
	//         The storage key format is: T <tx-hash> 0x01
	var txHash hash.Hash
	err = txHash.UnmarshalHex(txHashHex)
	cobra.CheckErr(err)

	txStorageKey := append([]byte{'T'}, txHash[:]...)
	txStorageKey = append(txStorageKey, byte(0x01))

	rc := conn.Runtime(pt)
	pr, err = rc.State().SyncGet(ctx, &syncer.GetRequest{
		Tree: syncer.TreeID{
			Root: mkvsNode.Root{
				Namespace: pt.Namespace(),
				Version:   blockNum,
				Type:      mkvsNode.RootTypeIO,
				Hash:      verifiedIORootHash,
			},
			Position: verifiedIORootHash,
		},
		Key:          txStorageKey,
		ProofVersion: 1,
	})
	cobra.CheckErr(err)

	// Step 6: Verify Merkle proof against the verified I/O root. This proves that the transaction
	//         is included in a block and also gets the raw transaction itself.
	wl, err = pv.VerifyProofToWriteLog(ctx, verifiedIORootHash, &pr.Proof)
	cobra.CheckErr(err)

	// Step 7: Extract the transaction from the verified proof.
	var verifiedTx []byte
	for _, v := range wl {
		if !bytes.Equal(v.Key, txStorageKey) {
			continue
		}

		type inputArtifacts struct {
			_ struct{} `cbor:",toarray"` // nolint

			// Input is the transaction input.
			Input []byte
			// Order is the transaction order within the block.
			Order uint32
		}
		var ia inputArtifacts
		err = cbor.Unmarshal(v.Value, &ia)
		cobra.CheckErr(err)

		verifiedTx = ia.Input
		break
	}

	// Step 8: Parse SDK-wrapped Ethereum transaction.
	var tx types.UnverifiedTransaction
	err = cbor.Unmarshal(verifiedTx, &tx)
	cobra.CheckErr(err)

	if len(tx.AuthProofs) != 1 || tx.AuthProofs[0].Module != "evm.ethereum.v0" {
		panic("unexpected non-ethereum transaction")
	}

	var ethTx ethTypes.Transaction
	if err = ethTx.UnmarshalBinary(tx.Body); err != nil {
		panic("unexpected malformed ethereum transaction")
	}

	fmt.Printf("Transaction hash:          %s\n", tx.Hash())
	fmt.Printf("Eth transaction hash:      %s\n", ethTx.Hash())

	if tx.Hash().String() != txHashHex {
		panic("unexpected SDK-wrapped transaction hash")
	}
	if ethTx.Hash().String() != txEthHashHex {
		panic("unexpected eth transaction hash")
	}

	// Step 9: Query the transaction result from the verified I/O root.
	//
	//         The storage key format is: T <tx-hash> 0x02
	txStorageKey = append([]byte{'T'}, txHash[:]...)
	txStorageKey = append(txStorageKey, byte(0x02))

	pr, err = rc.State().SyncGet(ctx, &syncer.GetRequest{
		Tree: syncer.TreeID{
			Root: mkvsNode.Root{
				Namespace: pt.Namespace(),
				Version:   blockNum,
				Type:      mkvsNode.RootTypeIO,
				Hash:      verifiedIORootHash,
			},
			Position: verifiedIORootHash,
		},
		Key:          txStorageKey,
		ProofVersion: 1,
	})
	cobra.CheckErr(err)

	// Step 10: Verify Merkle proof against the verified I/O root. This proves that the transaction
	//          has been executed within a block and also gets its raw result.
	wl, err = pv.VerifyProofToWriteLog(ctx, verifiedIORootHash, &pr.Proof)
	cobra.CheckErr(err)

	// Step 11: Extract the output from the verified proof.
	var verifiedTxResult []byte
	for _, v := range wl {
		if !bytes.Equal(v.Key, txStorageKey) {
			continue
		}

		type outputArtifacts struct {
			_ struct{} `cbor:",toarray"` // nolint

			// Output is the transaction output.
			Output []byte
		}
		var oa outputArtifacts
		err = cbor.Unmarshal(v.Value, &oa)
		cobra.CheckErr(err)

		verifiedTxResult = oa.Output
		break
	}

	// Step 12: Parse the transaction result.
	var txResult types.CallResult
	err = cbor.Unmarshal(verifiedTxResult, &txResult)
	cobra.CheckErr(err)

	switch res := txResult; {
	case res.Failed != nil:
		fmt.Printf("Runtime height:            %d\n", blockNum)
		fmt.Printf("Transaction status:        failed\n")
		fmt.Printf("            module:        %s\n", res.Failed.Module)
		fmt.Printf("            code:          %d\n", res.Failed.Code)
		fmt.Printf("            message:       %s\n", res.Failed.Message)
	case res.Ok != nil:
		fmt.Printf("Transaction status:        ok\n")
		fmt.Printf("            data:          0x%X\n", res.Ok)
	case res.Unknown != nil:
		fmt.Printf("Transaction status:        unknown\n")
		fmt.Printf("            data:          0x%X\n", res.Unknown)
	default:
		panic("unexpected result kind")
	}

	// Step 13: Query the events emitted by the transaction from the verified I/O root.
	//
	//         The storage key format is: E <tag> <tx-hash>
	txStorageKey = append([]byte{'E'}, []byte("evm\x00\x00\x00\x01")...)
	txStorageKey = append(txStorageKey, txHash[:]...)

	pr, err = rc.State().SyncGet(ctx, &syncer.GetRequest{
		Tree: syncer.TreeID{
			Root: mkvsNode.Root{
				Namespace: pt.Namespace(),
				Version:   blockNum,
				Type:      mkvsNode.RootTypeIO,
				Hash:      verifiedIORootHash,
			},
			Position: verifiedIORootHash,
		},
		Key:          txStorageKey,
		ProofVersion: 1,
	})
	cobra.CheckErr(err)

	// Step 14: Verify Merkle proof against the verified I/O root. This proves that the given EVM
	//          events have been emitted by the transaction.
	wl, err = pv.VerifyProofToWriteLog(ctx, verifiedIORootHash, &pr.Proof)
	cobra.CheckErr(err)

	// Step 15: Extract the output from the verified proof.
	var logs []*evm.Event
	for _, v := range wl {
		if !bytes.Equal(v.Key, txStorageKey) {
			continue
		}

		err = cbor.Unmarshal(v.Value, &logs)
		cobra.CheckErr(err)
		break
	}

	fmt.Printf("EVM events:\n")
	for _, log := range logs {
		fmt.Printf("- Address: 0x%X\n", log.Address)
		fmt.Printf("  Topics:\n")
		for _, topic := range log.Topics {
			fmt.Printf("    - 0x%X\n", topic)
		}
		fmt.Printf("  Data: 0x%X\n", log.Data)
	}
}
