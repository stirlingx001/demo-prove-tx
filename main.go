package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	mkvsNode "github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/config"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/connection"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/modules/evm"
	"github.com/spf13/cobra"
)

// BlockMeta is the CometBFT-specific per-block metadata that is
// exposed via the consensus API.
type BlockMeta struct {
	// Header is the CometBFT block header.
	Header *cmttypes.Header `json:"header"`
	// LastCommit is the CometBFT last commit info.
	LastCommit *cmttypes.Commit `json:"last_commit"`
}

func main() {
	ctx := context.Background()
	net := config.DefaultNetworks.All["testnet"]
	pt := net.ParaTimes.All["sapphire"]
	// NOTE: Consensus layer block number must be within the 1200-block window after the given
	//       runtime block was finalized in order for the root hashes to be available.
	//consensusBlockNum := int64(24002573)                                            // Consensus layer block number.
	consensusBlockNum := int64(0)
	blockNum := uint64(9106088)                                                     // Sapphire block number.
	txHashHex := "9e8f32ff98ca4d835281886d8e4041bce3cdce714d488c63b9202c65e1a4531a" // SHA512/256 transaction hash
	//txEthHashHex := "0xf3d49f4e387ff1f28bfa52b2464376ddcc70c56256ab963047d2e9e7398a479f" // Ethereum transaction hash

	// Establish a connection with the public Testnet gRPC node.
	conn, err := connection.Connect(ctx, net)
	cobra.CheckErr(err)

	// Assumes cc= https://github.com/oasisprotocol/demo-prove-tx/blob/4fc1a52d0a304a54be1a70e68184c60b772292cb/main.go#L40

	// Step 1: Query the relevant consensus layer block to obtain a trusted consensus state root.
	//         Here we are using a simple RPC query to a full node, but in practice one would use
	//         light client verification to obtain the block header.
	cc := conn.Consensus()

	st, err := cc.GetStatus(ctx)
	cobra.CheckErr(err)
	fmt.Printf("GenesisHeight: %v, LatestHeight: %v\n", st.GenesisHeight, st.LatestHeight)

	bkL := st.GenesisHeight
	bkR := st.LatestHeight
	count := 0
	for bkL <= bkR {
		count++
		m := (bkL + bkR) >> 1
		b, err := cc.RootHash().GetLatestBlock(ctx, &api.RuntimeRequest{RuntimeID: pt.Namespace(), Height: m})
		// Ensure b.Header.Round is within (blockNum, blockNum+1200).
		// Otherwise, adjust the consensusBlockNum to a higher or lower value.
		if err != nil {
			fmt.Printf("GetLatestBlock: %v\n", err)
			bkR = m - 1
			continue
		}
		if b.Header.Round > blockNum && b.Header.Round < blockNum+1200 {
			consensusBlockNum = m
			break
		}
		if b.Header.Round < blockNum {
			bkL = m + 1
		} else {
			bkR = m - 1
		}
	}
	fmt.Printf("count: %v\n", count)
	fmt.Printf("consensusBlockNum: %v\n", consensusBlockNum)
	if consensusBlockNum == 0 {
		panic("invalid consensusBlockNum")
	}

	cb, err := cc.GetBlock(ctx, consensusBlockNum)
	cobra.CheckErr(err)

	// Assumes cc= https://github.com/oasisprotocol/demo-prove-tx/blob/4fc1a52d0a304a54be1a70e68184c60b772292cb/main.go#L40
	// Ensure b.Header.Round is within (blockNum, blockNum+1200).
	// Otherwise, adjust the consensusBlockNum to a higher or lower value.

	meta := BlockMeta{}
	err = cbor.Unmarshal(cb.Meta, &meta)
	cobra.CheckErr(err)
	fmt.Printf("Consensus state root hash: %x\n", meta.Header.AppHash.Bytes())

	//os.WriteFile("1.txt", []byte(hex.EncodeToString(cb.Meta[:])), 0766)

	d := cbor.Marshal(meta)

	if bytes.Equal(d, cb.Meta) {
		fmt.Printf("ok\n")
	}

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
	var pastRootsStorageValue []byte
	for _, v := range wl {
		if !bytes.Equal(v.Key, pastRootsStorageKey) {
			continue
		}

		err = cbor.Unmarshal(v.Value, &verifiedRoots)
		fmt.Printf("v.Value: %x\n", v.Value)

		pastRootsStorageValue = v.Value

		cobra.CheckErr(err)
		break
	}

	{
		var nodes []*NodeData
		travelProof(ctx, &pr.Proof, 0, func(n *NodeData) {
			nodes = append(nodes, n)
		})
		fmt.Printf("len(nodes): %v\n", len(nodes))
		leafHash := HashLeafNode(pastRootsStorageKey, pastRootsStorageValue)
		fmt.Printf("verifyProof: %v\n", verifyProof(nodes, consensusStateRoot.Hash, leafHash))
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

	rc := conn.Runtime(pt)

	// Step 13: Query the events emitted by the transaction from the verified I/O root.
	//
	//         The storage key format is: E <tag> <tx-hash>
	txStorageKey := append([]byte{'E'}, []byte("evm\x00\x00\x00\x01")...)
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

	var logValue []byte
	// Step 15: Extract the output from the verified proof.
	var logs []*evm.Event
	for _, v := range wl {
		if !bytes.Equal(v.Key, txStorageKey) {
			continue
		}

		err = cbor.Unmarshal(v.Value, &logs)
		cobra.CheckErr(err)

		logValue = v.Value

		fmt.Printf("log value: %x\n", v.Value)

		break
	}

	{
		var nodes []*NodeData
		travelProof(ctx, &pr.Proof, 0, func(n *NodeData) {
			nodes = append(nodes, n)
		})
		fmt.Printf("len(nodes): %v\n", len(nodes))
		leafHash := HashLeafNode(txStorageKey, logValue)
		fmt.Printf("verifyProof: %v\n", verifyProof(nodes, verifiedIORootHash, leafHash))
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

type NodeData struct {
	Hash hash.Hash
	// Label is the label on the incoming edge.
	Label node.Key
	// LabelBitLength is the length of the label in bits.
	LabelBitLength node.Depth

	// LeafNode is for the key ending at this depth.
	LeafNodeHash hash.Hash
	//LeafNodeKey   node.Key
	//LeafNodeValue []byte

	LeftNodeHash  hash.Hash
	RightNodeHash hash.Hash
}

type Visitor func(n *NodeData)

func travelProof(ctx context.Context, proof *syncer.Proof, idx int, visit Visitor) (int, *node.Pointer, error) {
	if ctx.Err() != nil {
		return -1, nil, ctx.Err()
	}
	if idx >= len(proof.Entries) {
		return -1, nil, errors.New("verifier: malformed proof")
	}

	entry := proof.Entries[idx]
	if entry == nil {
		return idx + 1, nil, nil
	}
	if len(entry) == 0 {
		return -1, nil, errors.New("verifier: malformed proof")
	}

	switch entry[0] {
	case 1:
		// Full node.
		n, err := node.UnmarshalBinary(entry[1:])
		if err != nil {
			return -1, nil, err
		}

		// For internal nodes, also decode children.
		pos := idx + 1
		if nd, ok := n.(*node.InternalNode); ok {
			pos, nd.LeafNode, err = travelProof(ctx, proof, pos, visit)
			if err != nil {
				return -1, nil, err
			}

			// Left.
			pos, nd.Left, err = travelProof(ctx, proof, pos, visit)
			if err != nil {
				return -1, nil, err
			}
			// Right.
			pos, nd.Right, err = travelProof(ctx, proof, pos, visit)
			if err != nil {
				return -1, nil, err
			}

			// Recompute hash as hashes were not recomputed for compact encoding.
			nd.UpdateHash()

			n := &NodeData{
				Hash:           nd.Hash,
				Label:          nd.Label,
				LabelBitLength: nd.LabelBitLength,
				LeafNodeHash:   nd.LeafNode.GetHash(),
				LeftNodeHash:   nd.Left.GetHash(),
				RightNodeHash:  nd.Right.GetHash(),
			}
			visit(n)
		}

		ptr := &node.Pointer{Clean: true, Hash: n.GetHash(), Node: n}

		return pos, ptr, nil
	case 2:
		// Hash of a node.
		var h hash.Hash
		if err := h.UnmarshalBinary(entry[1:]); err != nil {
			return -1, nil, err
		}

		//visit(&NodeData{Hash: h})

		return idx + 1, &node.Pointer{Clean: true, Hash: h}, nil
	default:
		return -1, nil, fmt.Errorf("verifier: unexpected entry in proof (%x)", entry[0])
	}
}

func verifyProof(nodes []*NodeData, rootHash, leafHash hash.Hash) bool {
	if len(nodes) == 1 {
		if bytes.Equal(nodes[0].Hash[:], rootHash[:]) {
			return true
		}
		return false
	}

	foundLeafNode := false
	for _, n := range nodes {
		if !verifyNode(n) {
			return false
		}
		if bytes.Equal(n.LeafNodeHash[:], leafHash[:]) ||
			bytes.Equal(n.LeftNodeHash[:], leafHash[:]) ||
			bytes.Equal(n.RightNodeHash[:], leafHash[:]) {
			foundLeafNode = true
		}
	}
	if !foundLeafNode {
		return false
	}
	for i := 0; i < len(nodes); i++ {
		count := findParentCount(nodes[i], nodes)
		if count > 1 {
			return false
		}
		if count == 0 {
			if !bytes.Equal(nodes[i].Hash[:], rootHash[:]) {
				return false
			}
		}
	}
	return true
}

func findParentCount(n *NodeData, nodes []*NodeData) int {
	count := 0
	for i := 0; i < len(nodes); i++ {
		if bytes.Equal(nodes[i].LeftNodeHash[:], n.Hash[:]) || bytes.Equal(nodes[i].RightNodeHash[:], n.Hash[:]) {
			count++
		}
	}
	return count
}

func HashLeafNode(key, value []byte) hash.Hash {
	var keyLen, valueLen [4]byte
	binary.LittleEndian.PutUint32(keyLen[:], uint32(len(key)))
	binary.LittleEndian.PutUint32(valueLen[:], uint32(len(value)))

	var h hash.Hash
	h.FromBytes([]byte{node.PrefixLeafNode}, keyLen[:], key, valueLen[:], value)
	return h
}

func verifyNode(n *NodeData) bool {

	leafNodeHash := n.LeafNodeHash
	leftHash := n.LeftNodeHash
	rightHash := n.RightNodeHash
	labelBitLength := n.LabelBitLength.MarshalBinary()

	var h hash.Hash
	h.FromBytes(
		[]byte{node.PrefixInternalNode},
		labelBitLength,
		n.Label[:],
		leafNodeHash[:],
		leftHash[:],
		rightHash[:],
	)
	return bytes.Equal(h[:], n.Hash[:])
}
