package ibc

import (
	"github.com/tendermint/go-wire/data"
	"github.com/tendermint/iavl"
	"github.com/tendermint/light-client/cerifiers"
t
	sdk "github.com/cosmos/cosmos-sdk"
)

// nolint
const (
	// 0x3? series for ibc
	ByteRegisterChain = byte(0x30)
	ByteUpdateChain   = byte(0x31)
	ByteCreatePacket  = byte(0x32)
	BytePostPacket    = byte(0x33)

	TypeRegisterChain = NameIBC + "/register"
	TypeUpdateChain   = NameIBC + "/update"
	TypeCreatePacket  = NameIBC + "/create"
	TypePostPacket    = NameIBC + "/post"
)

func init() {
	sdk.TxMapper.
		RegisterImplementation(RegisterChainTx{}, TypeRegisterChain, ByteRegisterChain).
		RegisterImplementation(UpdateChainTx{}, TypeUpdateChain, ByteUpdateChain).
		RegisterImplementation(CreatePacketTx{}, TypeCreatePacket, ByteCreatePacket).
		RegisterImplementation(PostPacketTx{}, TypePostPacket, BytePostPacket)
}

// RegisterChainTx allows you to register a new chain on this blockchain
type RegisterChainTx struct {

	/* github.com/tendermint/light-client/cerifiers/provider.go
	// Seed is a checkpoint and the actual validator set, the base info you
	// need to update to a given point, assuming knowledge of some previous
	// validator set
	Seed 是一个检查点，+ 检查点时刻的validator set 

type Seed struct {
	lc.Checkpoint `json:"checkpoint"`
	Validators    *types.ValidatorSet `json:"validator_set"`
}

	*/
	Seed certifiers.Seed `json:"seed"`
}

/*

// Checkpoint is basically the rpc /commit response, but extended
//
// This is the basepoint for proving anything on the blockchain. It contains
// a signed header.  If the signatures are valid and > 2/3 of the known set,
// we can store this checkpoint and use it to prove any number of aspects of
// the system: such as txs, abci state, validator sets, etc...

type Checkpoint struct {
	Header *types.Header `json:"header"`
	Commit *types.Commit `json:"commit"`
}

/*
tendermint/types/block.go

// Header defines the structure of a Tendermint block header
type Header struct {
	ChainID        string     `json:"chain_id"`
	Height         int        `json:"height"`
	Time           time.Time  `json:"time"`
	NumTxs         int        `json:"num_txs"` // XXX: Can we get rid of this?
	LastBlockID    BlockID    `json:"last_block_id"`
	LastCommitHash data.Bytes `json:"last_commit_hash"` // commit from validators from the last block
	DataHash       data.Bytes `json:"data_hash"`        // transactions
	ValidatorsHash data.Bytes `json:"validators_hash"`  // validators for the current block
	AppHash        data.Bytes `json:"app_hash"`         // state after txs from the previous block
}



// Commit contains the evidence that a block was committed by a set of validators.
// NOTE: Commit is empty for height 1, but never nil.
type Commit struct {
	// NOTE: The Precommits are in order of address to preserve the bonded ValidatorSet order.
	// Any peer with a block can gossip precommits by index with a peer without recalculating the
	// active ValidatorSet.
	BlockID    BlockID `json:"blockID"`
	Precommits []*Vote `json:"precommits"`

	// Volatile
	firstPrecommit *Vote
	hash           data.Bytes
	bitArray       *cmn.BitArray  //BitArray returns a BitArray of which validators voted in this commit
}


*/
/*

// Volatile state for each Validator
// NOTE: The Accum is not included in Validator.Hash();
// make sure to update that method if changes are made here
type Validator struct {
	Address     data.Bytes    `json:"address"`
	PubKey      crypto.PubKey `json:"pub_key"`
	VotingPower int64         `json:"voting_power"`

	Accum int64 `json:"accum"`
}



// ValidatorSet represent a set of *Validator at a given height.
// The validators can be fetched by address or index.
// The index is in order of .Address, so the indices are fixed
// for all rounds of a given blockchain height.
// On the other hand, the .AccumPower of each validator and
// the designated .GetProposer() of a set changes every round,
// upon calling .IncrementAccum().
// NOTE: Not goroutine-safe.
// NOTE: All get/set to validators should copy the value for safety.
// TODO: consider validator Accum overflow
type ValidatorSet struct {
	// NOTE: persisted via reflect, must be exported.
	Validators []*Validator `json:"validators"`
	Proposer   *Validator   `json:"proposer"`

	// cached (unexported)
	totalVotingPower int64
}

*/

// ChainID helps get the chain this tx refers to
func (r RegisterChainTx) ChainID() string {
	return r.Seed.Header.ChainID
}
/*


// ValidateBasic does basic consistency checks and makes sure the headers
// and commits are all consistent and refer to our chain.
//
// Make sure to use a Verifier to validate the signatures actually provide
// a significantly strong proof for this header's validity.
func (c Checkpoint) ValidateBasic(chainID string) error {
	// make sure the header is reasonable
	if c.Header == nil {
		return errors.New("Checkpoint missing header")
	}
	if c.Header.ChainID != chainID {
		return errors.Errorf("Header belongs to another chain '%s' not '%s'",
			c.Header.ChainID, chainID)
	}

	if c.Commit == nil {
		return errors.New("Checkpoint missing commits")
	}

	// make sure the header and commit match (height and hash)
	if c.Commit.Height() != c.Header.Height {
		return ErrHeightMismatch(c.Commit.Height(), c.Header.Height)
	}
	hhash := c.Header.Hash()
	chash := c.Commit.BlockID.Hash
	if !bytes.Equal(hhash, chash) {
		return errors.Errorf("Commits sign block %X header is block %X",
			chash, hhash)
	}

	// make sure the commit is reasonable
	err := c.Commit.ValidateBasic()
	if err != nil {
		return errors.WithStack(err)
	}

	// looks good, we just need to make sure the signatures are really from
	// empowered validators
	return nil
}
*/
// ValidateBasic makes sure this is consistent, without checking the sigs
func (r RegisterChainTx) ValidateBasic() error {
	// light-client/checkpoint.go line : 50  ,验证chainId
/*
验证chainid  ： 当前检查点的chain id（seed的） 是不是等于申请注册的链的chainid
验证seed的commit ：是否为空，高度和seed.header的高度是不是一样、
c..header.hash(返回的是validatorsHash) == c.commit.blockId.hash
*/
	err := r.Seed.ValidateBasic(r.ChainID())
	if err != nil {
		err = ErrInvalidCommit(err)
	}
	return err
}

// Wrap - used to satisfy TxInner
func (r RegisterChainTx) Wrap() sdk.Tx {
	return sdk.Tx{r}
}

// UpdateChainTx updates the state of this chain
type UpdateChainTx struct {
	Seed certifiers.Seed `json:"seed"`
}

// ChainID helps get the chain this tx refers to
func (u UpdateChainTx) ChainID() string {
	return u.Seed.Header.ChainID
}

// ValidateBasic makes sure this is consistent, without checking the sigs
func (u UpdateChainTx) ValidateBasic() error {
	err := u.Seed.ValidateBasic(u.ChainID())
	if err != nil {
		err = ErrInvalidCommit(err)
	}
	return err
}

// Wrap - used to satisfy TxInner
func (u UpdateChainTx) Wrap() sdk.Tx {
	return sdk.Tx{u}
}

// CreatePacketTx is meant to be called by IPC, another module...
//
// this is the tx that will be sent to another app and the permissions it
// comes with (which must be a subset of the permissions on the current tx)
//
// If must have the special `AllowIBC` permission from the app
// that can send this packet (so only coins can request SendTx packet)
type CreatePacketTx struct {
	DestChain   string     `json:"dest_chain"`
	Permissions sdk.Actors `json:"permissions"`
	Tx          sdk.Tx     `json:"tx"`
}

// ValidateBasic makes sure this is consistent - used to satisfy TxInner
func (p CreatePacketTx) ValidateBasic() error {
	if p.DestChain == "" {
		return ErrWrongDestChain(p.DestChain)
	}
	return nil
}

// Wrap - used to satisfy TxInner
func (p CreatePacketTx) Wrap() sdk.Tx {
	return sdk.Tx{p}
}

// PostPacketTx takes a wrapped packet from another chain and
// TODO!!!
// also think... which chains can relay packets???
// right now, enforce that these packets are only sent directly,
// not routed over the hub.  add routing later.
type PostPacketTx struct {
	// The immediate source of the packet, not always Packet.SrcChainID
	FromChainID string `json:"src_chain"`
	// The block height in which Packet was committed, to check Proof
	FromChainHeight uint64 `json:"src_height"`
	// this proof must match the header and the packet.Bytes()
	Proof  *iavl.KeyExistsProof `json:"proof"`
	Key    data.Bytes           `json:"key"`
	Packet Packet               `json:"packet"`
}

// ValidateBasic makes sure this is consistent - used to satisfy TxInner
func (p PostPacketTx) ValidateBasic() error {
	// TODO
	return nil
}

// Wrap - used to satisfy TxInner
func (p PostPacketTx) Wrap() sdk.Tx {
	return sdk.Tx{p}
}
