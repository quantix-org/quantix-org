// go/src/core/stake_db.go
package core

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	logger "github.com/quantix-org/quantix-org/src/log"
)

const (
	stakePrefix       = "stake:"
	stakeRewardPrefix = "stake:reward:"
)

// StakeRecord holds validator stake information persisted in LevelDB.
type StakeRecord struct {
	NodeID        string   `json:"node_id"`
	StakeNQTX     *big.Int `json:"stake_nqtx"`
	RewardAddress string   `json:"reward_address"`
	Active        bool     `json:"active"`
}

// stakeRecordJSON is the serializable form of StakeRecord (big.Int → string).
type stakeRecordJSON struct {
	NodeID        string `json:"node_id"`
	StakeNQTX     string `json:"stake_nqtx"`
	RewardAddress string `json:"reward_address"`
	Active        bool   `json:"active"`
}

func toJSON(r *StakeRecord) []byte {
	j := stakeRecordJSON{
		NodeID:        r.NodeID,
		StakeNQTX:     r.StakeNQTX.String(),
		RewardAddress: r.RewardAddress,
		Active:        r.Active,
	}
	data, _ := json.Marshal(j)
	return data
}

func fromJSON(data []byte) (*StakeRecord, error) {
	var j stakeRecordJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, err
	}
	stake, ok := new(big.Int).SetString(j.StakeNQTX, 10)
	if !ok {
		stake = big.NewInt(0)
	}
	return &StakeRecord{
		NodeID:        j.NodeID,
		StakeNQTX:     stake,
		RewardAddress: j.RewardAddress,
		Active:        j.Active,
	}, nil
}

// GetValidatorStakeFromDB returns the stake for nodeID from LevelDB, or zero.
func (bc *Blockchain) GetValidatorStakeFromDB(nodeID string) *big.Int {
	db, err := bc.storage.GetDB()
	if err != nil {
		logger.Warn("GetValidatorStakeFromDB: %v", err)
		return big.NewInt(0)
	}
	data, err := db.Get(stakePrefix + nodeID)
	if err != nil || len(data) == 0 {
		return big.NewInt(0)
	}
	rec, err := fromJSON(data)
	if err != nil {
		return big.NewInt(0)
	}
	return rec.StakeNQTX
}

// SetValidatorStake writes or updates a stake record in LevelDB.
func (bc *Blockchain) SetValidatorStake(nodeID string, stakeNQTX *big.Int, rewardAddress string) error {
	db, err := bc.storage.GetDB()
	if err != nil {
		return fmt.Errorf("SetValidatorStake: %w", err)
	}
	rec := &StakeRecord{
		NodeID:        nodeID,
		StakeNQTX:     stakeNQTX,
		RewardAddress: rewardAddress,
		Active:        stakeNQTX.Sign() > 0,
	}
	return db.Put(stakePrefix+nodeID, toJSON(rec))
}

// GetAllStakes returns all validator stake records from LevelDB.
func (bc *Blockchain) GetAllStakes() ([]*StakeRecord, error) {
	db, err := bc.storage.GetDB()
	if err != nil {
		return nil, fmt.Errorf("GetAllStakes: %w", err)
	}
	// Use the raw LevelDB iterator via the underlying handle.
	rawDB := db.GetRawDB()
	if rawDB == nil {
		return nil, fmt.Errorf("GetAllStakes: raw db unavailable")
	}

	iter := rawDB.NewIterator(nil, nil)
	defer iter.Release()

	var records []*StakeRecord
	prefix := stakePrefix
	for iter.Next() {
		key := string(iter.Key())
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		// Skip reward sub-keys
		if strings.HasPrefix(key, stakeRewardPrefix) {
			continue
		}
		rec, err := fromJSON(iter.Value())
		if err != nil {
			continue
		}
		records = append(records, rec)
	}
	return records, iter.Error()
}

// GetTotalStakedFromDB returns the sum of all validator stakes from LevelDB.
func (bc *Blockchain) GetTotalStakedFromDB() *big.Int {
	records, err := bc.GetAllStakes()
	if err != nil {
		logger.Warn("GetTotalStakedFromDB: %v", err)
		return big.NewInt(0)
	}
	total := big.NewInt(0)
	for _, r := range records {
		if r.StakeNQTX != nil {
			total.Add(total, r.StakeNQTX)
		}
	}
	return total
}
