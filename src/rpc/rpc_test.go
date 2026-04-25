// MIT License
// Copyright (c) 2024 quantix
package rpc_test

import (
	"testing"

	"github.com/quantix-org/quantix-org/src/rpc"
)

func TestGetRPCID_NonZero(t *testing.T) {
	id := rpc.GetRPCID()
	if id == 0 {
		t.Error("GetRPCID returned 0; expected non-zero")
	}
}

func TestGetRPCID_Unique(t *testing.T) {
	ids := make(map[rpc.RPCID]bool)
	for i := 0; i < 100; i++ {
		id := rpc.GetRPCID()
		if ids[id] {
			t.Errorf("GetRPCID returned duplicate ID: %d", id)
		}
		ids[id] = true
	}
}

func TestRPCTypeString_KnownTypes(t *testing.T) {
	tests := []struct {
		rpcType rpc.RPCType
		want    string
	}{
		{rpc.RPCGetBlockCount, "getblockcount"},
		{rpc.RPCGetBestBlockHash, "getbestblockhash"},
		{rpc.RPCGetBlock, "getblock"},
		{rpc.RPCGetBlocks, "getblocks"},
		{rpc.RPCSendRawTransaction, "sendrawtransaction"},
		{rpc.RPCGetTransaction, "gettransaction"},
		{rpc.RPCPing, "ping"},
		{rpc.RPCJoin, "join"},
		{rpc.RPCFindNode, "findnode"},
		{rpc.RPCGetBlockByNumber, "getblockbynumber"},
		{rpc.RPCGetBlockHash, "getblockhash"},
		{rpc.RPCGetDifficulty, "getdifficulty"},
		{rpc.RPCGetChainTip, "getchaintip"},
		{rpc.RPCGetNetworkInfo, "getnetworkinfo"},
		{rpc.RPCGetMiningInfo, "getmininginfo"},
		{rpc.RPCEstimateFee, "estimatefee"},
		{rpc.RPCGetMemPoolInfo, "getmempoolinfo"},
		{rpc.RPCValidateAddress, "validateaddress"},
		{rpc.RPCVerifyMessage, "verifymessage"},
		{rpc.RPCGetRawTransaction, "getrawtransaction"},
	}
	for _, tt := range tests {
		got := tt.rpcType.String()
		if got != tt.want {
			t.Errorf("RPCType(%d).String() = %q, want %q", tt.rpcType, got, tt.want)
		}
	}
}

func TestRPCTypeString_Unknown(t *testing.T) {
	unknown := rpc.RPCType(100)
	got := unknown.String()
	if got != "unknown" {
		t.Errorf("unknown RPCType.String() = %q, want \"unknown\"", got)
	}
}

func TestRPCTypeString_AllNonEmpty(t *testing.T) {
	// Ensure all sequential RPCType values from 0 to 20 have non-empty strings
	for i := 0; i <= 20; i++ {
		s := rpc.RPCType(i).String()
		if s == "" {
			t.Errorf("RPCType(%d).String() returned empty string", i)
		}
	}
}
