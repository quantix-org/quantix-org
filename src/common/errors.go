// MIT License
// Copyright (c) 2024 quantix-org

// Package common provides shared utilities and error handling for Quantix.
package common

import (
	"errors"
	"fmt"
)

// =====================================================
// Standard Error Types
// =====================================================

// ErrorCode represents a categorized error code for Quantix operations.
type ErrorCode int

const (
	// General errors (1-99)
	ErrCodeUnknown       ErrorCode = 1
	ErrCodeInternal      ErrorCode = 2
	ErrCodeInvalidInput  ErrorCode = 3
	ErrCodeNotFound      ErrorCode = 4
	ErrCodeAlreadyExists ErrorCode = 5
	ErrCodeTimeout       ErrorCode = 6
	ErrCodeCancelled     ErrorCode = 7

	// Cryptography errors (100-199)
	ErrCodeInvalidSignature   ErrorCode = 100
	ErrCodeInvalidPublicKey   ErrorCode = 101
	ErrCodeInvalidPrivateKey  ErrorCode = 102
	ErrCodeSignatureFailed    ErrorCode = 103
	ErrCodeVerificationFailed ErrorCode = 104
	ErrCodeHashMismatch       ErrorCode = 105
	ErrCodeInvalidProof       ErrorCode = 106

	// Transaction errors (200-299)
	ErrCodeInvalidTransaction ErrorCode = 200
	ErrCodeInsufficientFunds  ErrorCode = 201
	ErrCodeNonceTooLow        ErrorCode = 202
	ErrCodeNonceTooHigh       ErrorCode = 203
	ErrCodeGasLimitExceeded   ErrorCode = 204
	ErrCodeGasPriceTooLow     ErrorCode = 205
	ErrCodeInvalidRecipient   ErrorCode = 206
	ErrCodeTxAlreadyKnown     ErrorCode = 207
	ErrCodeTxPoolFull         ErrorCode = 208

	// Block errors (300-399)
	ErrCodeInvalidBlock       ErrorCode = 300
	ErrCodeInvalidBlockHash   ErrorCode = 301
	ErrCodeInvalidParentHash  ErrorCode = 302
	ErrCodeInvalidStateRoot   ErrorCode = 303
	ErrCodeInvalidTxRoot      ErrorCode = 304
	ErrCodeBlockTooLarge      ErrorCode = 305
	ErrCodeFutureBlock        ErrorCode = 306
	ErrCodeBlockGasExceeded   ErrorCode = 307

	// Consensus errors (400-499)
	ErrCodeInvalidValidator   ErrorCode = 400
	ErrCodeInvalidVote        ErrorCode = 401
	ErrCodeQuorumNotReached   ErrorCode = 402
	ErrCodeInvalidProposal    ErrorCode = 403
	ErrCodeViewChangeFailed   ErrorCode = 404
	ErrCodeDoubleSign         ErrorCode = 405
	ErrCodeSlashed            ErrorCode = 406
	ErrCodeInvalidVDF         ErrorCode = 407

	// State errors (500-599)
	ErrCodeStateNotFound      ErrorCode = 500
	ErrCodeStateMismatch      ErrorCode = 501
	ErrCodeStorageError       ErrorCode = 502
	ErrCodeCorruptedState     ErrorCode = 503

	// Network errors (600-699)
	ErrCodePeerNotFound     ErrorCode = 600
	ErrCodeConnectionFailed ErrorCode = 601
	ErrCodeHandshakeFailed  ErrorCode = 602
	ErrCodeMessageTooLarge  ErrorCode = 603
	ErrCodeProtocolViolation ErrorCode = 604

	// VM errors (700-799)
	ErrCodeOutOfGas          ErrorCode = 700
	ErrCodeStackUnderflow    ErrorCode = 701
	ErrCodeStackOverflow     ErrorCode = 702
	ErrCodeInvalidOpcode     ErrorCode = 703
	ErrCodeInvalidJump       ErrorCode = 704
	ErrCodeWriteProtection   ErrorCode = 705
	ErrCodeContractNotFound  ErrorCode = 706
	ErrCodeExecutionReverted ErrorCode = 707
	ErrCodeCodeSizeExceeded  ErrorCode = 708
)

// String returns a human-readable name for the error code.
func (c ErrorCode) String() string {
	switch c {
	case ErrCodeUnknown:
		return "UNKNOWN"
	case ErrCodeInternal:
		return "INTERNAL"
	case ErrCodeInvalidInput:
		return "INVALID_INPUT"
	case ErrCodeNotFound:
		return "NOT_FOUND"
	case ErrCodeAlreadyExists:
		return "ALREADY_EXISTS"
	case ErrCodeTimeout:
		return "TIMEOUT"
	case ErrCodeCancelled:
		return "CANCELLED"
	case ErrCodeInvalidSignature:
		return "INVALID_SIGNATURE"
	case ErrCodeInvalidPublicKey:
		return "INVALID_PUBLIC_KEY"
	case ErrCodeInvalidPrivateKey:
		return "INVALID_PRIVATE_KEY"
	case ErrCodeSignatureFailed:
		return "SIGNATURE_FAILED"
	case ErrCodeVerificationFailed:
		return "VERIFICATION_FAILED"
	case ErrCodeHashMismatch:
		return "HASH_MISMATCH"
	case ErrCodeInvalidProof:
		return "INVALID_PROOF"
	case ErrCodeInvalidTransaction:
		return "INVALID_TRANSACTION"
	case ErrCodeInsufficientFunds:
		return "INSUFFICIENT_FUNDS"
	case ErrCodeNonceTooLow:
		return "NONCE_TOO_LOW"
	case ErrCodeNonceTooHigh:
		return "NONCE_TOO_HIGH"
	case ErrCodeGasLimitExceeded:
		return "GAS_LIMIT_EXCEEDED"
	case ErrCodeGasPriceTooLow:
		return "GAS_PRICE_TOO_LOW"
	case ErrCodeInvalidRecipient:
		return "INVALID_RECIPIENT"
	case ErrCodeTxAlreadyKnown:
		return "TX_ALREADY_KNOWN"
	case ErrCodeTxPoolFull:
		return "TX_POOL_FULL"
	case ErrCodeInvalidBlock:
		return "INVALID_BLOCK"
	case ErrCodeInvalidBlockHash:
		return "INVALID_BLOCK_HASH"
	case ErrCodeInvalidParentHash:
		return "INVALID_PARENT_HASH"
	case ErrCodeInvalidStateRoot:
		return "INVALID_STATE_ROOT"
	case ErrCodeInvalidTxRoot:
		return "INVALID_TX_ROOT"
	case ErrCodeBlockTooLarge:
		return "BLOCK_TOO_LARGE"
	case ErrCodeFutureBlock:
		return "FUTURE_BLOCK"
	case ErrCodeBlockGasExceeded:
		return "BLOCK_GAS_EXCEEDED"
	case ErrCodeInvalidValidator:
		return "INVALID_VALIDATOR"
	case ErrCodeInvalidVote:
		return "INVALID_VOTE"
	case ErrCodeQuorumNotReached:
		return "QUORUM_NOT_REACHED"
	case ErrCodeInvalidProposal:
		return "INVALID_PROPOSAL"
	case ErrCodeViewChangeFailed:
		return "VIEW_CHANGE_FAILED"
	case ErrCodeDoubleSign:
		return "DOUBLE_SIGN"
	case ErrCodeSlashed:
		return "SLASHED"
	case ErrCodeInvalidVDF:
		return "INVALID_VDF"
	case ErrCodeStateNotFound:
		return "STATE_NOT_FOUND"
	case ErrCodeStateMismatch:
		return "STATE_MISMATCH"
	case ErrCodeStorageError:
		return "STORAGE_ERROR"
	case ErrCodeCorruptedState:
		return "CORRUPTED_STATE"
	case ErrCodePeerNotFound:
		return "PEER_NOT_FOUND"
	case ErrCodeConnectionFailed:
		return "CONNECTION_FAILED"
	case ErrCodeHandshakeFailed:
		return "HANDSHAKE_FAILED"
	case ErrCodeMessageTooLarge:
		return "MESSAGE_TOO_LARGE"
	case ErrCodeProtocolViolation:
		return "PROTOCOL_VIOLATION"
	case ErrCodeOutOfGas:
		return "OUT_OF_GAS"
	case ErrCodeStackUnderflow:
		return "STACK_UNDERFLOW"
	case ErrCodeStackOverflow:
		return "STACK_OVERFLOW"
	case ErrCodeInvalidOpcode:
		return "INVALID_OPCODE"
	case ErrCodeInvalidJump:
		return "INVALID_JUMP"
	case ErrCodeWriteProtection:
		return "WRITE_PROTECTION"
	case ErrCodeContractNotFound:
		return "CONTRACT_NOT_FOUND"
	case ErrCodeExecutionReverted:
		return "EXECUTION_REVERTED"
	case ErrCodeCodeSizeExceeded:
		return "CODE_SIZE_EXCEEDED"
	default:
		return fmt.Sprintf("ERROR_%d", c)
	}
}

// =====================================================
// QuantixError - Structured Error Type
// =====================================================

// QuantixError is the standard error type for Quantix operations.
// It provides error codes, messages, and supports error wrapping.
type QuantixError struct {
	Code    ErrorCode // Categorized error code
	Message string    // Human-readable error message
	Cause   error     // Underlying cause (for wrapping)
	Data    map[string]interface{} // Additional context
}

// Error implements the error interface.
func (e *QuantixError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code.String(), e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code.String(), e.Message)
}

// Unwrap returns the underlying cause for errors.Is/As support.
func (e *QuantixError) Unwrap() error {
	return e.Cause
}

// Is checks if target error matches this error's code.
func (e *QuantixError) Is(target error) bool {
	var qe *QuantixError
	if errors.As(target, &qe) {
		return e.Code == qe.Code
	}
	return false
}

// WithData adds context data to the error.
func (e *QuantixError) WithData(key string, value interface{}) *QuantixError {
	if e.Data == nil {
		e.Data = make(map[string]interface{})
	}
	e.Data[key] = value
	return e
}

// =====================================================
// Error Constructors
// =====================================================

// NewError creates a new QuantixError with the given code and message.
func NewError(code ErrorCode, message string) *QuantixError {
	return &QuantixError{
		Code:    code,
		Message: message,
	}
}

// NewErrorf creates a new QuantixError with a formatted message.
func NewErrorf(code ErrorCode, format string, args ...interface{}) *QuantixError {
	return &QuantixError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

// WrapError wraps an existing error with a QuantixError.
func WrapError(code ErrorCode, message string, cause error) *QuantixError {
	return &QuantixError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// WrapErrorf wraps an existing error with a formatted message.
func WrapErrorf(code ErrorCode, cause error, format string, args ...interface{}) *QuantixError {
	return &QuantixError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
		Cause:   cause,
	}
}

// =====================================================
// Common Pre-defined Errors
// =====================================================

var (
	// General
	ErrUnknown      = NewError(ErrCodeUnknown, "unknown error")
	ErrInternal     = NewError(ErrCodeInternal, "internal error")
	ErrInvalidInput = NewError(ErrCodeInvalidInput, "invalid input")
	ErrNotFound     = NewError(ErrCodeNotFound, "not found")
	ErrTimeout      = NewError(ErrCodeTimeout, "operation timed out")

	// Crypto
	ErrInvalidSignature   = NewError(ErrCodeInvalidSignature, "invalid signature")
	ErrInvalidPublicKey   = NewError(ErrCodeInvalidPublicKey, "invalid public key")
	ErrVerificationFailed = NewError(ErrCodeVerificationFailed, "verification failed")
	ErrHashMismatch       = NewError(ErrCodeHashMismatch, "hash mismatch")

	// Transaction
	ErrInvalidTransaction = NewError(ErrCodeInvalidTransaction, "invalid transaction")
	ErrInsufficientFunds  = NewError(ErrCodeInsufficientFunds, "insufficient funds")
	ErrNonceTooLow        = NewError(ErrCodeNonceTooLow, "nonce too low")
	ErrGasLimitExceeded   = NewError(ErrCodeGasLimitExceeded, "gas limit exceeded")

	// Block
	ErrInvalidBlock      = NewError(ErrCodeInvalidBlock, "invalid block")
	ErrInvalidBlockHash  = NewError(ErrCodeInvalidBlockHash, "invalid block hash")
	ErrInvalidParentHash = NewError(ErrCodeInvalidParentHash, "invalid parent hash")

	// Consensus
	ErrInvalidValidator = NewError(ErrCodeInvalidValidator, "invalid validator")
	ErrQuorumNotReached = NewError(ErrCodeQuorumNotReached, "quorum not reached")
	ErrDoubleSign       = NewError(ErrCodeDoubleSign, "double signing detected")

	// VM
	ErrOutOfGas         = NewError(ErrCodeOutOfGas, "out of gas")
	ErrStackUnderflow   = NewError(ErrCodeStackUnderflow, "stack underflow")
	ErrStackOverflow    = NewError(ErrCodeStackOverflow, "stack overflow")
	ErrInvalidOpcode    = NewError(ErrCodeInvalidOpcode, "invalid opcode")
	ErrExecutionReverted = NewError(ErrCodeExecutionReverted, "execution reverted")
)

// =====================================================
// Error Checking Utilities
// =====================================================

// IsQuantixError checks if err is a QuantixError and returns it.
func IsQuantixError(err error) (*QuantixError, bool) {
	var qe *QuantixError
	if errors.As(err, &qe) {
		return qe, true
	}
	return nil, false
}

// GetErrorCode extracts the error code from an error, or ErrCodeUnknown.
func GetErrorCode(err error) ErrorCode {
	if qe, ok := IsQuantixError(err); ok {
		return qe.Code
	}
	return ErrCodeUnknown
}

// IsErrorCode checks if an error has the specified code.
func IsErrorCode(err error, code ErrorCode) bool {
	return GetErrorCode(err) == code
}
