package session

import "errors"

var (
	ErrNotFound        = errors.New("session: not found")
	ErrExpired         = errors.New("session: expired")
	ErrVersionConflict = errors.New("session: version conflict")
	ErrLocked          = errors.New("session: locked")
	ErrLockLost        = errors.New("session: lock lost")
)
