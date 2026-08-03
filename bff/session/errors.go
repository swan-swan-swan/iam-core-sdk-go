package session

import "errors"

var (
	ErrNotFound  = errors.New("session: not found")
	ErrExpired   = errors.New("session: expired")
	ErrConflict  = errors.New("session: conflict")
	ErrLeaseLost = errors.New("session: refresh lease lost")
)
