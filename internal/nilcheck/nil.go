// Package nilcheck detects nil values hidden inside public interface
// collaborators.
package nilcheck

import "reflect"

// IsNil reports whether value is nil, including a typed nil stored in an
// interface.
func IsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
