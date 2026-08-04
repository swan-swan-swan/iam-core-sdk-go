package nilcheck

import "testing"

type sample struct{}

func TestIsNilRecognizesTypedNilAndOrdinaryValues(t *testing.T) {
	var pointer *sample
	var function func()
	if !IsNil(pointer) || !IsNil(function) || !IsNil(nil) {
		t.Fatal("typed nil was not recognized")
	}
	if IsNil(sample{}) || IsNil("value") {
		t.Fatal("ordinary value was reported nil")
	}
}
