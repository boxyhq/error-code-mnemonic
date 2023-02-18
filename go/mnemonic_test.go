package mnemonic

import (
	"testing"
)

func TestNew(t *testing.T) {
		mnemonic, err := New(3)
		if err != nil {
			t.Error(err)
		}
		print(mnemonic)
}