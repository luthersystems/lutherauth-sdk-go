package jwk

import (
	"testing"
	"time"
)

func TestIsBeforeWithDrift(t *testing.T) {
	type testCase struct {
		t1     int64
		t2     int64
		result bool
	}
	testCases := map[string]testCase{
		"Before": {
			t1:     10000,
			t2:     12000,
			result: true,
		},
		"After": {
			t1:     12000,
			t2:     10000,
			result: false,
		},
		"In drift zone": {
			t1:     10000,
			t2:     9996,
			result: true,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if isBeforeWithDrift(time.Unix(tc.t1, 0), time.Unix(tc.t2, 0)) != tc.result {
				t.Fatal("Wrong result")
			}
		})
	}
}

func TestIsAfterWithDrift(t *testing.T) {
	type testCase struct {
		t1     int64
		t2     int64
		result bool
	}
	testCases := map[string]testCase{
		"Before": {
			t1:     10000,
			t2:     12000,
			result: false,
		},
		"After": {
			t1:     12000,
			t2:     10000,
			result: true,
		},
		"In drift zone": {
			t1:     10000,
			t2:     10012,
			result: true,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if isAfterWithDrift(time.Unix(tc.t1, 0), time.Unix(tc.t2, 0)) != tc.result {
				t.Fatal("Wrong result")
			}
		})
	}
}
