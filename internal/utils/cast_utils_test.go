// Package utils
package utils

import "testing"

func ExampleStrToFloat() {
	StrToFloat("1234", 0)
}

func ExampleStrToInt() {
	StrToInt("1234", 0)
}

func TestStrToFloat(t *testing.T) {
	tests := []struct {
		input        string
		defaultValue float64
		expected     float64
	}{
		{"1", 0, 1},
		{"4654132", 1, 4654132},
		{"ABCD", 0, 0},
		{"ABCD", 100, 100},
		{"-1", 100, -1},
	}
	pass := 0
	fail := 0
	for _, test := range tests {
		result := StrToFloat(test.input, test.defaultValue)
		if result != test.expected {
			fail++
			t.Errorf("StrToFloat(%q, %v) = %v; expected %v", test.input, test.defaultValue, result, test.expected)
			continue
		}
		pass++
	}
	t.Logf("TestStrToFloat: %d pass, %d fail", pass, fail)
}

func TestStrToInt(t *testing.T) {
	tests := []struct {
		input        string
		defaultValue int
		expected     int
	}{
		{"1", 0, 1},
		{"4654132", 1, 4654132},
		{"ABCD", 0, 0},
		{"ABCD", 100, 100},
		{"-1", 100, -1},
	}
	pass := 0
	fail := 0
	for _, test := range tests {
		result := StrToInt(test.input, test.defaultValue)
		if result != test.expected {
			fail++
			t.Errorf("StrToInt(%q, %v) = %v; expected %v", test.input, test.defaultValue, result, test.expected)
			continue
		}
		pass++
	}
	t.Logf("TestStrToInt: %d pass, %d fail", pass, fail)
}
