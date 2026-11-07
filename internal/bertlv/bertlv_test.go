package bertlv

import (
	"bytes"
	"errors"
	"testing"
)

func TestAppend(t *testing.T) {
	tests := []struct {
		name  string
		tag   uint32
		value []byte
		want  []byte
	}{
		{name: "empty", tag: 0x82, want: []byte{0x82, 0}},
		{name: "short", tag: 0x53, value: []byte{1, 2}, want: []byte{0x53, 2, 1, 2}},
		{name: "two byte tag", tag: 0x7f49, value: []byte{0x81, 0}, want: []byte{0x7f, 0x49, 2, 0x81, 0}},
		{name: "three byte tag", tag: 0x5fc105, value: []byte{3}, want: []byte{0x5f, 0xc1, 0x05, 1, 3}},
		{name: "four byte tag", tag: 0x7fffff01, want: []byte{0x7f, 0xff, 0xff, 1, 0}},
		{name: "long length", tag: 0x70, value: bytes.Repeat([]byte{0x42}, 128), want: append([]byte{0x70, 0x81, 0x80}, bytes.Repeat([]byte{0x42}, 128)...)},
		{name: "two byte length", tag: 0x70, value: bytes.Repeat([]byte{0x42}, 256), want: append([]byte{0x70, 0x82, 1, 0}, bytes.Repeat([]byte{0x42}, 256)...)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Append([]byte{0xaa}, test.tag, test.value)
			if !bytes.Equal(got, append([]byte{0xaa}, test.want...)) {
				t.Errorf("Append = %x, want prefix aa + %x", got, test.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	raw := []byte{0x5f, 0xc1, 5, 0x82, 0, 2, 0xaa, 0xbb, 0xfe, 0}

	tag, value, rest, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	if tag != 0x5fc105 || !bytes.Equal(value, []byte{0xaa, 0xbb}) || !bytes.Equal(rest, []byte{0xfe, 0}) {
		t.Errorf("Parse = (%x, %x, %x)", tag, value, rest)
	}

	value[0] = 0x11

	if raw[6] != 0x11 {
		t.Error("value does not borrow the original buffer")
	}

	if cap(value) != len(value) {
		t.Error("appending to value could overwrite the next object")
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "empty"},
		{name: "missing length", raw: []byte{0x53}},
		{name: "unterminated tag", raw: []byte{0x5f, 0x81}},
		{name: "tag leading zero", raw: []byte{0x5f, 0x80, 1, 0}},
		{name: "oversized tag", raw: []byte{0x7f, 0xff, 0xff, 0xff, 1, 0}},
		{name: "multibyte tag without length", raw: []byte{0x7f, 0x49}},
		{name: "indefinite length", raw: []byte{0x53, 0x80, 0, 0}},
		{name: "truncated length", raw: []byte{0x53, 0x82, 1}},
		{name: "oversized length", raw: []byte{0x53, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{name: "integer overflow length", raw: []byte{0x53, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{name: "truncated value", raw: []byte{0x53, 3, 1, 2}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, err := Parse(test.raw)
			if !errors.Is(err, ErrInvalidEncoding) {
				t.Errorf("Parse error = %v, want ErrInvalidEncoding", err)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{0x53, 1, 0x42, 0xfe, 0})
	f.Add([]byte{0x5f, 0xc1, 5, 0x81, 1, 0x42})
	f.Add([]byte{0x53, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, value, rest, err := Parse(raw)
		if err == nil && len(value)+len(rest) > len(raw)-2 {
			t.Fatalf("parsed value and rest exceed input: %x", raw)
		}
	})
}
