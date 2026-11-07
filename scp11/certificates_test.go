package scp11

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/telesma-app/iso7816"
)

type certificateStep struct {
	command  []byte
	response iso7816.Response
	err      error
}

type certificateReader struct {
	t     testing.TB
	steps []certificateStep
	calls int
}

func (reader *certificateReader) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	reader.t.Helper()

	if reader.calls >= len(reader.steps) {
		reader.t.Errorf("unexpected certificate discovery APDU: %+v", command)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	step := reader.steps[reader.calls]
	reader.calls++

	encoded, err := command.MarshalBinary()
	if err != nil {
		reader.t.Error(err)
		return iso7816.Response{}, err
	}

	if !bytes.Equal(encoded, step.command) {
		reader.t.Errorf("certificate discovery APDU = %x, want %x", encoded, step.command)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	return step.response, step.err
}

func newCertificateReader(t testing.TB, steps ...certificateStep) *certificateReader {
	t.Helper()

	reader := &certificateReader{t: t, steps: steps}
	t.Cleanup(func() {
		if reader.calls != len(steps) {
			t.Errorf("certificate discovery APDU count = %d, want %d", reader.calls, len(steps))
		}
	})

	return reader
}

func discoverySelect() certificateStep {
	return certificateStep{
		command:  []byte{0, 0xa4, 4, 0, 8, 0xa0, 0, 0, 1, 0x51, 0, 0, 0, 0},
		response: iso7816.Response{Status: 0x9000},
	}
}

func discoveryRead(data []byte) certificateStep {
	return certificateStep{
		command:  []byte{0, 0xca, 0xbf, 0x21, 6, 0xa6, 4, 0x83, 2, 0x13, 2, 0},
		response: iso7816.Response{Status: 0x9000, Data: data},
	}
}

func untrustedCertificate(t testing.TB, serial int64) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Discovery must return expired, unrelated self-signed certificates without
	// evaluating their trust. Verification is explicitly a caller responsibility.
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: fmt.Sprintf("untrusted certificate %d", serial)},
		NotBefore:    time.Unix(1, 0),
		NotAfter:     time.Unix(2, 0),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func TestReadCertificatesPreservesLeafLastOrderWithoutTrustEvaluation(t *testing.T) {
	issuer := untrustedCertificate(t, 1)
	leaf := untrustedCertificate(t, 2)
	chain := append(bytes.Clone(issuer), leaf...)
	reader := newCertificateReader(t, discoverySelect(), discoveryRead(chain))

	certificates, err := ReadCertificates(t.Context(), reader, 2, 0x13)
	if err != nil {
		t.Fatal(err)
	}

	if len(certificates) != 2 {
		t.Fatalf("certificate count = %d, want 2", len(certificates))
	}

	if !bytes.Equal(certificates[0].Raw, issuer) || !bytes.Equal(certificates[1].Raw, leaf) ||
		certificates[1].SerialNumber.Int64() != 2 {
		t.Error("certificate discovery reordered or changed the leaf-last chain")
	}
}

func TestReadCertificatesPreservesAPDUAndIOErrors(t *testing.T) {
	cause := errors.New("reader disconnected")

	for _, tc := range []struct {
		name   string
		read   bool
		status iso7816.StatusWord
		err    error
	}{
		{name: "select rejected", status: 0x6a82},
		{name: "select I/O", err: cause},
		{name: "GET DATA rejected", read: true, status: 0x6a88},
		{name: "GET DATA I/O", read: true, err: cause},
	} {
		t.Run(tc.name, func(t *testing.T) {
			steps := []certificateStep{discoverySelect()}
			if tc.read {
				steps = append(steps, discoveryRead(nil))
			}

			steps[len(steps)-1].response = iso7816.Response{Status: tc.status}
			steps[len(steps)-1].err = tc.err
			reader := newCertificateReader(t, steps...)

			certificates, err := ReadCertificates(t.Context(), reader, 2, 0x13)
			if certificates != nil || err == nil {
				t.Fatalf("ReadCertificates = %v, %v; want failure", certificates, err)
			}

			if tc.err != nil {
				if !errors.Is(err, cause) {
					t.Errorf("ReadCertificates = %v, want original I/O cause", err)
				}
			} else {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != tc.status {
					t.Errorf("ReadCertificates = %v, want APDU %s", err, tc.status)
				}
			}
		})
	}
}

func TestReadCertificatesRejectsEmptyOrMalformedChain(t *testing.T) {
	valid := untrustedCertificate(t, 1)

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "invalid certificate", data: []byte{0x30, 0}},
		{name: "truncated certificate", data: valid[:len(valid)-1]},
		{name: "trailing invalid data", data: append(bytes.Clone(valid), 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := newCertificateReader(t, discoverySelect(), discoveryRead(tc.data))

			certificates, err := ReadCertificates(t.Context(), reader, 2, 0x13)
			if certificates != nil || !errors.Is(err, iso7816.ErrInvalidResponse) {
				t.Errorf("ReadCertificates = %v, %v; want invalid response", certificates, err)
			}
		})
	}
}
