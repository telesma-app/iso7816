package scp11

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/telesma-app/iso7816"
)

// ReadCertificates selects the GlobalPlatform Security Domain and reads the
// referenced SCP11 card certificate chain. The certificates are untrusted,
// ordered leaf-last as returned by the card. The caller verifies their trust
// and intended use before supplying the leaf public key to Open.
//
// It borrows connection and leaves the Security Domain selected. The caller
// selects the intended application before Open and serializes this initialization
// sequence. Do not use an established secure channel or active application
// session here; selecting another application can clear its authentication state.
func ReadCertificates(ctx context.Context, connection APDU, keyVersion, keyID byte) ([]*x509.Certificate, error) {
	response, err := connection.Exchange(ctx, iso7816.Command{
		INS: 0xa4, P1: 4,
		Data: []byte{0xa0, 0, 0, 1, 0x51, 0, 0, 0},
		Le:   256, Encoding: iso7816.EncodingShort,
	})
	if err != nil {
		return nil, err
	}

	if err := response.APDUError(); err != nil {
		return nil, fmt.Errorf("scp11: select Security Domain: %w", err)
	}

	response, err = connection.Exchange(ctx, iso7816.Command{
		INS: 0xca, P1: 0xbf, P2: 0x21,
		Data: []byte{0xa6, 4, 0x83, 2, keyID, keyVersion},
		Le:   256, Encoding: iso7816.EncodingShort,
	})
	if err != nil {
		return nil, err
	}

	if err := response.APDUError(); err != nil {
		return nil, fmt.Errorf("scp11: read card certificates: %w", err)
	}

	certificates, err := x509.ParseCertificates(response.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: SCP11 certificates: %v", iso7816.ErrInvalidResponse, err)
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("%w: empty SCP11 certificate chain", iso7816.ErrInvalidResponse)
	}

	return certificates, nil
}
