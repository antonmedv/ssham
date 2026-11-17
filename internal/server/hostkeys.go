package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"

	gossh "golang.org/x/crypto/ssh"
)

// hostKey is one of the device's SSH host keys.
type hostKey struct {
	signer gossh.Signer
	// dropbear is the key in dropbear's own format, as it is stored in
	// /etc/dropbear on the device.
	dropbear []byte
	path     string // where dropbear keeps it
}

// loadHostKeys loads the device's host keys from dir, generating any that
// are missing. Dropbear 2019.78 has no ed25519, so the keys are ECDSA
// P-256 and RSA, the two it generates by default, in the order it offers
// them.
func loadHostKeys(dir string) ([]hostKey, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	ec, err := loadOrCreate(filepath.Join(dir, "ssham_ecdsa_key"), func() (crypto.Signer, error) {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	})
	if err != nil {
		return nil, err
	}
	rk, err := loadOrCreate(filepath.Join(dir, "ssham_rsa_key"), func() (crypto.Signer, error) {
		return rsa.GenerateKey(rand.Reader, 2048)
	})
	if err != nil {
		return nil, err
	}

	ecKey, ok := ec.(*ecdsa.PrivateKey)
	if !ok || ecKey.Curve != elliptic.P256() {
		return nil, errors.New("ssham_ecdsa_key: not an ECDSA P-256 key")
	}
	rsaKey, ok := rk.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("ssham_rsa_key: not an RSA key")
	}

	ecSigner, err := gossh.NewSignerFromSigner(ecKey)
	if err != nil {
		return nil, err
	}
	rsaSigner, err := gossh.NewSignerFromSigner(rsaKey)
	if err != nil {
		return nil, err
	}
	// Dropbear 2019.78 signs host keys with SHA-1 only (ssh-rsa).
	rsaSHA1, err := gossh.NewSignerWithAlgorithms(rsaSigner.(gossh.AlgorithmSigner), []string{gossh.KeyAlgoRSA})
	if err != nil {
		return nil, err
	}
	return []hostKey{
		{ecSigner, dropbearECDSA(ecKey), "/etc/dropbear/dropbear_ecdsa_host_key"},
		{rsaSHA1, dropbearRSA(rsaKey), "/etc/dropbear/dropbear_rsa_host_key"},
	}, nil
}

func loadOrCreate(path string, generate func() (crypto.Signer, error)) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		key, err := generate()
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		data = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return nil, err
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM data", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: not a signing key", path)
	}
	return signer, nil
}

// dropbear's key files are SSH wire-format fields, one after another.
type wire []byte

func (w wire) str(b []byte) wire {
	n := len(b)
	return append(append(w, byte(n>>24), byte(n>>16), byte(n>>8), byte(n)), b...)
}

func (w wire) mpint(x *big.Int) wire {
	b := x.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return w.str(b)
}

func dropbearECDSA(k *ecdsa.PrivateKey) []byte {
	pub, _ := k.PublicKey.ECDH()
	priv, _ := k.ECDH()
	return wire(nil).
		str([]byte("ecdsa-sha2-nistp256")).
		str([]byte("nistp256")).
		str(pub.Bytes()).
		mpint(new(big.Int).SetBytes(priv.Bytes()))
}

func dropbearRSA(k *rsa.PrivateKey) []byte {
	return wire(nil).
		str([]byte("ssh-rsa")).
		mpint(big.NewInt(int64(k.E))).
		mpint(k.N).
		mpint(k.D).
		mpint(k.Primes[0]).
		mpint(k.Primes[1])
}
