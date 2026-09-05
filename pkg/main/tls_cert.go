package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"sync"
)

// SafeCert holds a key/certificate pem pair
type SafeCert struct {
	keyPem  []byte
	certPem []byte

	sync.RWMutex
}

// NewSafeCert makes a SafeCert
func NewSafeCert() *SafeCert {
	return &SafeCert{}
}

// Read returns the pem currently in use
func (sc *SafeCert) Read() (keyPem, certPem []byte) {
	sc.RLock()
	defer sc.RUnlock()

	return sc.keyPem, sc.certPem
}

// Update checks that keyPem and certPem match and stores them if they differ from the current
// pem. updated reports whether the stored pem changed. Update rejects an invalid pair and leaves
// the stored pem untouched.
func (sc *SafeCert) Update(keyPem, certPem []byte) (updated bool, err error) {
	sc.Lock()
	defer sc.Unlock()

	// if no update to do, don't do anything
	if bytes.Equal(sc.keyPem, keyPem) && bytes.Equal(sc.certPem, certPem) {
		return false, nil
	}

	// validate the pair BEFORE storing anything so an invalid pair never ends up in memory (or on disk)
	_, err = tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return false, fmt.Errorf("failed to make x509 key pair for key/cert update (%s)", err)
	}

	// update pem
	sc.keyPem = keyPem
	sc.certPem = certPem

	return true, nil
}
