package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
)

// Server Endpoints
const (
	// serverEndpointDownloadPrivateCertChains returns the private key pem, a line feed, and then the
	// certificate chain pem of the certificate's newest valid order, so key and cert match.
	// The apiKey header is the certificate's api key and the private key's api key joined by a period.
	serverEndpointDownloadPrivateCertChains = "/certwarden/api/v1/download/privatecertchains"
)

// certPemHeader is the start of the first certificate block in the combined pem
var certPemHeader = []byte("-----BEGIN CERTIFICATE-----")

// splitKeyAndCertChainPem splits the combined pem returned by the private cert chain endpoint
// (key pem + "\n" + cert chain pem) into the key pem and the cert chain pem. It splits raw bytes,
// so the key pem and cert pem come out byte for byte identical to what the server stores and to
// what the separate key and certificate download endpoints return.
func splitKeyAndCertChainPem(combinedPem []byte) (keyPem, certPem []byte, err error) {
	idx := bytes.Index(combinedPem, certPemHeader)
	if idx <= 0 {
		return nil, nil, errors.New("combined pem from server does not contain a key followed by a certificate")
	}
	if combinedPem[idx-1] != '\n' {
		return nil, nil, errors.New("combined pem from server has an unexpected format (no separator before certificate)")
	}

	// drop the single line feed the server inserts between the key and the cert
	keyPem = combinedPem[:idx-1]
	certPem = combinedPem[idx:]

	if len(keyPem) == 0 {
		return nil, nil, errors.New("combined pem from server does not contain a key")
	}

	return keyPem, certPem, nil
}

// updateClientKeyAndCertchain queries the server for the specified certificate's key and cert chain
// and updates the app's in-memory key/cert if they changed. updated reports whether the in-memory
// key/cert changed. The request carries the ETag of the last fetch, so an unchanged key/cert
// transfers no data.
func (app *app) updateClientKeyAndCertchain(certIndex int) (updated bool, err error) {
	url := app.cfg.ServerAddress + serverEndpointDownloadPrivateCertChains + "/" + app.cfg.Certs[certIndex].CertName
	apiKey := app.cfg.Certs[certIndex].CertApiKey + "." + app.cfg.Certs[certIndex].KeyApiKey

	combinedPem, etag, notModified, err := app.getPemWithApiKey(app.shutdownContext, url, apiKey, app.pollETags[certIndex])
	if err != nil {
		// add a hint for authorization failures
		var statusErr *httpStatusError
		if errors.As(err, &statusErr) && (statusErr.status == http.StatusUnauthorized || statusErr.status == http.StatusForbidden) {
			return false, fmt.Errorf("failed to get key/cert pem %d from server (%s) - check CERT_APIKEY and KEY_APIKEY (if the certificate was switched to another private key on the server, update KEY_APIKEY)", certIndex, err)
		}
		return false, fmt.Errorf("failed to get key/cert pem %d from server (%s)", certIndex, err)
	}

	// unchanged since the last successful fetch
	if notModified {
		return false, nil
	}

	// split into key and cert chain
	keyPem, certPem, err := splitKeyAndCertChainPem(combinedPem)
	if err != nil {
		return false, fmt.Errorf("failed to parse key/cert pem %d from server (%s)", certIndex, err)
	}

	// do update of in-memory key/cert (validates the pair)
	updated, err = app.updateClientCert(keyPem, certPem, certIndex)
	if err != nil {
		// etag stays as it was, so the next poll fetches again
		return false, err
	}

	// remember etag so the next poll can be conditional
	app.pollETags[certIndex] = etag

	return updated, nil
}
