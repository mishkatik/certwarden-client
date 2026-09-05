package main

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"
)

// httpCWRoundTripper implements RoundTrip with headers for CertWarden Client
type httpCWRoundTripper struct {
	userAgent string
}

func (rt *httpCWRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// always override user-agent
	req.Header.Set("User-Agent", rt.userAgent)

	return http.DefaultTransport.RoundTrip(req)
}

// makeHttpClient returns an http.Client with a custom transport to ensure certain headers
// are added to all requests
func makeHttpClient() (client *http.Client) {
	t := &httpCWRoundTripper{
		userAgent: fmt.Sprintf("CertWardenClient/%s (%s; %s)", appVersion, runtime.GOOS, runtime.GOARCH),
	}

	return &http.Client{
		// set client timeout
		Timeout:   30 * time.Second,
		Transport: t,
	}
}

// httpStatusError reports an unexpected http status code from the server
type httpStatusError struct {
	status int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("error fetching pem (status: %d)", e.status)
}

// getPemWithApiKey fetches a pem response from the Cert Warden server. If etag is not blank, the request
// carries If-None-Match and a 304 answer yields notModified == true with nil pemContent. newETag is the
// ETag the server sent with the pem (blank if it sent none), or the etag passed in when the server
// answered 304; keep it for the next request.
func (app *app) getPemWithApiKey(ctx context.Context, url, apiKey, etag string) (pemContent []byte, newETag string, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", false, err
	}

	// set apiKey
	req.Header.Set("apiKey", apiKey)

	// make request conditional if the etag of the current data is known (send exactly as received)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	// do the request
	resp, err := app.httpClient.Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()

	// read body (before err check to ensure body is always read completely)
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", false, err
	}

	// not modified (only meaningful if we sent an etag)
	if resp.StatusCode == http.StatusNotModified {
		if etag == "" {
			return nil, "", false, errors.New("error fetching pem (server answered 304 to a request without an etag)")
		}
		return nil, etag, true, nil
	}

	// error if not code 200
	if resp.StatusCode != http.StatusOK {
		return nil, "", false, &httpStatusError{status: resp.StatusCode}
	}

	// validate the response data is actually pem
	pemBlock, _ := pem.Decode(bodyBytes)
	if pemBlock == nil {
		return nil, "", false, errors.New("error fetching pem (data from server was not valid pem data)")
	}

	return bodyBytes, resp.Header.Get("ETag"), false, nil
}
