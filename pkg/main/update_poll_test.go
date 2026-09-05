package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNextPollWait(t *testing.T) {
	const m = time.Minute
	const h = time.Hour

	tests := []struct {
		name          string
		allOk         bool
		retryDelay    time.Duration
		pollInterval  time.Duration
		wantWait      time.Duration
		wantNextRetry time.Duration
	}{
		{"success waits the poll interval and resets retry", true, 2 * h, 6 * h, 6 * h, 15 * m},
		{"first failure", false, 15 * m, 6 * h, 15 * m, 30 * m},
		{"second failure doubles", false, 30 * m, 6 * h, 30 * m, 1 * h},
		{"doubling is capped at the poll interval", false, 4 * h, 6 * h, 4 * h, 6 * h},
		{"stays at the poll interval once capped", false, 6 * h, 6 * h, 6 * h, 6 * h},
		{"poll interval shorter than retry: wait is the poll interval", false, 15 * m, 1 * m, 1 * m, 1 * m},
		{"poll interval between retry and 2x retry", false, 15 * m, 20 * m, 15 * m, 20 * m},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wait, next := nextPollWait(tc.allOk, tc.retryDelay, tc.pollInterval)
			if wait != tc.wantWait || next != tc.wantNextRetry {
				t.Fatalf("nextPollWait(%t, %s, %s) = (%s, %s), want (%s, %s)", tc.allOk, tc.retryDelay, tc.pollInterval, wait, next, tc.wantWait, tc.wantNextRetry)
			}
		})
	}
}

// waitForFile polls until the file has the expected content or the timeout expires
func waitForFile(t *testing.T, path, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got, err := os.ReadFile(path)
		if err == nil && string(got) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: got %q (err %v), want %q", path, got, err, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// pinModTime sets the mod time of the files to a fixed instant in the past, so a rewrite (even
// with identical content) shows up regardless of filesystem timestamp resolution
func pinModTime(t *testing.T, paths ...string) time.Time {
	t.Helper()
	pinned := time.Unix(1600000000, 0)
	for _, p := range paths {
		if err := os.Chtimes(p, pinned, pinned); err != nil {
			t.Fatal(err)
		}
	}
	return pinned
}

func assertNotRewritten(t *testing.T, pinned time.Time, paths ...string) {
	t.Helper()
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if !info.ModTime().Equal(pinned) {
			t.Fatalf("%s was rewritten (mod time %s, pinned %s)", p, info.ModTime(), pinned)
		}
	}
}

// newPollTestApp returns an app with one cert whose files live in a temp dir, no docker containers
// and a file update window that is always open (so scheduled writes run immediately)
func newPollTestApp(t *testing.T, serverURL string) (a *app, keyPath, certPath string) {
	t.Helper()
	dir := t.TempDir()
	a = newFetchTestApp(serverURL)
	cert := &a.cfg.Certs[0]
	cert.CertStoragePath = dir
	cert.KeyPemFilename = "key0.pem"
	cert.CertPemFilename = "certchain0.pem"
	cert.KeyPermissions = defaultKeyPermissions
	cert.CertPermissions = defaultCertPermissions
	cert.DockerContainersToRestart = []string{}
	cert.FileUpdateTimeStartHour, cert.FileUpdateTimeStartMinute = 0, 0
	cert.FileUpdateTimeEndHour, cert.FileUpdateTimeEndMinute = 23, 59
	cert.FileUpdateDaysOfWeek = allWeekdays
	return a, filepath.Join(dir, "key0.pem"), filepath.Join(dir, "certchain0.pem")
}

// pendingJobCancel returns the registered cancel func of the cert's pending job (nil if none)
func pendingJobCancel(a *app, certIndex int) any {
	a.pendingJobMu.Lock()
	defer a.pendingJobMu.Unlock()
	if a.pendingJobCancels[certIndex] == nil {
		return nil
	}
	return a.pendingJobCancels[certIndex]
}

func TestPollCertEndToEnd(t *testing.T) {
	keyA, certA := makeTestKeyCert(t)
	s := newPemTestServer(keyA+"\n"+certA, "certkey.keykey", true)
	defer s.srv.Close()
	app, keyPath, certPath := newPollTestApp(t, s.srv.URL)

	// 1: first poll fetches and writes the missing files immediately
	if !app.pollCert(0) {
		t.Fatal("first poll failed")
	}
	waitForFile(t, keyPath, keyA, time.Second)
	waitForFile(t, certPath, certA, time.Second)
	if info, _ := os.Stat(keyPath); info.Mode().Perm() != defaultKeyPermissions {
		t.Fatalf("key file permissions %o, want %o", info.Mode().Perm(), defaultKeyPermissions)
	}

	// 2: nothing changed on server -> 304, files untouched
	pinned := pinModTime(t, keyPath, certPath)
	if !app.pollCert(0) {
		t.Fatal("second poll failed")
	}
	if s.requestCount() != 2 {
		t.Fatalf("expected 2 requests, got %d", s.requestCount())
	}
	assertNotRewritten(t, pinned, keyPath, certPath)

	// 3: server has a new pair -> files exist but are stale -> write job scheduled and (window open) executed
	keyB, certB := makeTestKeyCert(t)
	s.setBody(keyB + "\n" + certB)
	if !app.pollCert(0) {
		t.Fatal("third poll failed")
	}
	waitForFile(t, keyPath, keyB, 5*time.Second)
	waitForFile(t, certPath, certB, 5*time.Second)

	// 4: server unreachable -> poll reports failure, files untouched
	pinned = pinModTime(t, keyPath, certPath)
	s.srv.Close()
	if app.pollCert(0) {
		t.Fatal("poll must fail when the server is unreachable")
	}
	assertNotRewritten(t, pinned, keyPath, certPath)
}

func TestPollCertUpgradeWithCurrentFilesOnDisk(t *testing.T) {
	// files written by the previous client version are already current: nothing must be rewritten
	keyA, certA := makeTestKeyCert(t)
	s := newPemTestServer(keyA+"\n"+certA, "certkey.keykey", true)
	defer s.srv.Close()
	app, keyPath, certPath := newPollTestApp(t, s.srv.URL)

	if err := os.WriteFile(keyPath, []byte(keyA), defaultKeyPermissions); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte(certA), defaultCertPermissions); err != nil {
		t.Fatal(err)
	}
	pinned := pinModTime(t, keyPath, certPath)

	if !app.pollCert(0) {
		t.Fatal("poll failed")
	}
	assertNotRewritten(t, pinned, keyPath, certPath)
	if pendingJobCancel(app, 0) != nil {
		t.Fatal("no write job must be scheduled when files are current")
	}
}

func TestPollCertRepairsCorruptCertFile(t *testing.T) {
	// key file is current but the cert file is empty (e.g. interrupted write): must be treated as
	// missing and rewritten immediately, without panicking
	keyA, certA := makeTestKeyCert(t)
	s := newPemTestServer(keyA+"\n"+certA, "certkey.keykey", true)
	defer s.srv.Close()
	app, keyPath, certPath := newPollTestApp(t, s.srv.URL)

	if err := os.WriteFile(keyPath, []byte(keyA), defaultKeyPermissions); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte{}, defaultCertPermissions); err != nil {
		t.Fatal(err)
	}

	if !app.pollCert(0) {
		t.Fatal("poll failed")
	}
	waitForFile(t, certPath, certA, time.Second)
	waitForFile(t, keyPath, keyA, time.Second)
}

func TestPollCertCancelsPendingJobWhenFilesWrittenImmediately(t *testing.T) {
	keyA, certA := makeTestKeyCert(t)
	s := newPemTestServer(keyA+"\n"+certA, "certkey.keykey", true)
	defer s.srv.Close()
	app, keyPath, certPath := newPollTestApp(t, s.srv.URL)

	// close the file update window (only a weekday that is neither today nor yesterday)
	closedDay := (time.Now().Weekday() + 3) % 7
	app.cfg.Certs[0].FileUpdateDaysOfWeek = map[time.Weekday]struct{}{closedDay: {}}

	// 1: missing files are written immediately even though the window is closed; no job pending
	if !app.pollCert(0) {
		t.Fatal("first poll failed")
	}
	waitForFile(t, keyPath, keyA, time.Second)
	waitForFile(t, certPath, certA, time.Second)
	if pendingJobCancel(app, 0) != nil {
		t.Fatal("no job must be pending after writing missing files")
	}

	// 2: new pair, files stale -> write deferred to the window -> job pending, files untouched
	keyB, certB := makeTestKeyCert(t)
	s.setBody(keyB + "\n" + certB)
	pinned := pinModTime(t, keyPath, certPath)
	if !app.pollCert(0) {
		t.Fatal("second poll failed")
	}
	if pendingJobCancel(app, 0) == nil {
		t.Fatal("a write job must be pending for the closed window")
	}
	assertNotRewritten(t, pinned, keyPath, certPath)

	// 3: key file disappears and a newer pair arrives -> written immediately -> pending job canceled
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	keyC, certC := makeTestKeyCert(t)
	s.setBody(keyC + "\n" + certC)
	if !app.pollCert(0) {
		t.Fatal("third poll failed")
	}
	waitForFile(t, keyPath, keyC, time.Second)
	waitForFile(t, certPath, certC, time.Second)
	if pendingJobCancel(app, 0) != nil {
		t.Fatal("the obsolete pending job must have been canceled")
	}
}
