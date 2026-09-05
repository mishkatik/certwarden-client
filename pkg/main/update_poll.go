package main

import (
	"math/rand"
	"time"
)

// nextPollWait returns how long to wait before the next poll iteration and the retry delay to use
// after it. allOk is whether the iteration that just completed synced every cert. retryDelay is the
// delay to use if the iteration failed; it starts at pollRetryInterval and doubles on each
// consecutive failed iteration, never exceeding pollInterval. The caller adds jitter.
func nextPollWait(allOk bool, retryDelay, pollInterval time.Duration) (wait, nextRetryDelay time.Duration) {
	if allOk {
		return pollInterval, pollRetryInterval
	}

	wait = min(retryDelay, pollInterval)
	return wait, min(wait*2, pollInterval)
}

// startPolling starts the poll loop that keeps the in-memory key/cert of each certificate in sync
// with the server and writes changes to disk. The first iteration runs immediately; subsequent
// iterations run every PollInterval (plus a random jitter of up to a minute). If any certificate
// failed to sync, the next iteration runs sooner: after pollRetryInterval, doubling on each
// consecutive failed iteration until PollInterval is reached.
func (app *app) startPolling() {
	app.shutdownWaitgroup.Add(1)

	go func() {
		defer app.shutdownWaitgroup.Done()

		retryDelay := pollRetryInterval

		for {
			// poll each cert (sequentially, in this goroutine)
			allOk := true
			for certIndex := range app.cfg.Certs {
				// stop if shutting down
				if app.shutdownContext.Err() != nil {
					app.logger.Info("poll loop shutdown complete")
					return
				}

				if !app.pollCert(certIndex) {
					allOk = false
				}
			}

			// stop if shutdown happened during the last poll (don't log a next poll that won't happen)
			if app.shutdownContext.Err() != nil {
				app.logger.Info("poll loop shutdown complete")
				return
			}

			// calculate delay until next iteration and add random jitter
			var wait time.Duration
			wait, retryDelay = nextPollWait(allOk, retryDelay, app.cfg.PollInterval)
			wait += time.Duration(rand.Intn(60)) * time.Second

			nextRunString := time.Now().Round(time.Second).Add(wait).String()
			if allOk {
				app.logger.Infof("next server poll for key/cert updates scheduled for %s", nextRunString)
			} else {
				app.logger.Infof("at least one key/cert failed to sync, next server poll (retry) scheduled for %s", nextRunString)
			}

			// wait for next iteration (or shutdown)
			select {
			case <-app.shutdownContext.Done():
				app.logger.Info("poll loop shutdown complete")
				return

			case <-time.After(wait):
				// next iteration
			}
		}
	}()
}

// pollCert fetches the latest key/cert for the specified cert index from the server and, if it
// changed, updates the files on disk (immediately if any file is missing, otherwise during the next
// permitted file update window) and restarts the configured docker containers. It returns false if
// the fetch failed.
func (app *app) pollCert(certIndex int) bool {
	// try and get newer key/cert from server
	updated, err := app.updateClientKeyAndCertchain(certIndex)
	if err != nil {
		// don't log an error if the fetch was aborted by shutdown
		if app.shutdownContext.Err() != nil {
			return false
		}

		app.logger.Errorf("failed to fetch key/cert %d from server (%s), will retry", certIndex, err)
		return false
	}

	// nothing changed on the server
	if !updated {
		app.logger.Debugf("key/cert %d unchanged on server", certIndex)
		return true
	}

	// new key/cert: write files now if any is missing; the call also reports whether the disk still
	// needs an update. If so, schedule a job; otherwise cancel any old pending job (its content is
	// obsolete and the disk is current).
	diskNeedsUpdate := app.updateCertFilesAndRestartContainers(certIndex, true)

	if diskNeedsUpdate {
		app.scheduleJobWriteCertsMemoryToDisk(certIndex)
	} else {
		app.cancelPendingJob(certIndex)
	}

	return true
}
