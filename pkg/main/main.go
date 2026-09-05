package main

import (
	"time"
)

// version
const appVersion = "0.6.0"

// main entrypoint
func main() {
	// configure app
	app, err := configureApp()
	if err != nil {
		// only fails if config is bad, so fatal ok
		app.logger.Fatalf("failed to configure app (%s)", err)
		// os.Exit(1)
	}

	// start polling the server for key/cert updates (first poll runs immediately)
	app.startPolling()

	// shutdown logic
	// wait for shutdown context to signal
	<-app.shutdownContext.Done()

	// cancel any pending jobs
	for certIndex := range app.cfg.Certs {
		app.cancelPendingJob(certIndex)
	}

	// wait for each component/service to shutdown
	// but also implement a maxWait chan to force close (panic)
	maxWait := 2 * time.Minute
	waitChan := make(chan struct{})

	// close wait chan when wg finishes waiting
	go func() {
		defer close(waitChan)
		app.shutdownWaitgroup.Wait()
	}()

	select {
	case <-waitChan:
		// continue, normal
	case <-time.After(maxWait):
		// timed out
		app.logger.Panic("graceful shutdown of component(s) failed due to time out, forcing shutdown")
	}

	app.logger.Info("cert warden client exited")
}
