package main

import (
	"context"
	"math/rand"
	"time"
)

// inFileUpdateWindow returns true if the job should run immediately because t is in the
// permitted file update time window
func (app *app) inFileUpdateWindow(certIndex int, t time.Time) bool {
	// check if t is an approved starting weekday or if the day before was approved
	approvedWeekday := false
	prevDayWasApprovedWeekday := false
	for weekday := range app.cfg.Certs[certIndex].FileUpdateDaysOfWeek {
		// check today
		if t.Weekday() == weekday {
			approvedWeekday = true
		}

		// check yesterday
		if (t.Weekday()+7-1)%7 == weekday {
			prevDayWasApprovedWeekday = true
		}
	}

	// compare t to start and end times
	tAfterOrEqualStartTime := timeAIsAfterOrEqualB(t.Hour(), t.Minute(), app.cfg.Certs[certIndex].FileUpdateTimeStartHour, app.cfg.Certs[certIndex].FileUpdateTimeStartMinute)
	tBeforeOrEqualEndTime := timeAIsBeforeOrEqualB(t.Hour(), t.Minute(), app.cfg.Certs[certIndex].FileUpdateTimeEndHour, app.cfg.Certs[certIndex].FileUpdateTimeEndMinute)

	// handling varies depending on if time window includes midnight
	if app.cfg.Certs[certIndex].FileUpdateTimeIncludesMidnight {
		// if prior day approved weekday, check if t is before end of window
		if prevDayWasApprovedWeekday && tBeforeOrEqualEndTime {
			return true
		}

		// if today is approved weekday, check if t is after start of window
		if approvedWeekday && tAfterOrEqualStartTime {
			return true
		}

	} else {
		// window does NOT include midnight

		// if t is after or equal start AND before or equal to end; in window
		if approvedWeekday && tAfterOrEqualStartTime && tBeforeOrEqualEndTime {
			return true
		}
	}

	// anything else, outside of window
	return false
}

// nextFileUpdateWindowStart returns the time the next update window begins
func (app *app) nextFileUpdateWindowStart(certIndex int) time.Time {
	now := time.Now().Round(time.Minute)

	// set time stamp for today with window start time
	nextWindow := time.Date(now.Year(), now.Month(), now.Day(), app.cfg.Certs[certIndex].FileUpdateTimeStartHour, app.cfg.Certs[certIndex].FileUpdateTimeStartMinute, 0, now.Nanosecond(), now.Location())

	// if today is acceptable and start hasn't happened yet, use today's start
	_, todayWeekdayOk := app.cfg.Certs[certIndex].FileUpdateDaysOfWeek[now.Weekday()]
	if todayWeekdayOk && timeAIsBeforeOrEqualB(now.Hour(), now.Minute(), app.cfg.Certs[certIndex].FileUpdateTimeStartHour, app.cfg.Certs[certIndex].FileUpdateTimeStartMinute) {
		return nextWindow
	}

	// if today is not an acceptable weekday or it is acceptable but start has passed, use next acceptable start

	// find next acceptable weekday (cap at +8 days to avoid infinite if some weird anomoly happens)
	addDays := 0
	for addDays++; addDays <= 8; addDays++ {
		_, newWeekdayOk := app.cfg.Certs[certIndex].FileUpdateDaysOfWeek[(now.Weekday()+time.Weekday(addDays))%7]
		if newWeekdayOk {
			break
		}
	}

	if addDays == 8 {
		app.logger.Error("somehow next update window added more than 7 days, this should never happen, report bug")
	}

	// add days to get to next proper weekday and return
	return nextWindow.Add(time.Duration(addDays) * 24 * time.Hour)
}

// cancelPendingJob cancels the pending file write job of the specified cert, if there is one
func (app *app) cancelPendingJob(certIndex int) {
	app.pendingJobMu.Lock()
	defer app.pendingJobMu.Unlock()

	if app.pendingJobCancels[certIndex] != nil {
		app.pendingJobCancels[certIndex]()
		app.pendingJobCancels[certIndex] = nil
	}
}

// replacePendingJob cancels the pending file write job of the specified cert (if there is one),
// registers a new job in its place and returns the new job's context and cancel func
func (app *app) replacePendingJob(certIndex int) (context.Context, context.CancelFunc) {
	app.pendingJobMu.Lock()
	defer app.pendingJobMu.Unlock()

	if app.pendingJobCancels[certIndex] != nil {
		app.pendingJobCancels[certIndex]()
	}

	ctx, cancel := context.WithCancel(context.Background())
	app.pendingJobCancels[certIndex] = cancel

	return ctx, cancel
}

// scheduleJobWriteCertsMemoryToDisk schedules a job to write the client's
// key/cert pem from memory to disk (and generate any additional files on disk that
// are configured). It cancels and replaces any pending job for the cert.
func (app *app) scheduleJobWriteCertsMemoryToDisk(certIndex int) {
	// cancel any old job and register this one BEFORE starting it, so the caller (and anything
	// that runs after it) always sees the current job
	ctx, cancel := app.replacePendingJob(certIndex)

	go func() {
		// always cancel when done to release the context (cancelPendingJob may call the registered
		// cancel func again later, which is harmless)
		defer cancel()

		// determine when this job should run and log it
		now := time.Now().Round(time.Minute)

		// if not within the approved update window, add delay until next window
		if !app.inFileUpdateWindow(certIndex, now) {
			// next window start
			runTime := app.nextFileUpdateWindowStart(certIndex)

			// add random second
			runTime = runTime.Add(time.Duration(rand.Intn(60)) * time.Second)
			runTimeString := runTime.String()

			app.logger.Infof("scheduling write cert %d job for %s", certIndex, runTimeString)

			// wait for user specified run window to occur
			select {
			case <-ctx.Done():
				// job canceled (presumably new job scheduled instead)
				app.logger.Infof("write cert %d job scheduled for %s canceled (ctx closed - probably another job scheduled in its place)", certIndex, runTimeString)
				// DONE
				return

			case <-time.After(time.Until(runTime)):
				// sleep until next run
			}

			app.logger.Infof("write cert %d job scheduled for %s executing", certIndex, runTimeString)
		} else {
			app.logger.Infof("write cert %d job executing imemdiately", certIndex)
		}

		// write certs in memory to disk, regardless of existence on disk
		diskNeedsUpdate := app.updateCertFilesAndRestartContainers(certIndex, false)

		// if something failed and update still needed, schedule next job
		if diskNeedsUpdate {
			app.scheduleJobWriteCertsMemoryToDisk(certIndex)
		}

		app.logger.Infof("write cert %d job complete", certIndex)
	}()
}
