//+build !linux

package sysvars

import (
	"github.com/yext/cloudprober/logger"
	"github.com/yext/cloudprober/metrics"
)

// osRuntimeVars doesn't anything for the non-Linux systems yet. We have it
// here to make sysvars package compilation work on non-Linux systems.
func osRuntimeVars(dataChan chan *metrics.EventMetrics, l *logger.Logger) {
}
