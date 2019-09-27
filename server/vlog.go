package server

import (
	"encoding/json"
	"fmt"
	"io"
	l "log"
	"os"

	"strings"
)

const (
	//INFO level 1
	INFO = iota
	//HTTP level 2
	HTTP
	//ERROR level 3
	ERROR
	//TRACE level 4
	TRACE
	//WARNING level 5
	WARNING
)

var (
	setLevel = WARNING
	trace    *l.Logger
	info     *l.Logger
	warning  *l.Logger
	httplog  *l.Logger
	errorlog *l.Logger
)

// FieldsMap map of key value pair to log
type FieldsMap map[string]interface{}

func init() {
	logInit(os.Stdout,
		os.Stdout,
		os.Stdout,
		os.Stdout,
		os.Stderr)
}

const (
	clusterType      = "CLUSTER_TYPE"
	clusterTypeLocal = "local"
	clusterTypeDev   = "dev1"
)

func logInit(
	traceHandle io.Writer,
	infoHandle io.Writer,
	warningHandle io.Writer,
	httpHandle io.Writer,
	errorHandle io.Writer) {

	if os.Getenv(clusterType) == clusterTypeLocal || os.Getenv(clusterType) == clusterTypeDev {
		trace = l.New(traceHandle,
			"TRACE|",
			l.LUTC|l.LstdFlags|l.Lshortfile)

		info = l.New(infoHandle,
			"INFO|",
			l.LUTC|l.LstdFlags|l.Lshortfile)

		warning = l.New(warningHandle,
			"WARNING|",
			l.LUTC|l.LstdFlags|l.Lshortfile)

		httplog = l.New(httpHandle,
			"HTTP|",
			l.LUTC|l.LstdFlags|l.Lshortfile)

		errorlog = l.New(errorHandle,
			"ERROR|",
			l.LUTC|l.LstdFlags|l.Lshortfile)
	} else {
		trace = l.New(traceHandle,
			"TRACE|",
			l.LUTC|l.LstdFlags)

		info = l.New(infoHandle,
			"INFO|",
			l.LUTC|l.LstdFlags)

		warning = l.New(warningHandle,
			"WARNING|",
			l.LUTC|l.LstdFlags)

		httplog = l.New(httpHandle,
			"HTTP|",
			l.LUTC|l.LstdFlags)

		errorlog = l.New(errorHandle,
			"ERROR|",
			l.LUTC|l.LstdFlags|l.Lshortfile)
	}
}

func doLog(cLog *l.Logger, level, callDepth int, v ...interface{}) {
	if level <= setLevel {
		if level == ERROR {
			cLog.SetOutput(os.Stderr)
		}
		//cLog.SetOutput(os.Stdout)
		cLog.Output(callDepth, fmt.Sprintln(v...))
	}
}

// HTTPLog prints the log in the following format:
//
// If any of the value is irrelevant then two consecutive PIPEs are printed:
// HTTP|TIMESTAMP|userName:roleID|ServerIP:PORT|RequestMethod|RequestURL|ResponseStatusCode|ResponseWeight|UserAgent|Duration
func HTTPLog(logMessage string) {
	doLog(httplog, HTTP, 6, logMessage)
}

//Trace system gives facility to helps you isolate your system problems by monitoring selected events Ex. entry and exit
func traceLog(v ...interface{}) {
	doLog(trace, TRACE, 6, v...)
}

//Info dedicated for logging valuable information
func infoLog(v ...interface{}) {
	doLog(info, INFO, 6, v...)
}

//Warning for critical error
func warningLog(v ...interface{}) {
	doLog(warning, WARNING, 3, v...)
}

//Error logging error
func errorLog(v ...interface{}) {
	doLog(errorlog, ERROR, 6, v...)
}

func generatePrefix(ctx APIContext) string {
	return strings.Join([]string{ctx.UserName, ctx.RequestID}, ":")
}

func generateTrackingIDs(ctx APIContext) string {
	requestID := ctx.RequestID
	correlationID := ctx.CorrelationID
	var retString string
	if correlationID != "" {
		retString += "correlationId=" + correlationID
	}
	retString += ":"
	if requestID != "" {
		retString += "requestId=" + requestID
	}
	return retString
}

//GenericError generates error log (following standard vennauto log spec)
func GenericError(ctx APIContext, e error, fields FieldsMap) {
	prefix := generatePrefix(ctx)
	trackingIDs := generateTrackingIDs(ctx)
	msg := fmt.Sprintf("|%s|%s|%s", prefix, trackingIDs, e.Error())
	if fields != nil && len(fields) > 0 {
		fieldsBytes, _ := json.Marshal(fields)
		fieldsString := string(fieldsBytes)
		errorLog(msg, "|", fieldsString)
	} else {
		errorLog(msg)
	}
}

//GenericInfo generates info log (following standard Vennauto log spec)
func GenericInfo(ctx APIContext, infoMessage string, fields FieldsMap) {
	prefix := generatePrefix(ctx)
	trackingIDs := generateTrackingIDs(ctx)
	fieldsBytes, _ := json.Marshal(fields)
	fieldsString := string(fieldsBytes)
	msg := fmt.Sprintf("|%s|%s|",
		prefix,
		trackingIDs)
	if fields != nil && len(fields) > 0 {
		infoLog(msg, infoMessage, "|", fieldsString)
	} else {
		infoLog(msg, infoMessage)
	}

}

//GenericWarning generates warning log (following standard Vennauto log spec)
func GenericWarning(ctx APIContext, warnMessage string, fields FieldsMap) {
	if os.Getenv("TEK_SERVICE_WARN") == "true" {
		prefix := generatePrefix(ctx)
		trackingIDs := generateTrackingIDs(ctx)
		msg := fmt.Sprintf("|%s|%s|",
			prefix,
			trackingIDs)
		if fields != nil && len(fields) > 0 {
			fieldsBytes, _ := json.Marshal(fields)
			fieldsString := string(fieldsBytes)
			warningLog(msg, warnMessage, "|", fieldsString)
		} else {
			warningLog(msg, warnMessage)
		}
	}
}

//GenericTrace generates trace log (following standard Vennauto log spec)
func GenericTrace(ctx APIContext, traceMessage string, fields FieldsMap) {

	if os.Getenv("TEK_SERVICE_TRACE") == "true" {
		prefix := generatePrefix(ctx)
		trackingIDs := generateTrackingIDs(ctx)
		msg := fmt.Sprintf("|%s|%s|",
			prefix,
			trackingIDs)
		if fields != nil && len(fields) > 0 {
			fieldsBytes, _ := json.Marshal(fields)
			fieldsString := string(fieldsBytes)
			traceLog(msg, traceMessage, "|", fieldsString)
		} else {
			traceLog(msg, traceMessage)
		}
	}

}
