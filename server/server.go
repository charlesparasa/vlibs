package server

import (
	"fmt"
	"log"
	"net/http"
	context2 "github.com/gorilla/context"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"time"
	"github.com/felixge/httpsnoop"
)

type route struct {
	Name                   string
	Method                 string
	Pattern                string
	ResourcesPermissionMap map[string]uint8
	HandlerFunc            http.HandlerFunc
}

type Routes []route

var routes = make(Routes, 0)

func newRouter(subroute string) *mux.Router {

	muxRouter := mux.NewRouter().StrictSlash(true)
	subRouter := muxRouter.PathPrefix(subroute).Subrouter()

	for _, route := range routes {
		subRouter.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(route.HandlerFunc)
	}

	return muxRouter
}

func AddNoAuthRoutes(methodName string, methodType string, mRoute string, handlerFunc http.HandlerFunc) {
	r := route{
		Name:        methodName,
		Method:      methodType,
		Pattern:     mRoute,
		HandlerFunc: useMiddleware(handlerFunc, logRequest)}
	routes = append(routes, r)

}

func useMiddleware(h http.HandlerFunc, middleware ...func(http.HandlerFunc) http.HandlerFunc) http.HandlerFunc {
	for _, m := range middleware {
		h = m(h)
	}
	return h
}

func logRequest(handler http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m := httpsnoop.CaptureMetrics(handler, w, r)
		HTTPLog(constructHTTPLog(r, m, time.Since(start)))
	})
}

func constructHTTPLog(r *http.Request, m httpsnoop.Metrics, duration time.Duration) string {
	ctx := r.Context().Value(APICtx)
	if ctx != nil {
		tCtx := ctx.(APIContext)
		return fmt.Sprintf("|%s|%s|%s|%s|%s|%d|%d|%s|%s|",
			// Cannot modify original request/obtain apiContext through gorilla context, hence we won't get the apiContext data from the request object.
			tCtx.UserName+":"+tCtx.RequestID,
			"correlationId="+tCtx.CorrelationID+":requestId="+tCtx.RequestID,
			r.RemoteAddr,
			r.Method,
			r.URL,
			m.Code,
			m.Written,
			r.UserAgent(),
			duration,
		)
	}
	return fmt.Sprintf("|%s|%s|%s|%d|%d|%s|%s|",
		// Cannot modify original request/obtain apiContext through gorilla context, hence we won't get the apiContext data from the request object.
		r.RemoteAddr,
		r.Method,
		r.URL,
		m.Code,
		m.Written,
		r.UserAgent(),
		duration,
	)

}

func Start(port, subroute string) {
	allowedOrigins := handlers.AllowedOrigins([]string{"*"}) // Allowing all origin as of now

	allowedHeaders := handlers.AllowedHeaders([]string{
		"X-Requested-With",
		"X-CSRF-Token",
		"X-Auth-Token",
		"Content-Type",
		"processData",
		"contentType",
		"Origin",
		"Authorization",
		"Accept",
		"Client-Security-Token",
		"Accept-Encoding",
		"timezone",
		"locale",
		"APIToken",
		"RequestID",
		"CorrelationID"})

	allowedMethods := handlers.AllowedMethods([]string{
		"POST",
		"GET",
		"DELETE",
		"PUT",
		"PATCH",
		"OPTIONS"})

	allowCredential := handlers.AllowCredentials()

	s := &http.Server{
		Addr: ":" + port,
		Handler: handlers.CORS(
			allowedHeaders,
			allowedMethods,
			allowedOrigins,
			allowCredential)(
			context2.ClearHandler(
				newRouter(subroute),
			)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		// MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())
}
