// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package secure

import (
	"net/http"

	"github.com/google/go-safeweb/safehttp"
	"github.com/google/go-safeweb/safehttp/plugins/coop"
	"github.com/google/go-safeweb/safehttp/plugins/csp"
	"github.com/google/go-safeweb/safehttp/plugins/fetchmetadata"
	"github.com/google/go-safeweb/safehttp/plugins/hostcheck"
	"github.com/google/go-safeweb/safehttp/plugins/hsts"
	"github.com/google/go-safeweb/safehttp/plugins/staticheaders"
	"github.com/google/go-safeweb/safehttp/plugins/xsrf/xsrfhtml"

	"github.com/empijei/go-safeweb-example-app/src/storage"
)

type dispatcher struct{}

func (dispatcher) Write(rw http.ResponseWriter, resp safehttp.Response) error {
	return safehttp.DefaultDispatcher{}.Write(rw, resp)
}

func (dispatcher) Error(rw http.ResponseWriter, resp safehttp.ErrorResponse) error {
	if ce, ok := resp.(ErrorResponse); ok {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.WriteHeader(int(ce.code))
		return templates.ExecuteTemplate(rw, "error.tpl.html", ce.message)
	}
	return safehttp.DefaultDispatcher{}.Error(rw, resp)
}

func NewMux(db *storage.DB, addr string) *safehttp.ServeMuxConfig {
	c := safehttp.NewServeMuxConfig(dispatcher{})
	// TODO(clap): add a report group once we support reporting.
	c.Intercept(coop.Default(""))
	// TODO(clap): add a report-uri once we support reporting.
	// TODO(clap): find a way to make the FramingPolicy here work together with the Framing plugin once we have it.
	c.Intercept(csp.Default(""))
	c.Intercept(fetchmetadata.NewInterceptor())
	c.Intercept(hostcheck.New(addr))
	c.Intercept(hsts.Default())
	c.Intercept(staticheaders.Interceptor{})
	c.Intercept(&xsrfhtml.Interceptor{SecretAppKey: "secret-key-that-should-not-be-in-sources"})
	c.Intercept(auth{db})
	return c
}
