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
	"github.com/google/go-safeweb/safehttp"
	"github.com/google/go-safeweb/safehttp/plugins/coop"
	"github.com/google/go-safeweb/safehttp/plugins/csp"
	"github.com/google/go-safeweb/safehttp/plugins/fetchmetadata"
	"github.com/google/go-safeweb/safehttp/plugins/hostcheck"
	"github.com/google/go-safeweb/safehttp/plugins/hsts"
	"github.com/google/go-safeweb/safehttp/plugins/staticheaders"
	"github.com/google/go-safeweb/safehttp/plugins/xsrf/xsrfhtml"

	"github.com/empijei/go-safeweb-example-app/src/secure/auth"
	"github.com/empijei/go-safeweb-example-app/src/storage"
)

// NewMuxConfig creates a safe ServeMuxConfig.
func NewMuxConfig(db *storage.DB, addr string) *safehttp.ServeMuxConfig {
	c := safehttp.NewServeMuxConfig(dispatcher{})
	c.Intercept(coop.Default(""))
	c.Intercept(csp.Default(""))
	c.Intercept(fetchmetadata.NewInterceptor())
	c.Intercept(hostcheck.New(addr))
	c.Intercept(hsts.Default())
	c.Intercept(staticheaders.Interceptor{})
	c.Intercept(&xsrfhtml.Interceptor{SecretAppKey: "secret-key-that-should-not-be-in-sources"})
	c.Intercept(auth.Interceptor{DB: db})
	return c
}
