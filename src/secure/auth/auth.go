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

package auth

import (
	"context"
	"log"

	"github.com/google/go-safeweb/safehttp"
	"github.com/google/safehtml/template"

	"github.com/empijei/go-safeweb-example-app/src/secure/responses"
	"github.com/empijei/go-safeweb-example-app/src/storage"
)

// TODO(kele|clap): comment on the role of a custom Interceptor.
// Potentially consider moving this to its own package.

const sessionCookie = "SESSION"

type ctxKey string

const (
	userCtx       ctxKey = "user"
	changeSessCtx ctxKey = "change"
	clearSess            = "clear"
	setSess              = "set"
)

var unauthMsg = template.MustParseAndExecuteToHTML(`Please <a href="/">login</a> before visiting this page.`)

type Interceptor struct {
	DB *storage.DB
}

func (ip Interceptor) Before(w safehttp.ResponseWriter, r *safehttp.IncomingRequest, cfg safehttp.InterceptorConfig) safehttp.Result {
	// Identify the user.
	user := ip.userFromCookie(r)
	if user != "" {
		r.SetContext(context.WithValue(r.Context(), userCtx, user))
	}

	if _, ok := cfg.(SkipAuth); ok {
		// If the config says we should not perform auth, let's stop executing here.
		return safehttp.NotWritten()
	}

	if user == "" {
		// We have to perform auth, and the user was not identified, bail out.
		return w.WriteError(responses.Error{
			StatusCode: safehttp.StatusUnauthorized,
			Message:    unauthMsg,
		})
	}
	return safehttp.NotWritten()
}

func (ip Interceptor) userFromCookie(r *safehttp.IncomingRequest) string {
	sess, err := r.Cookie(sessionCookie)
	if err != nil || sess.Value() == "" {
		return ""
	}
	user, ok := ip.DB.GetUser(sess.Value())
	if !ok {
		return ""
	}
	return user
}

// GetUser retrieves the user from the request context.
func GetUser(r *safehttp.IncomingRequest) string {
	v := r.Context().Value(userCtx)
	user, ok := v.(string)
	if !ok {
		return ""
	}
	return user
}

func (ip Interceptor) Commit(w safehttp.ResponseHeadersWriter, r *safehttp.IncomingRequest, resp safehttp.Response, cfg safehttp.InterceptorConfig) {
	action := r.Context().Value(changeSessCtx)
	if action == nil {
		return
	}
	act := action.(string)
	user := GetUser(r)
	switch act {
	case clearSess:
		ip.DB.DelSession(user)
		w.AddCookie(safehttp.NewCookie(sessionCookie, ""))
	case setSess:
		token := ip.DB.GetToken(user)
		w.AddCookie(safehttp.NewCookie(sessionCookie, token))
	default:
		log.Printf("invalid action")
	}
}

func ClearSession(r *safehttp.IncomingRequest) {
	r.SetContext(context.WithValue(r.Context(), changeSessCtx, clearSess))
}

func CreateSession(user string, r *safehttp.IncomingRequest) {
	r.SetContext(context.WithValue(r.Context(), changeSessCtx, setSess))
	r.SetContext(context.WithValue(r.Context(), userCtx, user))

}

// SkipAuth allows to mark an endpoint to skip auth checks.
// Its uses would normally be gated by a security review.
// TODO(clap|kele): potentially go in depth with this describing the mechanism,
// the linter configurations etc.
type SkipAuth struct{}

func (SkipAuth) Match(i safehttp.Interceptor) bool {
	// This configuration only applies to the auth plugin.
	_, ok := i.(Interceptor)
	return ok
}
