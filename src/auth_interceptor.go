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

package server

import (
	"context"

	"github.com/empijei/go-safeweb-example-app/src/storage"
	"github.com/google/go-safeweb/safehttp"
	"github.com/google/safehtml/template"
)

const sessionCookie = "SESSION"

type userCtxKey string

const userCtx userCtxKey = "user"

var unauthMsg = template.MustParseAndExecuteToHTML(`Please <a href="/">login</a> before visiting this page.`)

type auth struct {
	db         *storage.DB
	exceptions map[string]struct{}
}

func (a auth) Before(w safehttp.ResponseWriter, r *safehttp.IncomingRequest, cfg safehttp.InterceptorConfig) safehttp.Result {
	// Identify the user.
	user := a.userFromCookie(r)
	if user != "" {
		r.SetContext(context.WithValue(r.Context(), userCtx, user))
	}

	// If the config says we should not perform auth, let's stop executing here.
	if cfg != nil {
		if _, ok := cfg.(skipAuth); ok {
			return safehttp.NotWritten()
		}
	}

	if user == "" {
		// We have to perform auth, and the user was not identified, bail out.
		return w.WriteError(customError{
			code:    safehttp.StatusUnauthorized,
			message: unauthMsg,
		})
	}
	return safehttp.NotWritten()
}

func (a auth) userFromCookie(r *safehttp.IncomingRequest) string {
	sess, err := r.Cookie(sessionCookie)
	if err != nil || sess.Value() == "" {
		return ""
	}
	user, ok := a.db.GetUser(sess.Value())
	if !ok {
		return ""
	}
	return user
}

func getUser(r *safehttp.IncomingRequest) string {
	v := r.Context().Value(userCtx)
	user, ok := v.(string)
	if !ok {
		return ""
	}
	return user
}

func (a auth) Commit(w safehttp.ResponseHeadersWriter, r *safehttp.IncomingRequest, resp safehttp.Response, cfg safehttp.InterceptorConfig) {
}

type skipAuth struct{}

func (skipAuth) Match(i safehttp.Interceptor) bool {
	_, ok := i.(auth)
	return ok
}
