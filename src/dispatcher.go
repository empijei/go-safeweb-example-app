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
	"net/http"

	"github.com/google/go-safeweb/safehttp"
)

type Dispatcher struct{}

func (Dispatcher) Write(rw http.ResponseWriter, resp safehttp.Response) error {
	return safehttp.DefaultDispatcher.Write(rw, resp)
}

func (Dispatcher) Error(rw http.ResponseWriter, resp safehttp.ErrorResponse) error {
	if ce, ok := resp.(customError); ok {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.WriteHeader(int(ce.code))
		return templates.ExecuteTemplate(rw, "errors.go.html", ce.message)
	}
	return safehttp.DefaultDispatcher.Error(rw, resp)
}
