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
	"github.com/empijei/go-safeweb-example-app/src/storage"
	"github.com/google/go-safeweb/safehttp"
	"github.com/google/safehtml/template"
)

func loadServer(cfg *safehttp.ServeMuxConfig) {
	db := storage.NewStorage()

	cfg.Intercept(auth{db: db})

	cfg.Handle("/notes/", "GET", getNotesHandler(db))
	cfg.Handle("/notes", "POST", postNotesHandler(db))

	cfg.Handle("/logout", "POST", logoutHandler(db))

	cfg.Handle("/login", "POST", postLoginHandler(db), skipAuth{})
	cfg.Handle("/static/", "GET", safehttp.FileServer("static/"), skipAuth{})
	cfg.Handle("/", "GET", indexHandler(db), skipAuth{})
}

func getNotesHandler(db *storage.DB) safehttp.Handler {
	return safehttp.HandlerFunc(func(rw safehttp.ResponseWriter, r *safehttp.IncomingRequest) safehttp.Result {
		user := getUser(r)
		notes := db.GetNotes(user)
		return safehttp.ExecuteNamedTemplate(rw, templates, "notes.tpl.html", notes)
	})
}

func postNotesHandler(db *storage.DB) safehttp.Handler {
	noFormErr := customError{
		safehttp.StatusBadRequest,
		template.MustParseAndExecuteToHTML("Please specify the form with the note to add."),
	}
	noFieldsErr := customError{
		safehttp.StatusBadRequest,
		template.MustParseAndExecuteToHTML("Both title and body must be specified."),
	}

	return safehttp.HandlerFunc(func(rw safehttp.ResponseWriter, r *safehttp.IncomingRequest) safehttp.Result {
		form, err := r.PostForm()
		if err != nil {
			return rw.WriteError(noFormErr)
		}
		title := form.String("title", "")
		body := form.String("body", "")
		if title == "" || body == "" {
			return rw.WriteError(noFieldsErr)
		}

		user := getUser(r)
		db.AddOrEditNote(user, storage.Note{Title: title, Text: body})
		notes := db.GetNotes(user)
		return safehttp.ExecuteNamedTemplate(rw, templates, "notes.tpl.html", notes)
	})
}

func logoutHandler(db *storage.DB) safehttp.Handler {
	return safehttp.HandlerFunc(func(rw safehttp.ResponseWriter, r *safehttp.IncomingRequest) safehttp.Result {
		user := getUser(r)
		db.DelSession(user)
		rw.AddCookie(safehttp.NewCookie(sessionCookie, ""))
		return rw.Redirect(r, "/", safehttp.StatusTemporaryRedirect)
	})
}
func postLoginHandler(db *storage.DB) safehttp.Handler {
	return safehttp.HandlerFunc(func(rw safehttp.ResponseWriter, r *safehttp.IncomingRequest) safehttp.Result {
		// TODO
	})
}
func indexHandler(db *storage.DB) safehttp.Handler {
	return safehttp.HandlerFunc(func(rw safehttp.ResponseWriter, r *safehttp.IncomingRequest) safehttp.Result {
		// TODO
	})
}
