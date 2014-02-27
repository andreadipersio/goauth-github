goauth-github
==============

A Github OAuth2 authentication library.

[![GoDoc](https://godoc.org/github.com/andreadipersio/goauth-github?status.png)](http://godoc.org/github.com/andreadipersio/goauth-github)

### Usage

```Go

package main

import (
    "fmt"
    "net/http"

    "github.com/andreadipersio/goauth-github/github"
)

func main() {
    githubHandler := &github.OAuth2Handler{
        Key: "my app key",
        Secret: "my app secret",

        Scope: "user:email, repo",

        RedirectURI: "http://localhost:8001/oauth/github",

        ErrorCallback: func(w http.ResponseWriter, r *http.Request, err error) {
            http.Error(w, fmt.Sprintf("OAuth error - %v", err), 500)
        },

        SuccessCallback: func(w http.ResponseWriter, r *http.Request, token *github.Token) {
            http.SetCookie(w, &http.Cookie{
                Name: "github_token",
                Value: token.Token,
            })
        },
    }

    http.Handle("/oauth/github", githubHandler)
    http.ListenAndServe(":8001", nil)
}

```
