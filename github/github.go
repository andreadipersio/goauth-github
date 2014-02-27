// Package github implement OAuth2 authentication for Github
// providing an handler (OAuth2Handler) which perform OAuth token authorization
// and exchange.
package github

import (
    "fmt"
    "io"
    "io/ioutil"

    "net/url"
    "net/http"
)

const (
    authorizationURL = "https://github.com/login/oauth/authorize?"  +
                       "client_id=%v&redirect_uri=%v&scope=%v"

    tokenExchangeURL = "https://github.com/login/oauth/access_token"
)

type Token struct {
    // Github bearer access token. Can be used to make
    // API call to Github CORE API.
    Token string
}

type OAuth2Handler struct {
    // App Key
    Key,

    // App Secret
    Secret,

    // OAuth redirect URL
    RedirectURI string

    // access token
    Token *Token

    // Scope limit access for oauth tokens
    // If empty Grants read-only access to public information
    // (includes public user profile info, public repository info, and gists)
    // https://developer.github.com/v3/oauth/#scopes
    Scope string

    // SuccessCallback is executed when TokenExchange succeed
    SuccessCallback func(http.ResponseWriter, *http.Request, *Token)

    // ErrorCallback is executed when any of the OAuth step fails
    ErrorCallback   func(http.ResponseWriter, *http.Request, error)
}

func (h *OAuth2Handler) AuthorizeURL() string {
    return fmt.Sprintf(authorizationURL, h.Key,
                       h.RedirectURI, url.QueryEscape(h.Scope))
}

// TokenExchange method convert an auth code to a bearer token
// https://developer.github.com/v3/oauth/
func (h *OAuth2Handler) TokenExchange(authcode string) (*Token, error) {
    data := url.Values{}

    data.Add("code", authcode)
    data.Add("client_id", h.Key)
    data.Add("client_secret", h.Secret)
    data.Add("redirect_uri", h.RedirectURI)

    client := &http.Client{}

    req, err := http.NewRequest("POST", tokenExchangeURL, nil)
    req.Header.Add("Accept", "application/json")

    resp, err := client.PostForm(tokenExchangeURL, data)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    // Response Body contains query string representing
    //the result of token exchange
    parseResponse := func(r io.Reader) (url.Values, error) {
        b, err := ioutil.ReadAll(r)

        if err != nil {
            return nil, fmt.Errorf("Cannot read response %s", string(b))
        }

        if values, parseErr := url.ParseQuery(string(b)); parseErr != nil {
            return nil, fmt.Errorf("Cannot parse response %s", err)
        } else {
            return values, nil
        }
    }

    values, err := parseResponse(resp.Body)

    if err != nil {
        return nil, err
    }

    // Return error full with description and reference uri
    if values.Get("error") != "" {
        return nil, fmt.Errorf("%s - %s\nMore info %s",
                                values.Get("error"),
                                values.Get("error_description"),
                                values.Get("error_uri"))
    }

    return &Token{values.Get("access_token"),}, nil
}

// If no auth code is found, then redirect to github authorization endpoint,
// otherwise try to exchange the auth code with a bearer token, by invoking
// OAuth2Handler.TokenExchange.
// On success token is passed to OAuth2Handler.SuccessCallback,
// otherwise error is passed to OAuth2Handler.ErrorCallback
// (error is a string - error_code: error_description).
func (h *OAuth2Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    authcode := r.FormValue("code")
    oauthErrCode, oauthErrMsg := r.FormValue("error"), r.FormValue("error_description")

    // oauthErrCode --- http://tools.ietf.org/html/rfc6749#section-4.1.2.1
    if oauthErrCode != "" {
        h.ErrorCallback(w, r, fmt.Errorf("%v: %v", oauthErrCode, oauthErrMsg))
        return
    }

    if authcode == "" {
        http.Redirect(w, r, h.AuthorizeURL(), 302)
        return
    }

    if token, err := h.TokenExchange(authcode); err != nil {
        h.ErrorCallback(w, r, err)
    } else {
        h.SuccessCallback(w, r, token)
    }
}
