// Copyright 2015 Konstantin Kulikov. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntlm

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
)

var (
	ErrUnauthorized    = fmt.Errorf("ntlm: unauthorized")
	ErrUnsupportedAuth = fmt.Errorf("ntlm: unsupported authentication method")
)

// NewHTTPDialer returns dial func which dials remote address, GETs specified url with ntlm authentication headers
// then returns connection, if response status was anything, but 401.
//
// Usage:
// 	client = &http.Client{
// 		Transport: &http.Transport{
// 			Dial: ntlm.NewHTTPDialer(username, password, domain, url),
// 		},
// 	}
func NewHTTPDialer(username, password, domain, url string) func(network, address string) (net.Conn, error) {
	return func(network, address string) (net.Conn, error) {
		c, err := net.Dial(network, address)
		if err != nil {
			return nil, err
		}

		cc := httputil.NewClientConn(c, nil)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			c.Close()
			return nil, err
		}
		req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(Negotiate()))

		resp, err := cc.Do(req)
		if err != nil {
			c.Close()
			return nil, err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			return c, nil
		}

		challengeMsg := resp.Header.Get("Www-Authenticate")
		if !strings.HasPrefix(challengeMsg, "NTLM ") {
			c.Close()
			return nil, ErrUnsupportedAuth
		}
		challengeBytes, err := base64.StdEncoding.DecodeString(challengeMsg[len("NTLM "):])
		if err != nil {
			c.Close()
			return nil, err
		}
		challenge, err := ParseChallenge(challengeBytes)
		if err != nil {
			c.Close()
			return nil, err
		}

		req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(Authenticate(username, password, domain, challenge)))
		resp, err = cc.Do(req)
		if err != nil {
			c.Close()
			return nil, err
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			c.Close()
			return nil, ErrUnauthorized
		}

		return c, nil
	}
}
