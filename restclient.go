package xcarestclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// RESTClient encapsulates the actual HTTP client that communicates with XCA.
// Use New() to obtain an usable instance. All fields should be treated as read-only; functions are provided where changes shall be possible.
type RESTClient struct {
	httpClient  http.Client
	HTTPHost    string
	HTTPPort    uint
	HTTPTimeout uint
	UserAgent   string
	xcaUserID   string
	xcaSecret   string
	OAuth       OAuthToken
}

// New is used to create an usable instance of RESTClient.
// By default a new instance will use HTTPS to port 5825 with strict certificate checking. The HTTP timeout is set to 5 seconds. Authentication must be set manually before trying to send a query to XCA.
func New(host string) RESTClient {
	var c RESTClient

	c.httpClient = http.Client{}
	c.HTTPHost = host
	c.SetPort(5825)
	c.SetTimeout(5)
	c.UseSecureHTTPS()
	c.SetUserAgent(fmt.Sprintf("%s/%s", moduleName, moduleVersion))

	return c
}

// SetPort sets the TCP port where XCA is listening for the RESTClient instance.
func (c *RESTClient) SetPort(port uint) error {
	if httpMinPort <= port && httpMaxPort >= port {
		c.HTTPPort = port
		return nil
	}
	return fmt.Errorf("port out of range (%d - %d)", httpMinPort, httpMaxPort)
}

// SetTimeout sets the HTTP timeout in seconds for the RESTClient instance.
func (c *RESTClient) SetTimeout(seconds uint) error {
	if httpMinTimeout <= seconds && httpMaxTimeout >= seconds {
		c.httpClient.Timeout = time.Second * time.Duration(seconds)
		return nil
	}
	return fmt.Errorf("timeout out of range (%d - %d)", httpMinTimeout, httpMaxTimeout)
}

// UseSecureHTTPS enforces strict HTTPS certificate checking.
func (c *RESTClient) UseSecureHTTPS() {
	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}
	c.httpClient.Transport = httpTransport
}

// UseInsecureHTTPS disables strict HTTPS certificate checking.
func (c *RESTClient) UseInsecureHTTPS() {
	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c.httpClient.Transport = httpTransport
}

// SetUserAgent sets the User-Agent HTTP header.
func (c *RESTClient) SetUserAgent(ua string) {
	c.UserAgent = ua
}

// SetAuth sets the authentication credentials.
func (c *RESTClient) SetAuth(userID string, secret string) {
	c.xcaUserID = userID
	c.xcaSecret = secret
}

// SanitizeEndpoint prepares the provided API endpoint for concatenation.
func SanitizeEndpoint(endpoint *string) {
	if !strings.HasPrefix(*endpoint, "/") {
		*endpoint = fmt.Sprintf("/%s", *endpoint)
	}
	if !strings.HasPrefix(*endpoint, "/management") {
		*endpoint = fmt.Sprintf("/management%s", *endpoint)
	}
}

// SetRequestHeaders sets the usual headers required for requests to XCA.
func SetRequestHeaders(client *RESTClient, req *http.Request, payload *[]byte) {
	req.Header.Set("User-Agent", client.UserAgent)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Accept", jsonMimeType)
	if payload != nil {
		req.Header.Set("Content-Type", jsonMimeType)
	}
	if client.OAuth.AccessToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.OAuth.AccessToken))
	}
}

// PostRequest returns a prepared HTTP POST request instance.
func (c *RESTClient) PostRequest(endpoint string, payload []byte) (*http.Request, error) {
	SanitizeEndpoint(&endpoint)
	endpointURL := fmt.Sprintf("https://%s:%d%s", c.HTTPHost, c.HTTPPort, endpoint)

	req, reqErr := http.NewRequest(http.MethodPost, endpointURL, bytes.NewBuffer(payload))
	if reqErr != nil {
		return req, fmt.Errorf("could not create request: %s", reqErr)
	}
	SetRequestHeaders(c, req, &payload)

	return req, nil
}

// GetRequest returns a prepared HTTP GET request instance.
func (c *RESTClient) GetRequest(endpoint string) (*http.Request, error) {
	SanitizeEndpoint(&endpoint)
	endpointURL := fmt.Sprintf("https://%s:%d%s", c.HTTPHost, c.HTTPPort, endpoint)

	req, reqErr := http.NewRequest(http.MethodGet, endpointURL, nil)
	if reqErr != nil {
		return req, fmt.Errorf("could not create request: %s", reqErr)
	}
	SetRequestHeaders(c, req, nil)

	return req, nil
}

// DeleteRequest returns a prepared HTTP DELETE request instance.
func (c *RESTClient) DeleteRequest(endpoint string) (*http.Request, error) {
	SanitizeEndpoint(&endpoint)
	endpointURL := fmt.Sprintf("https://%s:%d%s", c.HTTPHost, c.HTTPPort, endpoint)

	req, reqErr := http.NewRequest(http.MethodDelete, endpointURL, nil)
	if reqErr != nil {
		return req, fmt.Errorf("could not create request: %s", reqErr)
	}
	SetRequestHeaders(c, req, nil)

	return req, nil
}

// PerformRequest sends a request to XCA and returns the result.
func (c *RESTClient) PerformRequest(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}

// Authenticate performs authentication against XCA and stores the OAuth token.
func (c *RESTClient) Authenticate() error {
	// Empty token structure to start with.
	var tokenData OAuthToken

	var tokenRequest TokenRequest
	tokenRequest.GrantType = "password"
	tokenRequest.UserID = c.xcaUserID
	tokenRequest.Password = c.xcaSecret
	tokenRequest.Scope = ""

	// Generate an actual HTTP request.
	payload, _ := json.Marshal(tokenRequest)
	req, reqErr := c.PostRequest("/management/v1/oauth2/token", payload)
	if reqErr != nil {
		return fmt.Errorf("could not create HTTP(S) request: %s", reqErr)
	}

	// Try to get a result from the API.
	res, resErr := c.httpClient.Do(req)
	if resErr != nil {
		return fmt.Errorf("could not connect to XMC: %s", resErr)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("got status code %d instead of %d", res.StatusCode, http.StatusOK)
	}
	defer res.Body.Close()

	// Check if the HTTP response has yielded the expected content type.
	resContentType := res.Header.Get("Content-Type")
	if strings.Index(resContentType, jsonMimeType) != 0 {
		return fmt.Errorf("Content-Type %s returned instead of %s", resContentType, jsonMimeType)
	}

	// Read and parse the body of the HTTP response.
	body, bodyErr := ioutil.ReadAll(res.Body)
	if bodyErr != nil {
		return fmt.Errorf("could not read server response: %s", bodyErr)
	}
	jsonErr := json.Unmarshal(body, &tokenData)
	if jsonErr != nil {
		return fmt.Errorf("could not read server response: %s", jsonErr)
	}

	c.OAuth = tokenData
	if decodeErr := c.OAuth.Decode(); decodeErr != nil {
		return fmt.Errorf("error decoding token: %s", decodeErr)
	}

	return nil
}
