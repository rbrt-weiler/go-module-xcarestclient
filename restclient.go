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

func (c *RESTClient) SetPort(port uint) error {
	if httpMinPort <= port && httpMaxPort >= port {
		c.HTTPPort = port
		return nil
	}
	return fmt.Errorf("port out of range (%d - %d)", httpMinPort, httpMaxPort)
}

func (c *RESTClient) SetTimeout(seconds uint) error {
	if httpMinTimeout <= seconds && httpMaxTimeout >= seconds {
		c.httpClient.Timeout = time.Second * time.Duration(seconds)
		return nil
	}
	return fmt.Errorf("timeout out of range (%d - %d)", httpMinTimeout, httpMaxTimeout)
}

func (c *RESTClient) UseSecureHTTPS() {
	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}
	c.httpClient.Transport = httpTransport
}

func (c *RESTClient) UseInsecureHTTPS() {
	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c.httpClient.Transport = httpTransport
}

func (c *RESTClient) SetUserAgent(ua string) {
	c.UserAgent = ua
}

func (c *RESTClient) SetAuth(userID string, secret string) {
	c.xcaUserID = userID
	c.xcaSecret = secret
}

func SanitizeEndpoint(endpoint *string) {
	if !strings.HasPrefix(*endpoint, "/") {
		*endpoint = fmt.Sprintf("/%s", *endpoint)
	}
	if !strings.HasPrefix(*endpoint, "/management") {
		*endpoint = fmt.Sprintf("/management%s", *endpoint)
	}
}

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

func (c *RESTClient) GetRequest(endpoint string, payload []byte) (*http.Request, error) {
	SanitizeEndpoint(&endpoint)
	endpointURL := fmt.Sprintf("https://%s:%d%s", c.HTTPHost, c.HTTPPort, endpoint)

	req, reqErr := http.NewRequest(http.MethodGet, endpointURL, bytes.NewBuffer(payload))
	if reqErr != nil {
		return req, fmt.Errorf("could not create request: %s", reqErr)
	}
	SetRequestHeaders(c, req, &payload)

	return req, nil
}

func (c *RESTClient) PerformRequest(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}

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
