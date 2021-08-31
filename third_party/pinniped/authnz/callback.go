package authnz

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/upstreamoidc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/getupio-undistro/undistro/pkg/scheme"
	"github.com/getupio-undistro/undistro/pkg/undistro"
	"github.com/getupio-undistro/undistro/pkg/util"
	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/httputil/httperr"
	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/oidc/provider"
	"github.com/go-logr/logr"
	"github.com/ory/fosite"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	"go.pinniped.dev/pkg/oidcclient/pkce"
	"go.pinniped.dev/pkg/oidcclient/state"
	"golang.org/x/oauth2"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	debugLogLevel = 4
)

type HandlerState struct {
	// Basic parameters.
	Ctx        context.Context
	Logger     logr.Logger
	Issuer     string
	ClientID   string
	Scopes     []string
	HTTPClient *http.Client
	State      state.State
	PKCE       pkce.Code
	Nonce      nonce.Nonce

	getProvider func(*oauth2.Config, *oidc.Provider, *http.Client) provider.UpstreamOIDCIdentityProviderI
	validateIDToken func(ctx context.Context, provider *oidc.Provider, audience string, token string) (*oidc.IDToken, error)

	// External calls for things.
	generateState func() (state.State, error)
	generatePKCE  func() (pkce.Code, error)
	generateNonce func() (nonce.Nonce, error)


	// Generated parameters of a login flow.
	provider     *oidc.Provider
	OAuth2Config *oauth2.Config
	UseFormPost  bool
	RestConf     *rest.Config
}

func SetRestConfHandlerState(r *rest.Config) *HandlerState {
	return &HandlerState{
		RestConf: r,
	}
}

func (h *HandlerState) HandleAuthCodeCallback(w http.ResponseWriter, r *http.Request) error {
	h.Ctx = r.Context()
	// Perform OIDC discovery.
	if err := h.initOIDCDiscovery(); err != nil {
		return err
	}
	return h.handleAuthCodeCallback(w, r)
}

func (h *HandlerState) handleAuthCodeCallback(w http.ResponseWriter, r *http.Request) (err error) {
	var params url.Values
	if h.UseFormPost {
		// Return HTTP 405 for anything that's not a POST.
		if r.Method != http.MethodPost {
			return httperr.Newf(http.StatusMethodNotAllowed, "wanted POST")
		}

		// Parse and pull the response parameters from a application/x-www-form-urlencoded request body.
		if err := r.ParseForm(); err != nil {
			return httperr.Wrap(http.StatusBadRequest, "invalid form", err)
		}
		params = r.Form
	} else {
		// Return HTTP 405 for anything that's not a GET.
		if r.Method != http.MethodGet {
			return httperr.Newf(http.StatusMethodNotAllowed, "wanted GET")
		}

		// Pull response parameters from the URL query string.
		params = r.URL.Query()
	}

	// Validate OAuth2 state and fail if it's incorrect (to block CSRF).
	if err := h.State.Validate(params.Get("state")); err != nil {
		msg := fmt.Sprintf("missing or invalid state parameter: %s", err)
		return httperr.New(http.StatusForbidden, msg)
	}

	// Check for error response parameters. See https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	if errorParam := params.Get("error"); errorParam != "" {
		if errorDescParam := params.Get("error_description"); errorDescParam != "" {
			return httperr.Newf(http.StatusBadRequest, "login failed with code %q: %s", errorParam, errorDescParam)
		}
		return httperr.Newf(http.StatusBadRequest, "login failed with code %q", errorParam)
	}

	// Exchange the authorization code for access, ID, and refresh tokens and perform required
	// validations on the returned ID token.
	if h.OAuth2Config == nil {
		return httperr.Newf(http.StatusInternalServerError, "OAuth2 Config is not set")
	}
	token, err := h.redeemAuthCode(r.Context(), params.Get("code"))
	if err != nil {
		return httperr.Wrap(http.StatusBadRequest, "could not complete code exchange", err)
	}
	resp := make(map[string]interface{})
	resp["token"] = token
	encoder := json.NewEncoder(w)
	err = encoder.Encode(resp)
	if err != nil {
		return httperr.Wrap(http.StatusInternalServerError, "could not marshal token", err)
	}
	// Perform the RFC8693 token exchange.
	exchangedToken, err := h.tokenExchangeRFC8693(baseToken)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}
	return nil
}

func (h *HandlerState) updateHandlerState(ctx context.Context) error {
	fedo := make(map[string]interface{})
	c, err := client.New(h.RestConf, client.Options{
		Scheme: scheme.Scheme,
	})
	if err != nil {
		return err
	}
	o, err := util.GetFromConfigMap(
		ctx, c, "identity-config", undistro.Namespace, "federationdomain.yaml", fedo)
	fedo = o.(map[string]interface{})
	if err != nil {
		return err
	}
	issuer := fedo["issuer"].(string)
	cli := http.DefaultClient
	isLocal, err := util.IsLocalCluster(ctx, c)
	if err != nil {
		return err
	}
	if isLocal {
		const caSecretName = "ca-secret"
		const caName = "ca.crt"
		byt, err := util.GetCaFromSecret(ctx, c, caSecretName, caName, undistro.Namespace)
		if err != nil {
			return err
		}
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(byt)

		tlsConfig := &tls.Config{
			RootCAs: certPool,
		}
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		cli = &http.Client{Transport: transport}
		h.Ctx = context.WithValue(ctx, oauth2.HTTPClient, h.HTTPClient)
	}
	h.Logger = ctrl.Log
	h.Issuer = issuer
	h.ClientID = "undistro-ui"
	h.Scopes = fosite.Arguments{
		oidc.ScopeOpenID,
		oidc.ScopeOfflineAccess,
		"profile",
		"email",
		"pinniped:request-audience",
	}
	h.HTTPClient = cli
	h.generateNonce = nonce.Generate
	h.generateState = state.Generate
	h.generatePKCE = pkce.Generate
	h.getProvider = upstreamoidc.New
    h.validateIDToken = func(ctx context.Context, provider *oidc.Provider, audience string, token string) (*oidc.IDToken, error) {
	return provider.Verifier(&oidc.Config{ClientID: audience}).Verify(ctx, token)
},
	return nil
}

func (h *HandlerState) initOIDCDiscovery() error {
	// Make this method idempotent, so it can be called in multiple cases with no extra network requests.
	if h.provider != nil {
		return nil
	}

	h.Logger.V(debugLogLevel).Info("Pinniped: Performing OIDC discovery", "Issuer", h.Issuer)
	var err error
	h.provider, err = oidc.NewProvider(h.Ctx, h.Issuer)
	if err != nil {
		return fmt.Errorf("could not perform OIDC discovery for %q: %w", h.Issuer, err)
	}

	// Build an OAuth2 configuration based on the OIDC discovery data and our callback endpoint.
	h.OAuth2Config = &oauth2.Config{
		ClientID: h.ClientID,
		Endpoint: h.provider.Endpoint(),
		Scopes:   h.Scopes,
	}

	h.UseFormPost = false
	return nil
}

func (h *handlerState) tokenExchangeRFC8693(baseToken *oidctypes.Token) (*oidctypes.Token, error) {
	h.logger.V(debugLogLevel).Info("Pinniped: Performing RFC8693 token exchange", "requestedAudience", h.requestedAudience)
	// Perform OIDC discovery. This may have already been performed if there was not a cached base token.
	if err := h.initOIDCDiscovery(); err != nil {
		return nil, err
	}

	// Form the HTTP POST request with the parameters specified by RFC8693.
	reqBody := strings.NewReader(url.Values{
		"client_id":            []string{h.clientID},
		"grant_type":           []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             []string{h.requestedAudience},
		"subject_token":        []string{baseToken.AccessToken.Token},
		"subject_token_type":   []string{"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": []string{"urn:ietf:params:oauth:token-type:jwt"},
	}.Encode())
	req, err := http.NewRequestWithContext(h.ctx, http.MethodPost, h.oauth2Config.Endpoint.TokenURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("could not build RFC8693 request: %w", err)
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")

	// Perform the request.
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Expect an HTTP 200 response with "application/json" content type.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("content-type"))
	if err != nil {
		return nil, fmt.Errorf("failed to decode content-type header: %w", err)
	}
	if mediaType != "application/json" {
		return nil, fmt.Errorf("unexpected HTTP response content type %q", mediaType)
	}

	// Decode the JSON response body.
	var respBody struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Expect the token_type and issued_token_type response parameters to have some known values.
	if respBody.TokenType != "N_A" {
		return nil, fmt.Errorf("got unexpected token_type %q", respBody.TokenType)
	}
	if respBody.IssuedTokenType != "urn:ietf:params:oauth:token-type:jwt" {
		return nil, fmt.Errorf("got unexpected issued_token_type %q", respBody.IssuedTokenType)
	}

	// Validate the returned JWT to make sure we got the audience we wanted and extract the expiration time.
	stsToken, err := h.validateIDToken(h, h.provider, h.requestedAudience, respBody.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("received invalid JWT: %w", err)
	}

	return &oidctypes.Token{IDToken: &oidctypes.IDToken{
		Token:  respBody.AccessToken,
		Expiry: metav1.NewTime(stsToken.Expiry),
	}}, nil
}

func (h *HandlerState) redeemAuthCode(ctx context.Context, code string) (*oidctypes.Token, error) {
	return h.getProvider(h.OAuth2Config, h.provider, h.HTTPClient).
		ExchangeAuthcodeAndValidateTokens(
			ctx,
			code,
			h.PKCE,
			h.Nonce,
			h.OAuth2Config.RedirectURL,
		)
}
