package authnz

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/getupio-undistro/undistro/pkg/kube"
	"github.com/getupio-undistro/undistro/pkg/scheme"
	"github.com/getupio-undistro/undistro/pkg/undistro"
	"github.com/getupio-undistro/undistro/pkg/util"
	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/httputil/httperr"
	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/oidc/provider"
	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/upstreamoidc"
	"github.com/go-logr/logr"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/ory/fosite"
	"go.pinniped.dev/pkg/conciergeclient"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	"go.pinniped.dev/pkg/oidcclient/pkce"
	"go.pinniped.dev/pkg/oidcclient/state"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

const (
	debugLogLevel = 4
	sessionKey    = "oidctoken"
)

type HandlerState struct {
	// Basic parameters.
	Ctx                          context.Context
	Logger                       logr.Logger
	Issuer                       string
	ClientID                     string
	Scopes                       []string
	HTTPClient                   *http.Client
	State                        state.State
	PKCE                         pkce.Code
	Nonce                        nonce.Nonce
	RequestedAudience            string
	upstreamIdentityProviderName string
	upstreamIdentityProviderType string

	getProvider     func(*oauth2.Config, *oidc.Provider, *http.Client) provider.UpstreamOIDCIdentityProviderI
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
	SessionStore sessions.Store
}

func SetRestConfHandlerState(r *rest.Config) *HandlerState {
	return &HandlerState{
		RestConf:     r,
		SessionStore: sessions.NewCookieStore(securecookie.GenerateRandomKey(32)),
	}
}

func (h *HandlerState) handleRefresh(ctx context.Context, refreshToken *oidctypes.RefreshToken) (*oidctypes.Token, error) {
	refreshSource := h.OAuth2Config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken.Token})

	refreshed, err := refreshSource.Token()
	if err != nil {
		// Ignore errors during refresh, but return nil which will trigger the full login flow.
		return nil, err
	}

	// The spec is not 100% clear about whether an ID token from the refresh flow should include a nonce, and at least
	// some providers do not include one, so we skip the nonce validation here (but not other validations).
	return h.getProvider(h.OAuth2Config, h.provider, h.HTTPClient).ValidateToken(ctx, refreshed, "")
}

func (h *HandlerState) HandleLogout(w http.ResponseWriter, r *http.Request) error {
	session, err := h.SessionStore.Get(r, "undistro-login")
	if err != nil {
		return err
	}
	session.Options.MaxAge = -1
	return session.Save(r, w)
}

func (h *HandlerState) HandleAuthCluster(w http.ResponseWriter, r *http.Request) error {
	h.Ctx = r.Context()
	// Perform OIDC discovery.
	if err := h.initOIDCDiscovery(); err != nil {
		return err
	}
	session, err := h.SessionStore.Get(r, "undistro-login")
	if err != nil {
		return err
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	c, err := client.New(cfg, client.Options{
		Scheme: scheme.Scheme,
	})
	if err != nil {
		return err
	}
	v := session.Values[sessionKey]
	if v == nil {
		session.Options.MaxAge = -1
		session.Save(r, w)
		return httperr.New(http.StatusBadRequest, "login required")
	}
	tokenStr := v.(string)
	token := &oidctypes.Token{}
	err = yaml.Unmarshal([]byte(tokenStr), token)
	if err != nil {
		session.Options.MaxAge = -1
		session.Save(r, w)
		return httperr.Newf(http.StatusBadRequest, "login required %s", err)
	}
	cli, err := h.updateHTTPClientCert(h.Ctx, c)
	if err != nil {
		return err
	}
	h.HTTPClient = cli
	if token.RefreshToken != nil && token.RefreshToken.Token != "" {
		token, err = h.handleRefresh(h.Ctx, token.RefreshToken)
		if err != nil {
			session.Options.MaxAge = -1
			session.Save(r, w)
			return httperr.Newf(http.StatusInternalServerError, "failed refresh: %s", err)
		}
		tokenyaml, err := yaml.Marshal(*token)
		if err != nil {
			return err
		}
		session.Values[sessionKey] = string(tokenyaml)
		err = session.Save(r, w)
		if err != nil {
			return err
		}
	}
	//// Perform the RFC8693 token exchange.
	exchangedToken, err := h.tokenExchangeRFC8693(token)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	name := q.Get("name")
	namspace := q.Get("namespace")

	if name == "" || namspace == "" {
		return httperr.New(http.StatusBadRequest, "query params name and namespace are required")
	}
	if name != "management" && namspace != "undistro-system" {
		cfg, err = kube.NewClusterConfig(h.Ctx, c, name, namspace)
		if err != nil {
			return err
		}
	}
	conciergeInfo, err := kube.ConciergeInfoFromConfig(h.Ctx, cfg)
	if err != nil {
		return err
	}
	concierge, err := conciergeclient.New(
		conciergeclient.WithEndpoint(conciergeInfo.Endpoint),
		conciergeclient.WithBase64CABundle(conciergeInfo.CABundle),
		conciergeclient.WithAuthenticator("jwt", "supervisor-jwt-authenticator"),
		conciergeclient.WithAPIGroupSuffix("pinniped.dev"),
	)
	if err != nil {
		return err
	}
	cred, err := concierge.ExchangeToken(h.Ctx, exchangedToken.IDToken.Token)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(cred)
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
	session, err := h.SessionStore.Get(r, "undistro-login")
	if err != nil {
		return err
	}
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
	tokenyaml, err := yaml.Marshal(*token)
	if err != nil {
		return err
	}
	session.Values[sessionKey] = string(tokenyaml)
	err = session.Save(r, w)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "login completed you can close this window")
	return nil
}

func (h *HandlerState) updateHTTPClientCert(ctx context.Context, c client.Client) (*http.Client, error) {
	const caSecretName = "ca-secret"
	const caName = "ca.crt"
	byt, err := util.GetCaFromSecret(ctx, c, caSecretName, caName, undistro.Namespace)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(byt)

	tlsConfig := &tls.Config{
		RootCAs: certPool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	cli := &http.Client{Transport: transport}
	h.Ctx = context.WithValue(ctx, oauth2.HTTPClient, h.HTTPClient)
	return cli, nil
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
		cli, err = h.updateHTTPClientCert(ctx, c)
		if err != nil {
			return err
		}
	}
	h.HTTPClient = cli
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
	h.generateNonce = nonce.Generate
	h.generateState = state.Generate
	h.generatePKCE = pkce.Generate
	h.getProvider = upstreamoidc.New
	h.validateIDToken = func(ctx context.Context, provider *oidc.Provider, audience string, token string) (*oidc.IDToken, error) {
		return provider.Verifier(&oidc.Config{ClientID: audience}).Verify(ctx, token)
	}
	// Todo support LDAP
	h.upstreamIdentityProviderType = "oidc"
	h.RequestedAudience = "undistro-request-audienc"
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

func (h *HandlerState) tokenExchangeRFC8693(baseToken *oidctypes.Token) (*oidctypes.Token, error) {
	h.Logger.V(debugLogLevel).Info("Pinniped: Performing RFC8693 token exchange", "requestedAudience", h.RequestedAudience)
	// Perform OIDC discovery. This may have already been performed if there was not a cached base token.
	if err := h.initOIDCDiscovery(); err != nil {
		return nil, err
	}

	// Form the HTTP POST request with the parameters specified by RFC8693.
	reqBody := strings.NewReader(url.Values{
		"client_id":            []string{h.ClientID},
		"grant_type":           []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             []string{h.RequestedAudience},
		"subject_token":        []string{baseToken.AccessToken.Token},
		"subject_token_type":   []string{"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": []string{"urn:ietf:params:oauth:token-type:jwt"},
	}.Encode())
	req, err := http.NewRequestWithContext(h.Ctx, http.MethodPost, h.OAuth2Config.Endpoint.TokenURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("could not build RFC8693 request: %w", err)
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")

	// Perform the request.
	resp, err := h.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Expect an HTTP 200 response with "application/json" content type.
	if resp.StatusCode != http.StatusOK {
		buf := bytes.Buffer{}
		io.Copy(&buf, resp.Body)
		return nil, fmt.Errorf("unexpected HTTP response status %s", buf.String())
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
	stsToken, err := h.validateIDToken(h.Ctx, h.provider, h.RequestedAudience, respBody.AccessToken)
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
