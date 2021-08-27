package callback

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/getupio-undistro/undistro/pkg/scheme"
	"github.com/getupio-undistro/undistro/pkg/undistro"
	"github.com/getupio-undistro/undistro/pkg/util"
	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/httputil/httperr"
	"github.com/go-logr/logr"
	"github.com/ory/fosite"
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
	// Perform OIDC discovery.
	if err := h.initOIDCDiscovery(); err != nil {
		return err
	}
	h, err := h.updateCallbackHandlerState(r.Context())
	if err != nil {
		return httperr.Newf(http.StatusInternalServerError, "error setting up callback handler state %s", err.Error())
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
	token, err := h.OAuth2Config.Exchange(r.Context(), params.Get("code"))
	if err != nil {
		return httperr.Wrap(http.StatusBadRequest, "could not complete code exchange", err)
	}

	resp := make(map[string]interface{})
	resp["token"] = token
	resp["type"] = "Bearer"

	encoder := json.NewEncoder(w)
	err = encoder.Encode(resp)
	if err != nil {
		return httperr.Wrap(http.StatusInternalServerError, "could not marshal token", err)
	}
	return nil
}

func (h *HandlerState) updateCallbackHandlerState(ctx context.Context) (*HandlerState, error) {
	fedo := make(map[string]interface{})
	c, err := client.New(h.RestConf, client.Options{
		Scheme: scheme.Scheme,
	})
	if err != nil {
		return nil, err
	}
	o, err := util.GetFromConfigMap(
		ctx, c, "identity-config", undistro.Namespace, "federationdomain.yaml", fedo)
	fedo = o.(map[string]interface{})
	if err != nil {
		return nil, err
	}
	issuer := fedo["issuer"].(string)
	cli := http.DefaultClient
	isLocal, err := util.IsLocalCluster(ctx, c)
	if err != nil {
		return nil, err
	}
	if isLocal {
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
		cli = &http.Client{Transport: transport}
	}

	handlerState := &HandlerState{
		Ctx:      context.Background(),
		Logger:   ctrl.Log,
		Issuer:   issuer,
		ClientID: "undistro-ui",
		Scopes: fosite.Arguments{
			oidc.ScopeOpenID,
			oidc.ScopeOfflineAccess,
			"profile",
			"email",
			"pinniped:request-audience",
		},
		HTTPClient: cli,
	}
	handlerState.RestConf = h.RestConf

	return handlerState, nil
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

	// Use response_mode=form_post if the provider supports it.
	var discoveryClaims struct {
		ResponseModesSupported []string `json:"response_modes_supported"`
	}
	if err := h.provider.Claims(&discoveryClaims); err != nil {
		return fmt.Errorf("could not decode response_modes_supported in OIDC discovery from %q: %w", h.Issuer, err)
	}
	h.UseFormPost = stringSliceContains(discoveryClaims.ResponseModesSupported, "form_post")
	return nil
}

func stringSliceContains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
