package authnz

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	appv1alpha1 "github.com/getupio-undistro/undistro/apis/app/v1alpha1"
	"github.com/getupio-undistro/undistro/pkg/scheme"
	"github.com/getupio-undistro/undistro/pkg/undistro"
	"github.com/getupio-undistro/undistro/pkg/util"
	"golang.org/x/oauth2"
	"net/http"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/getupio-undistro/undistro/third_party/pinniped/internal/httputil/httperr"
	"go.pinniped.dev/pkg/oidcclient/pkce"
	"go.pinniped.dev/pkg/oidcclient/state"
)

func (h *HandlerState) HandleLogin(w http.ResponseWriter, r *http.Request) error {
	h, err := h.updateCallbackHandlerState(r.Context())
	if err != nil {
		return httperr.Newf(http.StatusInternalServerError, "error setting up callback handler state %s", err.Error())
	}

	// Initialize login parameters.
	h.State, err = state.Generate()
	if err != nil {
		return err
	}
	h.PKCE, err = pkce.Generate()
	if err != nil {
		return err
	}

	// Prepare the common options for the authorization URL. We don't have the redirect URL yet though.
	authorizeOptions := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		h.PKCE.Challenge(),
		h.PKCE.Method(),
	}
	// Get the callback url from helm release
	c, err := client.New(h.RestConf, client.Options{
		Scheme: scheme.Scheme,
	})
	if err != nil {
		return err
	}
	hr := appv1alpha1.HelmRelease{}
	k := client.ObjectKey{
		Namespace: undistro.Namespace,
		Name:      "pinniped-supervisor",
	}
	err = c.Get(h.Ctx, k, &hr)
	if err != nil {
		return err
	}
	cli := http.DefaultClient
	isLocal, err := util.IsLocalCluster(h.Ctx, c)
	if err != nil {
		return err
	}
	if isLocal {
		const caSecretName = "ca-secret"
		const caName = "ca.crt"
		byt, err := util.GetCaFromSecret(h.Ctx, c, caSecretName, caName, undistro.Namespace)
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
	}
	h.HTTPClient = cli
	h.Ctx = context.WithValue(r.Context(), oauth2.HTTPClient, h.HTTPClient)
	config := hr.ValuesAsMap()["config"].(map[string]interface{})
	// Perform OIDC discovery.
	if err := h.initOIDCDiscovery(); err != nil {
		return err
	}
	h.OAuth2Config.RedirectURL = config["callbackURL"].(string)
	authorizeURL := h.OAuth2Config.AuthCodeURL(h.State.String(), authorizeOptions...)
	http.Redirect(w, r, authorizeURL, http.StatusTemporaryRedirect)
	return nil
}
