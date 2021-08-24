# 7 - Identity

## Minimal Identity Configuration
Identity functionality is available as of release v0.34.0 as a feature flag. To enable Identity feature, put the following minimal configuration into your UnDistro config file.
```yaml
undistro:
  identity:
    enabled: true
    name: <cool-name-for-identity-object>
    oidc:
      provider:
      issuer:
          name: gitlab | google # for now, we just support these Identity Providers
    credentials:
      clientID: <your-client-id> 
      clientSecret: <your-client-secret>
```