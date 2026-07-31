# hop-vend

Hop Vend issues short-lived Hop client credentials to identities authenticated
and authorized by a configured provider. GitHub OAuth and standards-compliant
OpenID Connect providers are supported. The credential is bound to the X25519
key that started enrollment; neither the private key nor provider tokens are
returned through the browser.

The enrollment flow is:

1. `hop-vend-client` connects to the Hop endpoint with the local Hop key.
2. Hop Vend returns a one-time identity-provider login URL over that connection.
3. The user opens the URL and authenticates.
4. Hop Vend applies the configured authorization policy.
5. A short-lived certificate for the original Hop key is returned over the
   same connection and saved by the client.

Enrollment requests expire after ten minutes by default and can be completed
only once.

## Authentication providers

Set `authentication.provider` to `github` or `oidc`. Both providers use the
authorization-code flow and the callback URL `<server.public_url>/callback`.
OIDC ID tokens are verified using discovery, including issuer, audience,
signature, expiry, and a transaction-bound nonce.

### GitHub

Create a GitHub App under **Settings → Developer settings → GitHub Apps**.

- Set the callback URL to `<server.public_url>/callback`.
- Grant **Organization permissions → Members: Read-only**.
- Install the app on the organization whose membership will be checked.
- Record the app's client ID and generate a client secret.

GitHub App user access tokens are sufficient for the authenticated-user
membership endpoint. Private memberships are supported when the app is
installed with the Members permission. An organization that enforces SAML SSO
may require the user to have an active SAML session while authorizing the app.

### OpenID Connect

Register Hop Vend as a confidential OIDC client. The configured identity claim
becomes the name in the issued certificate and must be a non-empty string.
`preferred_username` is the default.

The optional authorization policy requires a scalar or array-valued ID-token
claim to contain one value. If `authorization.claim` and `authorization.value`
are omitted, any identity authenticated by the configured issuer is allowed.

## Server configuration

Copy and edit `config.toml`. Secrets should normally be provided through the
environment rather than committed to the file:

```console
export HOP_VEND_GITHUB_CLIENT_SECRET='...'
go run .
```

Environment variables use the `HOP_VEND_` prefix and replace dots with
underscores. For example, `server.public_url` becomes
`HOP_VEND_SERVER_PUBLIC_URL`.

```toml
[authentication]
provider = "github"

[github]
client_id = "your-github-app-client-id"
client_secret = ""
org = "hop-proto"

[ca]
cert_path = "/etc/hop-vend/intermediate.pem"
key_path = "/etc/hop-vend/intermediate.key.pem"

[credential]
validity_seconds = 3600
request_timeout_seconds = 600

[server]
address = ":8080"
public_url = "https://vend.example.com"

[hop]
address = ":7777"
server_name = "vend-server"
```

For a generic OIDC provider, replace the authentication and GitHub sections
with:

```toml
[authentication]
provider = "oidc"

[oidc]
issuer = "https://identity.example.com"
client_id = "hop-vend"
client_secret = ""
identity_claim = "preferred_username"
scopes = ["openid", "profile", "email"]

[authorization]
claim = "groups"
value = "hop-users"
```

Provide the OIDC secret through `HOP_VEND_OIDC_CLIENT_SECRET`.
`server.public_url` must be the externally reachable HTTPS origin registered
with the provider. The HTTP and Hop listeners may use different internal
addresses behind a reverse proxy or firewall. The issuing intermediate key must
match the configured intermediate certificate.

## Enrolling a client

Place the trusted Hop root certificate at `~/.hop/root.cert`, then run:

```console
go run ./cmd/hop-vend-client -address vend.example.com:7777
```

The client creates `~/.hop/id_hop.pem` with mode `0600` if no key exists,
prints the one-time provider URL, waits for authorization, verifies the
returned chain and key binding, and writes:

- `~/.hop/id_hop.cert`
- `~/.hop/intermediate.cert`

Use `-help` to override these paths, the expected server name, or the ten-minute
timeout. `-insecure` is available only for local development because it skips
authentication of the Hop Vend server.

## Developing and building

Hop Vend requires Go 1.25 or newer.

The project currently depends on Hop through the private
`github.com/hop-proto/hop-go` repository. Configure Go and Git to fetch private
modules, then run:

```console
make build
make lint
make test
```

The test suite includes a complete in-memory OIDC provider and exercises
discovery, browser redirects, signed ID-token validation, authorization, Hop
enrollment, certificate issuance, and client persistence without external
credentials.
