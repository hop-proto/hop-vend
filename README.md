# hop-vend

Hop Vend is a GitHub application that issues Hop client certificates based on a user's membership within a GitHub organization. To run Hop Vend, create a GitHub App in your user settings, make it public, and attach it to the organization whose membership you want to check.

## Configuration

### GitHub App

On GitHub, go to your user settings (Profile Picture -> **Settings**). Click **Developer Settings** on the left. Create a new **GitHub Application**, not an OAuth integration. You will need the client ID and client secret to configure Hop Vend.

In the application configuration, grant **Permissions -> Organizations -> Read Members**.

To install the app to an organization, make it public from the app settings -> **Advanced** page.

### Hop Vend

Set `client_id` and `client_secret` in the `[github]` section of `config.toml`. You can optionally set configuration as environment variables prefixed with `HOP_VEND_`, for example `HOP_VEND_GITHUB_CLIENT_SECRET`. Set `org` to the name of the GitHub organization to be checked for membership.

In the `[ca]` section, set `cert_path` and `key_path`.

The properties of the issued certificate are set in the `[credential]` section.

## Developing and Building

This project depends on Hop itself, so your Go installation must be able to pull private Go repositories until Hop is open-sourced. This involves two steps: ensuring that `go get` uses SSH (instead of an access token) and informing `go get` that it should not check the transparency information because the repository is private.

To do this, add the following to `~/.gitconfig`:

``` 
[url "ssh://git@github.com/hop-proto/hop-go"]
        insteadOf = https://github.com/hop-proto/hop-go
```

When running `go get` to fetch dependencies:

```console
GOPRIVATE='github.com/hop-proto/*' go get ./...
```
