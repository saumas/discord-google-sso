# Operator guide — Discord Google SSO

This guide covers everything a server maintainer needs to run the service:
Google and Discord OAuth registration, maintainer (bot) permission setup,
credential handling, backup and restore of the application-owned state
Secret, and revocation instructions.

## Overview

The service verifies that a Discord member controls an approved Google
Workspace identity, links the two 1:1, and applies your configured role
changes. State (identity links, membership timestamps, pending role
operations) lives in a Kubernetes Secret **owned by the application** — the
Helm chart does not create, template, or own it, so upgrades, rollbacks, and
uninstall/reinstall never destroy it.

## 1. Google Cloud — OAuth client registration

1. In the [Google Cloud Console](https://console.cloud.google.com/), open
   **APIs & Services → Credentials** for the project backing your Workspace.
2. **Create credentials → OAuth client ID → Web application**.
3. Authorized redirect URI: `https://<your-public-base-url>/callback/google`.
   The URI must match the deployed `publicBaseURL` **exactly** (scheme,
   host, path, and trailing slash).
4. Note the **Client ID** and **Client secret**.

The domain allowlist you configure on the service is checked against the
signed `hd` claim of the Google ID token: members must present a verified
email on an account whose hosted domain is in your allowlist. Consumer
Google accounts (no `hd`) are rejected.

## 2. Discord — application and bot registration

1. In the [Discord Developer Portal](https://discord.com/developers/applications),
   create an application. Note the **Application ID** (used as the OAuth
   Client ID) and the **Public Key** (hex) from the General Information page.
2. Add a redirect URI under OAuth2: `https://<your-public-base-url>/callback/discord`
   (again an exact match).
3. Create the **Client Secret** (OAuth2 page).
4. Create a **Bot** user and copy its **bot token**.
5. Install the application to your server: OAuth2 → URL Generator → scopes
   `bot` and `applications.commands`; open the generated URL and select your
   server.

## 3. Maintainer permission setup in Discord

The bot must be able to:

- read guild members (`Server Members Intent` in the Developer Portal, plus
  the **View Server Members** permission), and
- manage the roles you configure as `addRoles`, `removeRoles`, and
  `unverifiedRoles`.

Place the bot's role **above every role it manages** in your server's role
hierarchy (Discord role API calls fail with 403 otherwise; the service logs
those as permanent failures and keeps the pending operation recoverable).

As the maintainer you additionally own the human parts of onboarding
(maintainer-owned, out of the service's scope):

- Create the read-only **Welcome** channel visible to the unverified role
  set, and configure other channels so unverified members see only Welcome.
- Pin or post the verification link `https://<your-public-base-url>/verify`
  in Welcome.
- Create the roles referenced in the chart values (verified-role set,
  removal set, and the initial/unverified set — a role must appear in at
  most one of these groups; the service refuses to start otherwise).

## 4. Deployment

1. Create the credentials Secret (never committed to git, never templated by
   the chart):

   ```sh
   kubectl -n discord-sso create secret generic discord-google-sso-credentials \
     --from-literal=discord-client-secret=<discord-oauth-client-secret> \
     --from-literal=discord-bot-token=<bot-token> \
     --from-literal=google-client-secret=<google-client-secret>
   ```

2. Install the chart with your values (see `charts/discord-google-sso/values.yaml`
   for the full list):

   ```yaml
   guildID: "<your-guild-id>"
   publicBaseURL: "https://sso.example.com"
   discord:
     clientID: "<application-id>"
     publicKey: "<ed25519-public-key-hex>"
   google:
     clientID: "<google-client-id>"
   allowedDomains: ["your-workspace.com"]
   addRoles: ["<verified-role-id>"]
   removeRoles: ["<unverified-role-id>"]
   unverifiedRoles: ["<unverified-role-id>"]
   adminRoleIDs: ["<admin-role-id>"]
   credentialsSecret: discord-google-sso-credentials
   stateSecretName: discord-google-sso-state
   ```

   ```sh
   helm upgrade --install sso charts/discord-google-sso -n discord-sso --create-namespace -f my-values.yaml
   ```

3. Put an Ingress with TLS in front (see `ingress.enabled` values) — the
   OAuth URIs are exact-match, so keep the host stable.

The service starts serving when configuration is validated and the state
Secret is loaded. On first start it registers the guild-scoped `/revoke`
slash command (retried in the background if Discord is unreachable) and
runs a membership reconciliation pass; further passes run every five
minutes.

## 5. Credential handling

- The chart consumes credentials from a pre-created Secret by reference; it
  never templates them.
- Rotation: update the credentials Secret (`kubectl -n <ns> create secret
  ... --dry-run=client -o yaml | kubectl apply -f -`) and restart the
  Deployment (`kubectl -n <ns> rollout restart deploy/<release>`).
- Logs never contain OAuth codes, tokens, or ID-token material.

## 6. State backup and restore

The state document is a versioned, gzipped JSON payload stored under the
`state.json.gz` key of the app-owned Secret `<stateSecretName>`.

Backup:

```sh
kubectl -n discord-sso get secret discord-google-sso-state -o yaml > state-backup.yaml
```

Restore (e.g. into a fresh cluster):

```sh
kubectl -n discord-sso apply -f state-backup.yaml
```

Because the chart neither creates nor owns this Secret, `helm uninstall` +
reinstall in the retained namespace preserves it; restore is only needed
when the namespace or cluster itself is gone. The loader refuses corrupt
data, unknown schema versions, and Secrets belonging to a different guild
rather than resetting anything — if you see such an error, fix or restore the
Secret; do not delete it while it holds links you care about.

## 7. Revoking a member

Two entry points share the same core operation; both invalidate the
member's pending login sessions, restore the configured initial (unverified)
role set, remove the roles verification granted, and release the identity
link so the member can verify afresh.

### Slash command (admins)

In Discord, an authorized caller (holding one of the configured admin role
IDs or matching an admin user ID) runs:

```
/revoke member:@someone
```

The command is acknowledged immediately ("accepted"); the completed outcome
is delivered on the interaction channel when the role work finishes.

### Operator CLI (commit-only, works during a service outage)

The CLI runs as a Job using the application's ServiceAccount, so it shares
the chart's RBAC and works even while the Deployment is down; role
restoration is applied by the service's reconciler once it runs again.
Create the Job from a small manifest (recent kubectl versions do not support
`--overrides` on `create job`, so the manifest form is the reliable way to
set the ServiceAccount):

```sh
kubectl -n discord-sso apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: revoke-<name>
spec:
  backoffLimit: 0
  template:
    spec:
      serviceAccountName: <app-sa>   # the release's ServiceAccount
      restartPolicy: Never
      containers:
      - name: revoke
        image: <app-image>
        args: ["revoke", "<member-id>", "--state-secret", "<name>", "--guild", "<id>"]
EOF
kubectl -n discord-sso wait --for=condition=complete job/revoke-<name> --timeout=60s
kubectl -n discord-sso logs job/revoke-<name>
```

Notes:

- The manifest form is what makes the Job's pod run as the application's
  ServiceAccount (`kubectl --as` would only impersonate the request that
  creates the Job, not the pod).
- Pass the release's actual `stateSecretName` and guild ID (sourced from the
  release values) — the Job pod inherits nothing from the Deployment's
  environment.
- The CLI reports the durable commit and says explicitly if role
  restoration is still pending; it never claims early completion and never
  blocks unboundedly on Discord.

Delete the completed Job afterwards to keep the namespace tidy:
`kubectl -n discord-sso delete job revoke-<name>`.

## 8. Reconciliation behavior (what to expect)

- Every five minutes the service re-checks stored members via the Discord
  REST API. A member who left (kicked, banned, or left) has their link
  released and must verify afresh on rejoining.
- If the service was down when a member left, the departure is discovered on
  the next pass after restart.
- Discord outages, rate limits, and permission errors never count as
  departure; nothing is released on transient failures.
- Pending role operations (grants or revocations interrupted by crashes or
  provider failures) are resumed until applied.
