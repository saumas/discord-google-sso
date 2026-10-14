# Real-provider smoke test runbook

The automated E2E suite (`make e2e`) runs against Go-simulated providers.
This runbook verifies the service against the **real** Discord and Google
endpoints. Run it once per release candidate, from a deployment that is
otherwise identical to production except for the test identities.

## Prerequisites

- A deployed release per the [operator guide](operator-guide.md), with a
  real guild and a real Google Workspace (or a Workspace trial) domain you
  control.
- Two Google accounts: one **inside** the allowed Workspace domain, one
  **outside** it (any consumer Gmail account works for the negative case).
- A Discord account that is a member of the guild, and one that is not.
- An admin identity (admin role or user ID) for the revoke step.

## Procedure

1. **Unverified start state.** Confirm the member holds only the configured
   unverified roles and can see only the Welcome channel.

2. **Happy path.** Open `https://<public-base-url>/verify` in a private
   browser window as the member:
   - Approve the Discord authorization, then the Google authorization with
     the Workspace account.
   - Expect a "Verification complete" page.
   - In Discord, confirm the verified roles were added and the unverified
     roles removed; confirm the member can see the protected channels.
   - Confirm the state Secret records the link:
     `kubectl -n <ns> get secret <stateSecretName> -o jsonpath='{.data.state\.json\.gz}' | base64 -d | gunzip | jq .`

3. **Non-member.** Run the flow from the account that is not a member of
   the guild: expect rejection at the membership check, no Google step.

4. **Wrong domain / non-Workspace.** Run the flow with the consumer Google
   account: expect rejection with the "approved organization" message, no
   roles, no link stored.

5. **1:1 both directions.** A second Discord member attempts the flow with
   the same Google account: expect rejection. The original member attempts
   the flow with the other Google account: expect rejection.

6. **Cancellation and replay.** Cancel at the Discord consent screen, then
   complete a fresh flow. Reload the final Google callback URL: expect the
   "already used or expired" page, and confirm no duplicate effects.

7. **Re-assertion.** Manually remove a verified role from the member in
   Discord, re-run the flow with the same Google account: expect success and
   the role to be restored.

8. **Slash-command revoke.** As the admin, run `/revoke member:@member`.
   Expect an immediate "accepted" acknowledgment, then the completed
   outcome on the channel; the member's roles return to the unverified set
   and the link is released. Re-run the flow to re-verify.

9. **CLI revoke.** Using the documented command:

   ```sh
   kubectl -n <ns> create job revoke-smoke --image=<app-image> \
     --overrides='{"spec":{"template":{"spec":{"serviceAccountName":"<app-sa>"}}}}' \
     -- /discord-google-sso revoke <member-id> --state-secret <name> --guild <id>
   kubectl -n <ns> wait --for=condition=complete job/revoke-smoke --timeout=60s
   kubectl -n <ns> logs job/revoke-smoke
   ```

   Expect "revocation committed", plus either completion or an explicit
   "role restoration is still pending" line; if pending, wait for the next
   reconcile pass (≤ five minutes) and confirm the roles.

10. **Departure.** Kick the (re-verified) member from the guild. Within
    five minutes the link is released (check the Secret) and the member's
    rejoining requires fresh verification.

11. **Log hygiene.** During and after the run, inspect the service logs:

    ```sh
    kubectl -n <ns> logs deploy/<release>
    ```

    Confirm no OAuth codes, tokens, or ID-token material appear (grep for
    the code shown in the browser address bar during the flow — it must not
    appear in any log line).

## Pass criteria

Every numbered step above behaves as described; no step leaves the state
Secret or the member's roles in an unexpected state, and the logs stay free
of secrets.
