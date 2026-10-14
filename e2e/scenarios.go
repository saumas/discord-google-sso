package main

import (
	"fmt"
	"strings"
	"time"
)

func runScenarios(e *env) int {
	type scenario struct {
		name string
		fn   func(*env) error
	}
	scenarios := []scenario{
		{"HappyPath", scHappyPath},
		{"NonMemberRejected", scNonMember},
		{"PolicyRejections", scPolicyRejections},
		{"CancellationAndReplay", scCancelReplay},
		{"OneToOne", scOneToOne},
		{"ReassertionIdempotent", scReassertion},
		{"SlashRevoke", scSlashRevoke},
		{"SlashRevokeUnauthorized", scSlashRevokeUnauthorized},
		{"SlashRevokeBadSignature", scSlashRevokeBadSignature},
		{"RevokeDuringLogin", scRevokeDuringLogin},
		{"CliRevoke", scCliRevoke},
		{"LeaveRejoinBetweenPolls", scLeaveRejoin},
		{"MissedDepartureDuringDowntime", scMissedDeparture},
		{"ApiOutageConservative", scApiOutage},
		{"CrashRestartPendingGrant", scCrashRestartGrant},
		{"DowntimeCliRevokeSupersedesPendingGrant", scDowntimeCliRevoke},
		{"PendingRevocationSupersededByReverification", scRevokeSupersededByReverify},
		{"RepeatedRevocationPending", scRepeatedRevocation},
		{"PendingGrantForRejoinedMember", scPendingGrantRejoined},
		{"PolicyChangeReattemptDisturbsNothing", scPolicyChange},
		{"HelmLifecyclePreservesState", scHelmLifecycle},
		{"RbacProbe", scRbacProbe},
		{"LogRedaction", scLogRedaction},
	}

	failed := 0
	for _, s := range scenarios {
		fmt.Printf("\n=== %s\n", s.name)
		start := time.Now()
		e.discAdmin("POST", "/_admin/clear-failures", nil)
		if err := s.fn(e); err != nil {
			failed++
			fmt.Printf("FAIL %s (%s): %v\n", s.name, time.Since(start).Round(time.Second), err)
		} else {
			fmt.Printf("PASS %s (%s)\n", s.name, time.Since(start).Round(time.Second))
		}
	}
	return failed
}

// verifyUser runs the real browser flow as the given simulated identities
// and returns the final page body.
func verifyUser(e *env, user string, gid googleID) string {
	e.loginDiscord(user)
	e.loginGoogle(gid)
	return e.browser.verifyFlow(e)
}

func expectBody(body, want string) error {
	if !strings.Contains(body, want) {
		return fmt.Errorf("page does not contain %q: %s", want, clip(body, 200))
	}
	return nil
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// pollState waits for cond to hold on the state document.
func pollState(what string, timeout time.Duration, cond func() bool) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", what)
}

func scHappyPath(e *env) error {
	body := verifyUser(e, userMain, gIDWorkspace)
	if err := expectBody(body, "Verification complete"); err != nil {
		return err
	}
	m := e.stateMember(userMain)
	if m == nil || m.GoogleSub != gIDWorkspace.Sub {
		return fmt.Errorf("link missing or wrong: %+v", m)
	}
	if !e.hasRole(userMain, roleVerified1) || !e.hasRole(userMain, roleVerified2) {
		return fmt.Errorf("verified roles not applied: %v", e.memberRoles(userMain))
	}
	if !e.hasRole(userMain, roleUnrelated) {
		return fmt.Errorf("unrelated role not preserved: %v", e.memberRoles(userMain))
	}
	doc, _ := e.readState()
	if len(doc.Pending) != 0 {
		return fmt.Errorf("pending ops left: %+v", doc.Pending)
	}
	return nil
}

func scNonMember(e *env) error {
	body := verifyUser(e, userOut, gIDWorkspace)
	if err := expectBody(body, "not currently a member"); err != nil {
		return err
	}
	if e.stateMember(userOut) != nil {
		return fmt.Errorf("non-member stored a link")
	}
	return nil
}

func scPolicyRejections(e *env) error {
	for _, tc := range []struct {
		name string
		id   googleID
		want string
	}{
		{"unapproved-domain", gIDEvilDomain, "approved organization"},
		{"consumer-no-hd", gIDConsumer, "approved organization"},
		{"unverified-email", gIDUnverified, "not verified"},
	} {
		body := verifyUser(e, userMain, tc.id)
		if err := expectBody(body, tc.want); err != nil {
			return fmt.Errorf("%s: %w", tc.name, err)
		}
		if e.hasRole(userMain, roleVerified1) != true {
			// userMain is already verified from the happy path; policy
			// failures must disturb nothing.
			return fmt.Errorf("%s: prior verified roles disturbed", tc.name)
		}
	}
	// A failed re-attempt with a non-linked identity for a fresh user too.
	body := verifyUser(e, userSecond, gIDEvilDomain)
	return expectBody(body, "approved organization")
}

func scCancelReplay(e *env) error {
	e.loginDiscord(userMain)
	e.loginGoogle(gIDWorkspace)

	// Cancel at the Discord consent page.
	body, err := e.browser.flowSteps(e, stepDeny, stepApprove)
	if err != nil {
		return err
	}
	if err := expectBody(body, "cancelled"); err != nil {
		return err
	}
	// A fresh attempt works afterwards.
	body = verifyUser(e, userMain, gIDWorkspace)
	if err := expectBody(body, "Verification complete"); err != nil {
		return err
	}
	// Capture the final (Google callback) URL and replay it.
	cbURL, err := e.browser.currentURL()
	if err != nil {
		return err
	}
	if !strings.Contains(cbURL, "/callback/google") {
		return fmt.Errorf("unexpected final URL: %s", cbURL)
	}
	body, err = e.browser.navigateTo(cbURL)
	if err != nil {
		return err
	}
	return expectBody(body, "already used or expired")
}

func scOneToOne(e *env) error {
	// userMain is verified with gIDWorkspace. A second member attempts the
	// same Google identity.
	body := verifyUser(e, userSecond, gIDWorkspace)
	if err := expectBody(body, "already linked to another Discord account"); err != nil {
		return err
	}
	if e.hasRole(userSecond, roleVerified1) {
		return fmt.Errorf("loser received verified roles")
	}
	// The verified member attempts a different Google identity.
	body = verifyUser(e, userMain, gIDOther)
	return expectBody(body, "already verified with a different identity")
}

func scReassertion(e *env) error {
	// Roles get lost (e.g. removed manually).
	roles := []string{roleUnverif1, roleUnverif2, roleUnrelated, roleVerified2}
	e.discAdmin("POST", "/_admin/member", map[string]any{"user_id": userMain, "guild_id": guildID, "roles": roles})
	body := verifyUser(e, userMain, gIDWorkspace)
	if err := expectBody(body, "Verification complete"); err != nil {
		return err
	}
	if !e.hasRole(userMain, roleVerified1) {
		return fmt.Errorf("lost role not self-healed: %v", e.memberRoles(userMain))
	}
	doc, _ := e.readState()
	linked := 0
	for _, m := range doc.Members {
		if m.GoogleSub == gIDWorkspace.Sub {
			linked++
		}
	}
	if linked != 1 {
		return fmt.Errorf("re-assertion created duplicate links: %d", linked)
	}
	return nil
}

func scSlashRevoke(e *env) error {
	status, respBody, err := e.postInteraction(revokeCommand(userMain, userAdmin, []string{roleAdmin}))
	if err != nil {
		return err
	}
	if status != 200 || !strings.Contains(respBody, "accepted") {
		return fmt.Errorf("ack: status %d body %s", status, respBody)
	}
	fu, ok := e.waitFollowup(1, "Revocation complete")
	if !ok {
		return fmt.Errorf("completion follow-up not delivered: %v", e.followups())
	}
	if e.stateMember(userMain) != nil {
		return fmt.Errorf("link not released")
	}
	if e.hasRole(userMain, roleVerified1) || e.hasRole(userMain, roleVerified2) {
		return fmt.Errorf("granted roles survive revocation: %v", e.memberRoles(userMain))
	}
	if !e.hasRole(userMain, roleUnverif1) || !e.hasRole(userMain, roleUnverif2) {
		return fmt.Errorf("unverified roles not restored: %v", e.memberRoles(userMain))
	}
	if !e.hasRole(userMain, roleUnrelated) {
		return fmt.Errorf("unrelated role lost: %v", e.memberRoles(userMain))
	}
	_ = fu
	// Re-verify so later scenarios start from a verified member.
	return expectBody(verifyUser(e, userMain, gIDWorkspace), "Verification complete")
}

func scSlashRevokeUnauthorized(e *env) error {
	before := e.memberRoles(userMain)
	status, respBody, err := e.postInteraction(revokeCommand(userMain, userSecond, []string{roleUnrelated}))
	if err != nil {
		return err
	}
	if status != 200 || !strings.Contains(respBody, "not authorized") {
		return fmt.Errorf("status %d body %s", status, respBody)
	}
	if e.stateMember(userMain) == nil {
		return fmt.Errorf("unauthorized revoke released the link")
	}
	if fmt.Sprint(before) != fmt.Sprint(e.memberRoles(userMain)) {
		return fmt.Errorf("roles disturbed by unauthorized revoke")
	}
	return nil
}

func scSlashRevokeBadSignature(e *env) error {
	p := revokeCommand(userMain, userAdmin, []string{roleAdmin})
	body, _ := jsonMarshal(p)
	ts := fmt.Sprint(time.Now().Unix())
	req, _ := httpNewRequest("POST", e.appURL+"/interactions", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature-Timestamp", ts)
	req.Header.Set("X-Signature-Ed25519", strings.Repeat("00", 64)) // invalid
	resp, err := httpDefaultClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		return fmt.Errorf("invalid signature accepted: %d", resp.StatusCode)
	}
	if e.stateMember(userMain) == nil {
		return fmt.Errorf("forged request released the link")
	}
	return nil
}

func scRevokeDuringLogin(e *env) error {
	// userFresh has an in-flight login paused at the Google consent page
	// (Discord identity already established).
	e.loginDiscord(userFresh)
	e.loginGoogle(gIDWorkspace)
	if _, err := e.browser.flowSteps(e, stepApprove, stepStopAtGoogle); err != nil {
		return err
	}
	// A revocation for the never-linked target lands mid-login.
	status, respBody, err := e.postInteraction(revokeCommand(userFresh, userAdmin, []string{roleAdmin}))
	if err != nil {
		return err
	}
	if status != 200 || !strings.Contains(respBody, "accepted") {
		return fmt.Errorf("ack: %d %s", status, respBody)
	}
	// The login completes: it must not grant access.
	body, err := e.browser.continueFromGoogleConsent()
	if err != nil {
		return err
	}
	if !strings.Contains(body, "superseded") && !strings.Contains(body, "start again") {
		return fmt.Errorf("revoked-during-login login granted access: %s", clip(body, 200))
	}
	if e.stateMember(userFresh) != nil {
		return fmt.Errorf("link stored despite revocation")
	}
	if e.hasRole(userFresh, roleVerified1) {
		return fmt.Errorf("roles granted despite revocation")
	}
	return nil
}

func scCliRevoke(e *env) error {
	// userSecond verifies first.
	if err := expectBody(verifyUser(e, userSecond, gIDOther), "Verification complete"); err != nil {
		return err
	}
	// The operator guide's documented kubectl create job command.
	sa := release + "-discord-google-sso"
	e.kubectl("create", "job", "revoke-e2e-cli",
		"--image="+appImage,
		"--overrides="+fmt.Sprintf(`{"spec":{"template":{"spec":{"serviceAccountName":%q}}}}`, sa),
		"--", "/discord-google-sso", "revoke", userSecond,
		"--state-secret", stateSecret, "--guild", guildID)
	e.kubectl("wait", "--for=condition=complete", "job/revoke-e2e-cli", "--timeout=90s")
	logs := e.kubectl("logs", "job/revoke-e2e-cli")
	if !strings.Contains(logs, "revocation committed") {
		return fmt.Errorf("cli output: %s", clip(logs, 400))
	}
	if e.stateMember(userSecond) != nil {
		return fmt.Errorf("link not released by CLI")
	}
	// Role restoration is applied by the reconciler.
	if err := pollState("unverified roles restored", 30*time.Second, func() bool {
		return e.hasRole(userSecond, roleUnverif1) && e.hasRole(userSecond, roleUnverif2) &&
			!e.hasRole(userSecond, roleVerified1)
	}); err != nil {
		return err
	}
	e.kubectl("delete", "job", "revoke-e2e-cli")
	return nil
}

func scLeaveRejoin(e *env) error {
	// userMain is verified. The member leaves and rejoins (newer joined_at).
	e.discAdmin("POST", "/_admin/member", map[string]any{
		"user_id": userMain, "guild_id": guildID,
		"joined_at": time.Now().UTC().Format(time.RFC3339),
		"roles":     []string{roleUnverif1, roleUnverif2, roleUnrelated},
	})
	if err := pollState("leave/rejoin release", 30*time.Second, func() bool {
		return e.stateMember(userMain) == nil
	}); err != nil {
		return err
	}
	// The member must verify afresh (the old verification is gone).
	return expectBody(verifyUser(e, userMain, gIDWorkspace), "Verification complete")
}

func scMissedDeparture(e *env) error {
	// userMain is verified; the service goes down while they leave.
	e.scaleApp(0)
	if err := pollAppScaled(e, 0); err != nil {
		return err
	}
	e.discAdmin("POST", "/_admin/kick", map[string]any{"user_id": userMain, "guild_id": guildID})
	e.scaleApp(1)
	if err := e.waitReady(); err != nil {
		return err
	}
	if err := pollState("missed departure release after restart", 30*time.Second, func() bool {
		return e.stateMember(userMain) == nil
	}); err != nil {
		return err
	}
	// Restore membership for later scenarios and re-verify.
	e.discAdmin("POST", "/_admin/member", map[string]any{"user_id": userMain, "guild_id": guildID, "roles": []string{roleUnverif1, roleUnverif2, roleUnrelated}})
	return expectBody(verifyUser(e, userMain, gIDWorkspace), "Verification complete")
}

func pollAppScaled(e *env, replicas int) error {
	deadline := time.Now().Add(60 * time.Second)
	name := release + "-discord-google-sso"
	for time.Now().Before(deadline) {
		out := e.kubectl("get", "deploy", name, "-o", "jsonpath={.status.replicas}")
		if out == fmt.Sprint(replicas) {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("deployment never scaled to %d", replicas)
}

func scApiOutage(e *env) error {
	// Member lookups fail; nothing may be released.
	e.discAdmin("POST", "/_admin/fail", map[string]any{
		"path": "/api/guilds/" + guildID + "/members/", "status": 500, "count": 0,
	})
	time.Sleep(8 * time.Second) // > 2 reconcile intervals
	if e.stateMember(userMain) == nil {
		return fmt.Errorf("API outage treated as departure")
	}
	e.discAdmin("POST", "/_admin/clear-failures", nil)
	return nil
}

func scCrashRestartGrant(e *env) error {
	// Role adds fail; the browser flow reports in-progress honestly.
	e.discAdmin("POST", "/_admin/fail", map[string]any{
		"path": "/roles/", "status": 500, "count": 0,
	})
	body := verifyUser(e, userSecond, gIDOther)
	if err := expectBody(body, "in progress"); err != nil {
		return err
	}
	doc, _ := e.readState()
	op := doc.Pending[userSecond]
	if op == nil {
		return fmt.Errorf("no pending grant recorded")
	}
	// Crash and restart; resumption completes the grant.
	e.discAdmin("POST", "/_admin/clear-failures", nil)
	if err := e.restartApp(); err != nil {
		return err
	}
	if err := pollState("grant resumption", 30*time.Second, func() bool {
		return e.hasRole(userSecond, roleVerified1) && e.hasRole(userSecond, roleVerified2) && e.stateMember(userSecond) != nil
	}); err != nil {
		return err
	}
	doc, _ = e.readState()
	if doc.Pending[userSecond] != nil {
		return fmt.Errorf("resumed op not completed")
	}
	return nil
}

func scDowntimeCliRevoke(e *env) error {
	// A pending grant exists; during downtime the CLI revokes.
	e.discAdmin("POST", "/_admin/fail", map[string]any{"path": "/roles/", "status": 500, "count": 0})
	body := verifyUser(e, userFresh, gIDWorkspace)
	if err := expectBody(body, "in progress"); err != nil {
		return err
	}
	e.scaleApp(0)
	if err := pollAppScaled(e, 0); err != nil {
		return err
	}
	sa := release + "-discord-google-sso"
	e.kubectl("create", "job", "revoke-e2e-down",
		"--image="+appImage,
		"--overrides="+fmt.Sprintf(`{"spec":{"template":{"spec":{"serviceAccountName":%q}}}}`, sa),
		"--", "/discord-google-sso", "revoke", userFresh,
		"--state-secret", stateSecret, "--guild", guildID)
	e.kubectl("wait", "--for=condition=complete", "job/revoke-e2e-down", "--timeout=90s")
	e.kubectl("delete", "job", "revoke-e2e-down")
	e.discAdmin("POST", "/_admin/clear-failures", nil)
	e.scaleApp(1)
	if err := e.waitReady(); err != nil {
		return err
	}
	// The resumption must discard the stale grant and apply the revocation.
	if err := pollState("downtime revocation terminal state", 30*time.Second, func() bool {
		return e.stateMember(userFresh) == nil &&
			!e.hasRole(userFresh, roleVerified1) && !e.hasRole(userFresh, roleVerified2) &&
			e.hasRole(userFresh, roleUnverif1) && e.hasRole(userFresh, roleUnverif2)
	}); err != nil {
		return fmt.Errorf("%w; roles: %v", err, e.memberRoles(userFresh))
	}
	return nil
}

func scRevokeSupersededByReverify(e *env) error {
	// userMain is verified. A revocation's restoration re-adds the first
	// unverified role but fails on the second.
	e.discAdmin("POST", "/_admin/fail", map[string]any{
		"path": "/roles/" + roleUnverif2, "status": 500, "count": 0,
	})
	status, respBody, err := e.postInteraction(revokeCommand(userMain, userAdmin, []string{roleAdmin}))
	if err != nil {
		return err
	}
	if status != 200 || !strings.Contains(respBody, "accepted") {
		return fmt.Errorf("ack: %d %s", status, respBody)
	}
	// Removals succeed; first unverified role re-added; second is pending.
	if err := pollState("partial restoration", 30*time.Second, func() bool {
		return e.hasRole(userMain, roleUnverif1) && !e.hasRole(userMain, roleVerified1)
	}); err != nil {
		return fmt.Errorf("%w; roles: %v", err, e.memberRoles(userMain))
	}
	doc, _ := e.readState()
	if op := doc.Pending[userMain]; op == nil || op.Kind != "revoke" || len(op.RestoredSoFar) != 1 {
		return fmt.Errorf("partial revoke op wrong: %+v", doc.Pending[userMain])
	}
	// Re-verification supersedes the partial revocation: verified roles
	// applied, restored unverified roles removed again.
	e.discAdmin("POST", "/_admin/clear-failures", nil)
	if err := expectBody(verifyUser(e, userMain, gIDWorkspace), "Verification complete"); err != nil {
		return err
	}
	if e.hasRole(userMain, roleUnverif1) || e.hasRole(userMain, roleUnverif2) {
		return fmt.Errorf("restored unverified roles survived re-verification: %v", e.memberRoles(userMain))
	}
	if !e.hasRole(userMain, roleVerified1) || !e.hasRole(userMain, roleVerified2) {
		return fmt.Errorf("verified roles not applied: %v", e.memberRoles(userMain))
	}
	doc, _ = e.readState()
	if doc.Pending[userMain] != nil {
		return fmt.Errorf("superseded revoke op not replaced")
	}
	return nil
}

func scRepeatedRevocation(e *env) error {
	// Restoration stalls; repeated revocations remain idempotent.
	e.discAdmin("POST", "/_admin/fail", map[string]any{"path": "/roles/", "status": 500, "count": 0})
	for range 2 {
		status, respBody, err := e.postInteraction(revokeCommand(userMain, userAdmin, []string{roleAdmin}))
		if err != nil {
			return err
		}
		if status != 200 || !strings.Contains(respBody, "accepted") {
			return fmt.Errorf("ack: %d %s", status, respBody)
		}
	}
	doc, _ := e.readState()
	if doc.Epochs[userMain] != 2 {
		return fmt.Errorf("epoch after two revocations: %d", doc.Epochs[userMain])
	}
	if op := doc.Pending[userMain]; op == nil || op.Kind != "revoke" {
		return fmt.Errorf("no single outstanding revoke op: %+v", doc.Pending[userMain])
	}
	// Provider recovers; the restoration eventually applies.
	e.discAdmin("POST", "/_admin/clear-failures", nil)
	if err := pollState("repeated revocation restoration", 30*time.Second, func() bool {
		return e.hasRole(userMain, roleUnverif1) && e.hasRole(userMain, roleUnverif2) &&
			!e.hasRole(userMain, roleVerified1)
	}); err != nil {
		return err
	}
	// Honest done-vs-pending reporting: the follow-up said so.
	if _, ok := e.waitFollowup(1, ""); !ok {
		return fmt.Errorf("no follow-up delivered")
	}
	return expectBody(verifyUser(e, userMain, gIDWorkspace), "Verification complete")
}

func scPendingGrantRejoined(e *env) error {
	// A pending grant for a member who left and rejoined during downtime is
	// discarded rather than resumed.
	e.discAdmin("POST", "/_admin/fail", map[string]any{"path": "/roles/", "status": 500, "count": 0})
	body := verifyUser(e, userSecond, gIDOther)
	if err := expectBody(body, "in progress"); err != nil {
		return err
	}
	e.scaleApp(0)
	if err := pollAppScaled(e, 0); err != nil {
		return err
	}
	e.discAdmin("POST", "/_admin/kick", map[string]any{"user_id": userSecond, "guild_id": guildID})
	e.discAdmin("POST", "/_admin/member", map[string]any{
		"user_id": userSecond, "guild_id": guildID,
		"joined_at": time.Now().UTC().Format(time.RFC3339),
		"roles":     []string{roleUnverif1, roleUnverif2},
	})
	e.discAdmin("POST", "/_admin/clear-failures", nil)
	e.scaleApp(1)
	if err := e.waitReady(); err != nil {
		return err
	}
	if err := pollState("stale grant discarded", 30*time.Second, func() bool {
		doc, err := e.readState()
		if err != nil {
			return false
		}
		return doc.Pending[userSecond] == nil && doc.Members[userSecond] == nil
	}); err != nil {
		return err
	}
	if e.hasRole(userSecond, roleVerified1) {
		return fmt.Errorf("stale grant applied verified roles to rejoiner")
	}
	return nil
}

func scPolicyChange(e *env) error {
	// userMain is verified with example.com. The allowlist changes.
	if err := e.helmInstall(e.releaseDir, `"evil.io"`); err != nil {
		return err
	}
	if err := e.waitReady(); err != nil {
		return err
	}
	// A failed re-attempt disturbs nothing.
	body := verifyUser(e, userMain, gIDWorkspace)
	if err := expectBody(body, "approved organization"); err != nil {
		return err
	}
	m := e.stateMember(userMain)
	if m == nil || m.GoogleSub != gIDWorkspace.Sub {
		return fmt.Errorf("failed re-attempt disturbed the link")
	}
	if !e.hasRole(userMain, roleVerified1) {
		return fmt.Errorf("failed re-attempt disturbed roles")
	}
	// Restore the original allowlist.
	return e.helmInstall(e.releaseDir, "example.com")
}

func scHelmLifecycle(e *env) error {
	// userMain is verified; an upgrade must preserve state.
	if err := e.helmInstall(e.releaseDir, "example.com"); err != nil {
		return err
	}
	e.helm("upgrade", release, "charts/discord-google-sso", "--namespace", ns,
		"--reuse-values", "--set", "sessionTTL=11m", "--wait", "--timeout", "180s")
	if err := e.waitReady(); err != nil {
		return err
	}
	if m := e.stateMember(userMain); m == nil || m.GoogleSub != gIDWorkspace.Sub {
		return fmt.Errorf("helm upgrade lost the link")
	}
	if !e.hasRole(userMain, roleVerified1) {
		return fmt.Errorf("helm upgrade lost roles")
	}
	// Uninstall + reinstall in the retained namespace.
	e.helm("uninstall", release, "--namespace", ns)
	if err := e.helmInstall(e.releaseDir, "example.com"); err != nil {
		return fmt.Errorf("reinstall: %w", err)
	}
	if err := e.waitReady(); err != nil {
		return err
	}
	if m := e.stateMember(userMain); m == nil || m.GoogleSub != gIDWorkspace.Sub {
		return fmt.Errorf("uninstall/reinstall lost the link")
	}
	if !e.hasRole(userMain, roleVerified1) {
		return fmt.Errorf("uninstall/reinstall lost roles")
	}
	// The state Secret carries no workload owner reference.
	out := e.kubectl("get", "secret", stateSecret, "-o", "jsonpath={.metadata.ownerReferences}")
	if out != "" {
		return fmt.Errorf("state secret has owner references: %s", out)
	}
	// The member can still re-verify (idempotent re-assertion).
	return expectBody(verifyUser(e, userMain, gIDWorkspace), "Verification complete")
}

func scRbacProbe(e *env) error {
	sa := "system:serviceaccount:" + ns + ":" + release + "-discord-google-sso"
	checks := []struct {
		args []string
		want string
	}{
		{[]string{"get", "secret", stateSecret, "-n", ns, "--as", sa}, "yes"},
		{[]string{"create", "secret", "-n", ns, "--as", sa}, "yes"},
		{[]string{"get", "secret", "other-secret", "-n", ns, "--as", sa}, "no"},
		{[]string{"delete", "secret", stateSecret, "-n", ns, "--as", sa}, "no"},
	}
	for _, c := range checks {
		args := append([]string{"auth", "can-i"}, c.args...)
		args = append([]string{"--kubeconfig", e.kubeconfig}, args...)
		out := strings.TrimSpace(mustRun(e.releaseDir, "kubectl", args...))
		if out != c.want {
			return fmt.Errorf("kubectl auth can-i %v: got %q want %q", c.args, out, c.want)
		}
	}
	return nil
}

func scLogRedaction(e *env) error {
	secrets := e.collectIssuedSecrets()
	if len(secrets) == 0 {
		return fmt.Errorf("no provider secrets issued; test broken")
	}
	logs := e.appLogs()
	for _, s := range secrets {
		if s != "" && strings.Contains(logs, s) {
			return fmt.Errorf("log redaction failure: issued secret %s... appears in app logs", clip(s, 12))
		}
	}
	return nil
}
