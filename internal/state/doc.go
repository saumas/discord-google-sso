// Package state defines the durable state document persisted in the
// application-owned Kubernetes Secret and its invariants.
package state

import (
	"fmt"
	"time"
)

// SchemaVersion is the current state document schema version. The loader
// refuses documents carrying any other version.
const SchemaVersion = 1

// DataKey is the Secret data field holding the gzipped state document.
const DataKey = "state.json.gz"

// OpKind enumerates pending role operation kinds.
type OpKind string

const (
	// OpGrant is a pending verification grant: add AddRoles, remove
	// RemoveRoles, attesting membership as of MemberJoinedAt.
	OpGrant OpKind = "grant"
	// OpRevoke is a pending revocation: remove RemoveRoles and re-add the
	// configured unverified role set.
	OpRevoke OpKind = "revoke"
)

// Member is a stored identity link: one Google identity ↔ one Discord user.
type Member struct {
	GoogleSub    string    `json:"googleSub"`
	GoogleName   string    `json:"googleName"`
	GoogleEmail  string    `json:"googleEmail"`
	JoinedAt     time.Time `json:"joinedAt"` // membership attestation observed at verification time
	AppliedRoles []string  `json:"appliedRoles"`
}

// PendingOp is a durably recorded role operation that has not fully applied
// yet. It is persisted before any Discord side effect and resumed by the
// reconciler after crashes.
type PendingOp struct {
	Kind          OpKind   `json:"kind"`
	OpID          string   `json:"opID"`
	Epoch         uint64   `json:"epoch"`                   // revocation epoch the operation was created under
	AddRoles      []string `json:"addRoles,omitempty"`      // grant: intended additions (configured adds plus any fold-ins)
	RemoveRoles   []string `json:"removeRoles,omitempty"`   // grant: configured removals; revoke: removal set
	AddedSoFar    []string `json:"addedSoFar,omitempty"`    // grant progress: roles successfully added
	RestoredSoFar []string `json:"restoredSoFar,omitempty"` // revoke progress: unverified roles re-added
	// MemberJoinedAt is the membership attestation captured when the grant
	// was persisted. Resumption re-validates it.
	MemberJoinedAt time.Time `json:"memberJoinedAt,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
}

// Doc is the full state document.
type Doc struct {
	SchemaVersion int                   `json:"schemaVersion"`
	GuildID       string                `json:"guildID"`
	Members       map[string]*Member    `json:"members"` // key: Discord user ID
	Epochs        map[string]uint64     `json:"epochs"`  // per-user revocation epochs; retained after link release
	Pending       map[string]*PendingOp `json:"pending"` // key: Discord user ID
}

// NewDoc returns an empty state document for the given guild.
func NewDoc(guildID string) *Doc {
	return &Doc{
		SchemaVersion: SchemaVersion,
		GuildID:       guildID,
		Members:       map[string]*Member{},
		Epochs:        map[string]uint64{},
		Pending:       map[string]*PendingOp{},
	}
}

// Validate checks document integrity: schema version, guild ownership, and
// the 1:1 identity-link invariant (one Google sub ↔ one Discord user).
func (d *Doc) Validate(guildID string) error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported state schema version %d (want %d)", d.SchemaVersion, SchemaVersion)
	}
	if d.GuildID == "" {
		return fmt.Errorf("state document has no guild ID")
	}
	if d.GuildID != guildID {
		return fmt.Errorf("state document belongs to guild %s, not configured guild %s", d.GuildID, guildID)
	}
	if d.Members == nil {
		return fmt.Errorf("state document has no members map")
	}
	seenSub := map[string]string{}
	for memberID, m := range d.Members {
		if memberID == "" || m == nil || m.GoogleSub == "" {
			return fmt.Errorf("corrupt member entry for %q", memberID)
		}
		if other, ok := seenSub[m.GoogleSub]; ok {
			return fmt.Errorf("identity link invariant violated: google sub linked to both %s and %s", other, memberID)
		}
		seenSub[m.GoogleSub] = memberID
	}
	return nil
}

// FindMemberBySub returns the Discord user ID linked to the given Google sub,
// or "" if none.
func (d *Doc) FindMemberBySub(sub string) string {
	for id, m := range d.Members {
		if m.GoogleSub == sub {
			return id
		}
	}
	return ""
}

// Epoch returns the current revocation epoch for a member (0 if unset).
func (d *Doc) Epoch(memberID string) uint64 {
	return d.Epochs[memberID]
}

// ApplyRevokeCommit performs the atomic revocation state commit on the
// document: bump the per-user revocation epoch, release the identity link,
// and replace the member's pending operation with a durable revocation
// operation whose removal set is the union of a superseded grant's intended
// additions and its additions-so-far, or the completed link's retained
// applied role IDs. A never-linked or already-released target with no
// outstanding revocation gets an epoch bump only. It returns whether a
// revocation operation is now outstanding for the target.
func (d *Doc) ApplyRevokeCommit(memberID, opID string, now time.Time) bool {
	epoch := d.Epochs[memberID] + 1
	d.Epochs[memberID] = epoch
	defer delete(d.Members, memberID)

	op := d.Pending[memberID]
	switch {
	case op != nil && op.Kind == OpGrant:
		d.Pending[memberID] = &PendingOp{
			Kind:        OpRevoke,
			OpID:        opID,
			Epoch:       epoch,
			RemoveRoles: UnionStrings(op.AddRoles, op.AddedSoFar),
			CreatedAt:   now,
		}
		return true
	case op != nil && op.Kind == OpRevoke:
		// An outstanding revocation stays in place to complete; repeated
		// revocations are idempotent.
		return true
	case d.Members[memberID] != nil:
		d.Pending[memberID] = &PendingOp{
			Kind:        OpRevoke,
			OpID:        opID,
			Epoch:       epoch,
			RemoveRoles: append([]string(nil), d.Members[memberID].AppliedRoles...),
			CreatedAt:   now,
		}
		return true
	default:
		// Never-linked or already-released: epoch bump only, no role step.
		delete(d.Pending, memberID)
		return false
	}
}

// UnionStrings returns the ordered union of the given slices.
func UnionStrings(slices ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range slices {
		for _, v := range s {
			if v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}
