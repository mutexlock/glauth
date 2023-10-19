package handler

import (
	"fmt"
	"github.com/glauth/glauth/v2/pkg/stats"
	"github.com/nmcclain/ldap"
	"regexp"
	"sort"
	"strings"
)

func (l LDAPOpsHelper) topLevelTenantNode(tenant, searchBaseDN string) *ldap.Entry {
	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{tenant}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"organizationalUnit", "top"}})
	dn := searchBaseDN
	if !strings.HasPrefix(dn, fmt.Sprintf("ou=%s", tenant)) {
		dn = fmt.Sprintf("ou=%s,%s", tenant, dn)
	}
	return &ldap.Entry{DN: dn, Attributes: attrs}
}

func (l LDAPOpsHelper) topLevelTenantsNode(h LDAPOpsHandler, searchBaseDN string) []*ldap.Entry {
	entries := []*ldap.Entry{}

	for _, u := range h.GetCfg().Tenants {
		attrs := []*ldap.EntryAttribute{}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{u.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"organizationalUnit", "top"}})
		dn := fmt.Sprintf("ou=%s,%s", u.Name, searchBaseDN)
		//if !strings.HasPrefix(dn, "ou=tenant1,") {
		//	dn = fmt.Sprintf("ou=tenant1,%s", dn)
		//}
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}

	return entries
}

func (l LDAPOpsHelper) topLevelTenantGroupsNode(searchBaseDN string, hierarchy string) *ldap.Entry {
	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{"groups"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"organizationalUnit", "top"}})
	hierarchyStringPrefix := fmt.Sprintf("ou=%s,", hierarchy)
	dn := searchBaseDN
	if !strings.HasPrefix(dn, hierarchyStringPrefix) {
		dn = fmt.Sprintf("%s%s", hierarchyStringPrefix, dn)
	}
	return &ldap.Entry{DN: dn, Attributes: attrs}
}

func (l LDAPOpsHelper) topLevelTenantUsersNode(searchBaseDN string) *ldap.Entry {
	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{"users"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"organizationalUnit", "top"}})
	dn := searchBaseDN
	if !strings.HasPrefix(dn, "ou=users,") {
		dn = fmt.Sprintf("ou=users,%s", dn)
	}
	return &ldap.Entry{DN: dn, Attributes: attrs}
}

func (l LDAPOpsHelper) topLevelTenantSyncerUsersNode(h LDAPOpsHandler, tenant string, searchBaseDN string) *ldap.Entry {
	for _, u := range h.GetCfg().Users {
		if u.Tenant == tenant && u.Syncer {
			attrs := []*ldap.EntryAttribute{}
			attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{u.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"users"}})
			dn := searchBaseDN
			if !strings.HasPrefix(dn, fmt.Sprintf("cn=%s,", u.Name)) {
				dn = fmt.Sprintf("cn=%s,%s", u.Name, dn)
			}
			return &ldap.Entry{DN: dn, Attributes: attrs}
		}
	}
	return nil
}

// ou=tenant2,dc=glauth,dc=com
func (l LDAPOpsHelper) searchMaybeTenantLevelNodes(h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	searchTenant, tenant := checkSearchTenant(baseDN, searchBaseDN)
	if !searchTenant {
		return nil, ldap.LDAPResultOther // OK
	}

	h.GetLog().Info().Str("special case", "top-level browse").Msg("Search request")
	entries := []*ldap.Entry{}
	if searchReq.Scope == ldap.ScopeBaseObject || searchReq.Scope == ldap.ScopeWholeSubtree {
		entries = append(entries, l.topLevelTenantNode(tenant, searchBaseDN))
	}
	entries = append(entries, l.topLevelTenantGroupsNode(searchBaseDN, "groups"))
	entries = append(entries, l.topLevelTenantUsersNode(searchBaseDN))
	entries = append(entries, l.topLevelTenantSyncerUsersNode(h, tenant, searchBaseDN))

	if searchReq.Scope == ldap.ScopeWholeSubtree {
		groupentries, err := h.FindPosixGroups(fmt.Sprintf("ou=groups,ou=%s", tenant))
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, groupentries...)

		userentries, err := h.FindPosixAccounts(fmt.Sprintf("ou=users,ou=%s", tenant))
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, userentries...)
	}
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().Info().Str("filter", searchReq.Filter).Msg("AP: Top-Level Browse OK")
	return entries, ldap.LDAPResultSuccess
}

func (h configHandler) FindTenantPosixGroups(tenant, hierarchy string) (entrylist []*ldap.Entry, err error) {
	//asGroupOfUniqueNames := hierarchy == "ou=groups"
	//
	entries := []*ldap.Entry{}

	for _, g := range h.cfg.Groups {
		if g.Tenant != tenant {
			continue
		}
		attrs := []*ldap.EntryAttribute{}
		attrs = append(attrs, &ldap.EntryAttribute{Name: h.backend.GroupFormat, Values: []string{g.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{g.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{g.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s", g.Name)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", g.GIDNumber)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uniqueMember", Values: h.getTenantGroupMemberDNs(tenant, g.GIDNumber)})
		//if asGroupOfUniqueNames {
		//	attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"groupOfUniqueNames", "top"}})
		//} else {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: h.getGroupMemberIDs(g.GIDNumber)})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup", "top"}})
		//}
		dn := fmt.Sprintf("%s=%s,%s,%s", h.backend.GroupFormat, g.Name, hierarchy, h.backend.BaseDN)
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}

	return entries, nil
}

func checkSearchTenant(baseDN string, searchBaseDN string) (bool, string) {
	pattern := fmt.Sprintf(`^ou=(\w+),%s$`, baseDN)
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(searchBaseDN)

	if len(match) >= 2 {
		return true, match[1]
	}

	return false, ""
}

// ou=group3, ou=groups,ou=tenant2
// ou=groups,ou=tenant2
// ou=tenant2
// ""
func getTenantGroupByHierarchy(hierarchy string) (tenant string, group string) {

	pattern := `ou=(\w+),ou=groups,ou=(\w+)$`
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(hierarchy)
	if len(match) >= 3 {
		return match[2], match[1]
	}

	pattern = `^ou=groups,ou=(\w+)$`
	re = regexp.MustCompile(pattern)
	match = re.FindStringSubmatch(hierarchy)
	if len(match) >= 2 {
		return match[1], ""
	}

	pattern1 := `^ou=(\w+)$`
	re1 := regexp.MustCompile(pattern1)
	match = re1.FindStringSubmatch(hierarchy)
	if len(match) >= 2 {
		return match[1], ""
	}
	return "", ""
}

// ou=user1, ou=users,ou=tenant2
// ou=users,ou=tenant2
// ou=tenant2
// ""
func getTenantUserByHierarchy(hierarchy string) (tenant string, user string) {
	pattern := `cn=(\w+),ou=users,ou=(\w+)$`
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(hierarchy)
	if len(match) >= 3 {
		return match[2], match[1]
	}

	pattern = `^ou=users,ou=(\w+)$`
	re = regexp.MustCompile(pattern)
	match = re.FindStringSubmatch(hierarchy)
	if len(match) >= 2 {
		return match[1], ""
	}

	pattern1 := `^ou=(\w+)$`
	re1 := regexp.MustCompile(pattern1)
	match = re1.FindStringSubmatch(hierarchy)
	if len(match) >= 2 {
		return match[1], ""
	}
	return "", ""
}

func checkSearchTenantByGroups(baseDN string, searchBaseDN string) (bool, string) {
	pattern := fmt.Sprintf(`^ou=groups,ou=(\w+),%s$`, baseDN)
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(searchBaseDN)

	if len(match) >= 2 {
		return true, match[1]
	}

	return false, ""
}

func checkSearchTenantSyncer(baseDN string, searchBaseDN string) (string, string) {
	pattern := fmt.Sprintf(`^cn=(\w+),ou=(\w+),%s$`, baseDN)
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(searchBaseDN)

	if len(match) >= 3 {
		return match[1], match[2]
	}

	return "", ""
}

func checkSearchTenantByUsers(baseDN string, searchBaseDN string) (bool, string) {
	pattern := fmt.Sprintf(`^ou=users,ou=(\w+),%s$`, baseDN)
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(searchBaseDN)

	if len(match) >= 2 {
		return true, match[1]
	}

	return false, ""
}

// cn=tenant_syncer,ou=tenant2,dc=glauth,dc=com
func (l LDAPOpsHelper) searchMaybeTenantLevelSyncer(h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	syncer, tenant := checkSearchTenantSyncer(baseDN, searchBaseDN)
	if syncer == "" && tenant == "" {
		return nil, ldap.LDAPResultOther // OK
	}

	entries := []*ldap.Entry{}

	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{syncer}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"users"}})
	dn := searchBaseDN
	if !strings.HasPrefix(dn, fmt.Sprintf("cn=%s,", syncer)) {
		dn = fmt.Sprintf("cn=%s,%s", syncer, dn)
	}

	entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})

	stats.Frontend.Add("search_successes", 1)
	h.GetLog().Info().Str("filter", searchReq.Filter).Msg("AP: Top-Level Users Browse OK")
	return entries, ldap.LDAPResultSuccess
}

// ou=groups,ou=tenant2,dc=glauth,dc=com
func (l LDAPOpsHelper) searchMaybeTopTenantLevelGroupsNode(h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	search, tenant := checkSearchTenantByGroups(baseDN, searchBaseDN)
	if !search {
		return nil, ldap.LDAPResultOther // OK
	}

	fmt.Println(tenant)
	h.GetLog().Info().Str("special case", "top-level groups node").Msg("Search request")
	entries := []*ldap.Entry{}
	if searchReq.Scope == ldap.ScopeBaseObject || searchReq.Scope == ldap.ScopeWholeSubtree {
		entries = append(entries, l.topLevelTenantGroupsNode(searchBaseDN, "groups"))
	}
	if searchReq.Scope == ldap.ScopeSingleLevel || searchReq.Scope == ldap.ScopeWholeSubtree {
		groupentries, err := h.FindPosixGroups(fmt.Sprintf("ou=groups,ou=%s", tenant))
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, groupentries...)
	}
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().Info().Str("filter", searchReq.Filter).Msg("AP: Top-Level Groups Browse OK")
	return entries, ldap.LDAPResultSuccess
}

// ou=users,ou=tenant2,dc=glauth,dc=com
func (l LDAPOpsHelper) searchMaybeTopTenantLevelUsersNode(h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	search, tenant := checkSearchTenantByUsers(baseDN, searchBaseDN)
	if !search {
		return nil, ldap.LDAPResultOther // OK
	}

	hierarchy := ""
	bits := strings.Split(strings.Replace(searchBaseDN, baseDN, "", 1), ",")
	if len(bits) != 3 {
		return nil, ldap.LDAPResultOther // OK
	}
	hierarchy = fmt.Sprintf("%s,%s", bits[0], bits[1])

	fmt.Println(tenant)
	h.GetLog().Info().Str("special case", "top-level users node").Msg("Search request")
	entries := []*ldap.Entry{}
	if searchReq.Scope == ldap.ScopeBaseObject || searchReq.Scope == ldap.ScopeWholeSubtree {
		entries = append(entries, l.topLevelTenantUsersNode(searchBaseDN))
	}
	if searchReq.Scope == ldap.ScopeSingleLevel || searchReq.Scope == ldap.ScopeWholeSubtree {
		userentries, err := h.FindPosixAccounts(hierarchy)
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, userentries...)
	}
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().Info().Str("filter", searchReq.Filter).Msg("AP: Top-Level Users Browse OK")
	return entries, ldap.LDAPResultSuccess
}

func (h configHandler) getTenantGroupMemberDNs(tenant string, gid int) []string {
	members := make(map[string]bool)
	for _, u := range h.cfg.Users {
		if u.PrimaryGroup == gid {
			dn := fmt.Sprintf("%s=%s,%s=%s,ou=%s,%s", h.backend.NameFormat, u.Name, h.backend.GroupFormat, h.getTenantGroupName(tenant, u.PrimaryGroup), tenant, h.backend.BaseDN)
			members[dn] = true
		} else {
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					dn := fmt.Sprintf("%s=%s,%s=%s,ou=%s,%s", h.backend.NameFormat, u.Name, h.backend.GroupFormat, h.getTenantGroupName(tenant, u.PrimaryGroup), tenant, h.backend.BaseDN)
					members[dn] = true
				}
			}
		}
	}

	for _, g := range h.cfg.Groups {
		if gid == g.GIDNumber {
			for _, includegroupid := range g.IncludeGroups {
				if includegroupid != gid {
					includegroupmembers := h.getTenantGroupMemberDNs(tenant, includegroupid)

					for _, includegroupmember := range includegroupmembers {
						members[includegroupmember] = true
					}
				}
			}
		}
	}

	m := []string{}
	for k := range members {
		m = append(m, k)
	}

	sort.Strings(m)

	return m
}

func (h configHandler) getTenantGroupName(tenant string, gid int) string {
	for _, g := range h.cfg.Groups {
		if g.Tenant != tenant {
			continue
		}
		if g.GIDNumber == gid {
			return g.Name
		}
	}
	return ""
}

func (h configHandler) getTenantGroupMemberIDs(tenant string, gid int) []string {
	members := make(map[string]bool)
	for _, u := range h.cfg.Users {
		if u.Tenant != tenant {
			continue
		}
		if u.PrimaryGroup == gid {
			members[u.Name] = true
		} else {
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					members[u.Name] = true
				}
			}
		}
	}

	for _, g := range h.cfg.Groups {
		if g.Tenant != tenant {
			continue
		}
		if gid == g.GIDNumber {
			for _, includegroupid := range g.IncludeGroups {
				if includegroupid == gid {
					h.log.Warn().Int("groupid", includegroupid).Msg("Ignoring myself as included group")
				} else {
					includegroupmemberids := h.getTenantGroupMemberIDs(tenant, includegroupid)

					for _, includegroupmemberid := range includegroupmemberids {
						members[includegroupmemberid] = true
					}
				}
			}
		}
	}

	m := []string{}
	for k := range members {
		m = append(m, k)
	}

	sort.Strings(m)

	return m
}

// Converts an array of GUIDs into an array of DNs
func (h configHandler) getTenantGroupDNs(tenant string, gids []int) []string {
	groups := make(map[string]bool)
	for _, gid := range gids {
		for _, g := range h.cfg.Groups {
			if g.Tenant != tenant {
				continue
			}
			if g.GIDNumber == gid {
				dn := fmt.Sprintf("%s=%s,ou=groups,ou=%s,%s", h.backend.GroupFormat, g.Name, tenant, h.backend.BaseDN)
				groups[dn] = true
			}

			for _, includegroupid := range g.IncludeGroups {
				if includegroupid == gid && g.GIDNumber != gid {
					includegroupdns := h.getTenantGroupDNs(tenant, []int{g.GIDNumber})

					for _, includegroupdn := range includegroupdns {
						groups[includegroupdn] = true
					}
				}
			}
		}
	}

	g := []string{}
	for k := range groups {
		g = append(g, k)
	}

	sort.Strings(g)

	return g
}
