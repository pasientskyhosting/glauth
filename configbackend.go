package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/GeertJohan/yubigo"
	"github.com/nmcclain/ldap"
	"github.com/pquerna/otp/totp"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	// BindSuccess - Successful bind attempt - used for logging
	BindSuccess = "success"
	// BindInvalid - Invalid bind attempt - used for logging
	BindInvalid = "invalid"
	// BindNotFound - User or group not found for bind attempt - used for logging
	BindNotFound = "notfound"
	// BindInvalidCredentials - User did not specify valid credentials
	BindInvalidCredentials = "invalidcredentials"
)

type configHandler struct {
	cfg         *config
	yubikeyAuth *yubigo.YubiAuth
}

func newConfigHandler(cfg *config, yubikeyAuth *yubigo.YubiAuth) Backend {
	handler := configHandler{
		cfg:         cfg,
		yubikeyAuth: yubikeyAuth}
	return handler
}

func (h configHandler) LogBindAttempt(userName string, result string) {
	if len(h.cfg.AuthLog) == 0 {
		return
	}

	f, err := os.OpenFile(h.cfg.AuthLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Warning(fmt.Sprintf("Could not open auth-log file %s for writing", h.cfg.AuthLog))
		return
	}
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf("%s|%s|%s\n", time.Now().Format(time.RFC3339), userName, result))
	if err != nil {
		log.Warning(fmt.Sprintf("Could not write auth-log entry to %s", h.cfg.AuthLog))
	}

	return
}

//
func (h configHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode ldap.LDAPResultCode, err error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.cfg.Backend.BaseDN)
	log.Debug(fmt.Sprintf("Bind request: bindDN: %s, BaseDN: %s, source: %s", bindDN, h.cfg.Backend.BaseDN, conn.RemoteAddr().String()))

	stats_frontend.Add("bind_reqs", 1)

	// parse the bindDN - ensure that the bindDN ends with the BaseDN
	if !strings.HasSuffix(bindDN, baseDN) {
		h.LogBindAttempt(bindDN, BindInvalid)
		log.Warning(fmt.Sprintf("Bind Error: BindDN %s not our BaseDN %s", bindDN, h.cfg.Backend.BaseDN))
		// log.Warning(fmt.Sprintf("Bind Error: BindDN %s not our BaseDN %s", bindDN, baseDN))
		return ldap.LDAPResultInvalidCredentials, nil
	}
	parts := strings.Split(strings.TrimSuffix(bindDN, baseDN), ",")
	groupName := ""
	userName := ""
	if len(parts) == 1 {
		userName = strings.TrimPrefix(parts[0], h.cfg.Backend.NameFormat+"=")
	} else if len(parts) == 2 {
		userName = strings.TrimPrefix(parts[0], h.cfg.Backend.NameFormat+"=")
		groupName = strings.TrimPrefix(parts[1], h.cfg.Backend.GroupFormat+"=")
	} else {
		h.LogBindAttempt(userName, BindInvalid)
		log.Warning(fmt.Sprintf("Bind Error: BindDN %s should have only one or two parts (has %d)", bindDN, len(parts)))
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// find the user
	user := configUser{}
	found := false
	for _, u := range h.cfg.Users {
		if u.Name == userName {
			found = true
			user = u
		}
	}
	if !found {
		h.LogBindAttempt(userName, BindNotFound)
		log.Warning(fmt.Sprintf("Bind Error: User %s not found.", userName))
		return ldap.LDAPResultInvalidCredentials, nil
	}
	// find the group
	group := configGroup{}
	found = false
	for _, g := range h.cfg.Groups {
		if g.Name == groupName {
			found = true
			group = g
		}
	}
	if !found {
		h.LogBindAttempt(user.Name, BindNotFound)
		log.Warning(fmt.Sprintf("Bind Error: Group %s not found.", groupName))
		return ldap.LDAPResultInvalidCredentials, nil
	}
	// validate group membership
	if user.PrimaryGroup != group.UnixID {
		h.LogBindAttempt(user.Name, BindInvalid)
		log.Warning(fmt.Sprintf("Bind Error: User %s primary group is not %s.", userName, groupName))
		return ldap.LDAPResultInvalidCredentials, nil
	}

	validotp := false

	if len(user.Yubikey) == 0 && len(user.OTPSecret) == 0 {
		validotp = true
	}

	if len(user.Yubikey) > 0 && h.yubikeyAuth != nil {
		if len(bindSimplePw) > 44 {
			otp := bindSimplePw[len(bindSimplePw)-44:]
			yubikeyid := otp[0:12]
			bindSimplePw = bindSimplePw[:len(bindSimplePw)-44]

			if user.Yubikey == yubikeyid {
				_, ok, _ := h.yubikeyAuth.Verify(otp)

				if ok {
					validotp = true
				}
			}
		}
	}

	// Store the full bind password provided before possibly modifying
	// in the otp check
	// Generate a hash of the provided password
	hashFull := sha256.New()
	hashFull.Write([]byte(bindSimplePw))

	// Test OTP if exists
	if len(user.OTPSecret) > 0 && !validotp {
		if len(bindSimplePw) > 6 {
			otp := bindSimplePw[len(bindSimplePw)-6:]
			bindSimplePw = bindSimplePw[:len(bindSimplePw)-6]

			validotp = totp.Validate(otp, user.OTPSecret)
		}
	}

	// finally, validate user's pw

	// check app passwords first
	for index, appPw := range user.PassAppSHA256 {

		if appPw != hex.EncodeToString(hashFull.Sum(nil)) {
			log.Debug(fmt.Sprintf("Attempted to bind app pw #%d - failure as %s from %s", index, bindDN, conn.RemoteAddr().String()))
		} else {
			stats_frontend.Add("BindSuccesses", 1)
			h.LogBindAttempt(user.Name, BindSuccess)
			log.Debug("Bind success using app pw #%d as %s from %s", index, bindDN, conn.RemoteAddr().String())
			return ldap.LDAPResultSuccess, nil
		}

	}

	// then check main password with the hash
	hash := sha256.New()
	hash.Write([]byte(bindSimplePw))

	// Then ensure the OTP is valid before checking
	if !validotp {
		h.LogBindAttempt(user.Name, BindInvalidCredentials)
		log.Warning(fmt.Sprintf("Bind Error: invalid OTP token as %s from %s", bindDN, conn.RemoteAddr().String()))
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// Now, check the hash
	if user.PassSHA256 != hex.EncodeToString(hash.Sum(nil)) {
		h.LogBindAttempt(user.Name, BindInvalidCredentials)
		log.Warning(fmt.Sprintf("Bind Error: invalid credentials as %s from %s", bindDN, conn.RemoteAddr().String()))
		return ldap.LDAPResultInvalidCredentials, nil
	}

	stats_frontend.Add("BindSuccesses", 1)
	log.Debug(fmt.Sprintf("Bind success as %s from %s", bindDN, conn.RemoteAddr().String()))
	h.LogBindAttempt(user.Name, BindSuccess)
	return ldap.LDAPResultSuccess, nil
}

//
func (h configHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.cfg.Backend.BaseDN)
	// searchBaseDN := strings.ToLower(searchReq.BaseDN)
	log.Debug(fmt.Sprintf("Search request as %s from %s for %s", bindDN, conn.RemoteAddr().String(), searchReq.Filter))
	stats_frontend.Add("search_reqs", 1)

	// validate the user is authenticated and has appropriate access
	if len(bindDN) < 1 {
		// close the connection - not doing so can cause weird client-side behavior (sssd will not react properly if connection is not closed)
		err := conn.Close()
		if err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInappropriateAuthentication}, err
		}

		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInappropriateAuthentication}, fmt.Errorf("Search Error: Anonymous BindDN not allowed %s", bindDN)
	}
	if !strings.HasSuffix(bindDN, baseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("Search Error: BindDN %s not in our BaseDN %s", bindDN, h.cfg.Backend.BaseDN)
	}
	// if !strings.HasSuffix(searchBaseDN, h.cfg.Backend.BaseDN) {
	// 	return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultNoSuchObject}, fmt.Errorf("Search Error: search BaseDN %s is not in our BaseDN %s", searchBaseDN, h.cfg.Backend.BaseDN)
	// }
	// return all users in the config file - the LDAP library will filter results for us
	entries := []*ldap.Entry{}
	filterEntity, err := ldap.GetFilterObjectClass(searchReq.Filter)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: error parsing filter: %s", searchReq.Filter)
	}
	switch filterEntity {
	default:
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: unhandled filter type: %s [%s]", filterEntity, searchReq.Filter)
	case "posixgroup":
		for _, g := range h.cfg.Groups {
			attrs := []*ldap.EntryAttribute{}
			attrs = append(attrs, &ldap.EntryAttribute{"cn", []string{g.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{"uid", []string{g.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{"description", []string{fmt.Sprintf("%s", g.Name)}})
			attrs = append(attrs, &ldap.EntryAttribute{"gidNumber", []string{fmt.Sprintf("%d", g.UnixID)}})
			attrs = append(attrs, &ldap.EntryAttribute{"objectClass", []string{"posixGroup"}})
			attrs = append(attrs, &ldap.EntryAttribute{"uniqueMember", h.getGroupMembers(g.UnixID)})
			attrs = append(attrs, &ldap.EntryAttribute{"memberUid", h.getGroupMemberIDs(g.UnixID)})
			dn := fmt.Sprintf("cn=%s,%s=groups,%s", g.Name, h.cfg.Backend.GroupFormat, h.cfg.Backend.BaseDN)
			entries = append(entries, &ldap.Entry{dn, attrs})
		}
	case "posixaccount", "":
		for _, u := range h.cfg.Users {
			attrs := []*ldap.EntryAttribute{}
			attrs = append(attrs, &ldap.EntryAttribute{"cn", []string{u.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{"uid", []string{u.Name}})

			if len(u.GivenName) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{"givenName", []string{u.GivenName}})
			}

			if len(u.SN) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{"sn", []string{u.SN}})
			}

			if len(u.GivenName) > 0 && len(u.SN) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{"displayName", []string{fmt.Sprintf("%s %s", u.GivenName, u.SN)}})
			} else if len(u.GivenName) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{"displayName", []string{fmt.Sprintf("%s", u.GivenName)}})
			} else if len(u.SN) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{"displayName", []string{fmt.Sprintf("%s", u.SN)}})
			}

			attrs = append(attrs, &ldap.EntryAttribute{"ou", []string{h.getGroupName(u.PrimaryGroup)}})
			attrs = append(attrs, &ldap.EntryAttribute{"uidNumber", []string{fmt.Sprintf("%d", u.UnixID)}})

			if u.Disabled {
				attrs = append(attrs, &ldap.EntryAttribute{"accountStatus", []string{"inactive"}})
			} else {
				attrs = append(attrs, &ldap.EntryAttribute{"accountStatus", []string{"active"}})
			}

			if len(u.Mail) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{"mail", []string{u.Mail}})
			}

			attrs = append(attrs, &ldap.EntryAttribute{"objectClass", []string{"posixAccount"}})

			if len(u.LoginShell) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{"loginShell", []string{u.LoginShell}})
			} else {
				attrs = append(attrs, &ldap.EntryAttribute{"loginShell", []string{"/bin/bash"}})
			}

			if len(u.Homedir) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{"homeDirectory", []string{u.Homedir}})
			} else {
				attrs = append(attrs, &ldap.EntryAttribute{"homeDirectory", []string{"/home/" + u.Name}})
			}

			attrs = append(attrs, &ldap.EntryAttribute{"description", []string{fmt.Sprintf("%s", u.Name)}})
			attrs = append(attrs, &ldap.EntryAttribute{"gecos", []string{fmt.Sprintf("%s", u.Name)}})
			attrs = append(attrs, &ldap.EntryAttribute{"gidNumber", []string{fmt.Sprintf("%d", u.PrimaryGroup)}})
			attrs = append(attrs, &ldap.EntryAttribute{"memberOf", h.getGroupDNs(u.UnixID, append(u.OtherGroups, u.PrimaryGroup))})
			if len(u.SSHKeys) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{h.cfg.Backend.SSHKeyAttr, u.SSHKeys})
			}
			dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.cfg.Backend.NameFormat, u.Name, h.cfg.Backend.GroupFormat, h.getGroupName(u.PrimaryGroup), h.cfg.Backend.BaseDN)
			entries = append(entries, &ldap.Entry{dn, attrs})
		}
	}
	stats_frontend.Add("search_successes", 1)
	log.Debug(fmt.Sprintf("AP: Search OK: %s", searchReq.Filter))
	return ldap.ServerSearchResult{entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

//
func (h configHandler) Close(boundDn string, conn net.Conn) error {
	stats_frontend.Add("closes", 1)
	return nil
}

func (h configHandler) userSatisfiesGroupRequirements(user configUser, groupId int) bool {
	return h.getGroupRequire2FA(groupId) == false || len(user.OTPSecret) > 0 || len(user.Yubikey) > 0
}

//
func (h configHandler) getGroupMembers(gid int) []string {
	members := make(map[string]bool)
	for _, u := range h.cfg.Users {
		if u.PrimaryGroup == gid {
			if h.userSatisfiesGroupRequirements(u, gid) {
				dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.cfg.Backend.NameFormat, u.Name, h.cfg.Backend.GroupFormat, h.getGroupName(u.PrimaryGroup), h.cfg.Backend.BaseDN)
				members[dn] = true
			} else {
				log.Debug("User %s not added as member of %d because no 2FA", u.Name, gid)
			}
		} else {
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					if h.userSatisfiesGroupRequirements(u, gid) {
						dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.cfg.Backend.NameFormat, u.Name, h.cfg.Backend.GroupFormat, h.getGroupName(u.PrimaryGroup), h.cfg.Backend.BaseDN)
						members[dn] = true
					} else {
						log.Debug("User %s not added as member of %d because no 2FA", u.Name, gid)
					}
				}
			}
		}
	}

	for _, g := range h.cfg.Groups {
		if gid == g.UnixID {
			for _, includegroupid := range g.IncludeGroups {
				if includegroupid != gid {
					includegroupmembers := h.getGroupMembers(includegroupid)

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

//
func (h configHandler) getGroupMemberIDs(gid int) []string {
	members := make(map[string]bool)
	for _, u := range h.cfg.Users {
		if u.PrimaryGroup == gid {
			if h.userSatisfiesGroupRequirements(u, gid) {
				members[u.Name] = true
			} else {
				log.Debug("User %s not added as member of %d because no 2FA", u.Name, gid)
			}
		} else {
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					if h.userSatisfiesGroupRequirements(u, gid) {
						members[u.Name] = true
					} else {
						log.Debug("User %s not added as member of %d because no 2FA", u.Name, gid)
					}
				}
			}
		}
	}

	for _, g := range h.cfg.Groups {
		if gid == g.UnixID {
			for _, includegroupid := range g.IncludeGroups {
				if includegroupid == gid {
					log.Warning(fmt.Sprintf("Group: %d - Ignoring myself as included group", includegroupid))
				} else {
					includegroupmemberids := h.getGroupMemberIDs(includegroupid)

					for _, includegroupmemberid := range includegroupmemberids {
						members[includegroupmemberid] = true
					}
				}
			}
		}
	}

	m := []string{}
	for k, _ := range members {
		m = append(m, k)
	}

	sort.Strings(m)

	return m
}

func (h configHandler) getGroups(gids []int) []configGroup {
	groups := []configGroup{}
	for _, gid := range gids {
		for _, g := range h.cfg.Groups {
			if g.UnixID == gid {
				groups = append(groups, g)
			}

			for _, includegroupid := range g.IncludeGroups {
				if includegroupid == gid && g.UnixID != gid {
					includegroups := h.getGroups([]int{g.UnixID})

					for _, includegroup := range includegroups {
						groups = append(groups, includegroup)
					}
				}
			}
		}
	}

	return groups
}

// Converts an array of GUIDs into an array of DNs
func (h configHandler) getGroupDNs(uid int, gids []int) []string {
	groups := make(map[string]bool)
	for _, gid := range gids {
		for _, g := range h.cfg.Groups {
			if g.UnixID == gid {
				if len(h.getUserYubikey(uid)) == 0 && len(h.getUserOTPSecret(uid)) == 0 && h.getGroupRequire2FA(gid) {
					log.Debug("User %s not added as member of %d because no 2FA", uid, gid)
				} else {
					dn := fmt.Sprintf("cn=%s,%s=groups,%s", g.Name, h.cfg.Backend.GroupFormat, h.cfg.Backend.BaseDN)
					groups[dn] = true
				}
			}

			for _, includegroupid := range g.IncludeGroups {
				if includegroupid == gid && g.UnixID != gid {
					includegroupdns := h.getGroupDNs(uid, []int{g.UnixID})

					for _, includegroupdn := range includegroupdns {
						groups[includegroupdn] = true
					}
				}
			}
		}
	}

	g := []string{}
	for k, _ := range groups {
		g = append(g, k)
	}

	sort.Strings(g)

	return g
}

func (h configHandler) getUserYubikey(uid int) string {
	for _, u := range h.cfg.Users {
		if u.UnixID == uid {
			return u.Yubikey
		}
	}

	return ""
}

func (h configHandler) getUserOTPSecret(uid int) string {
	for _, u := range h.cfg.Users {
		if u.UnixID == uid {
			return u.OTPSecret
		}
	}

	return ""
}

//
func (h configHandler) getGroupName(gid int) string {
	for _, g := range h.cfg.Groups {
		if g.UnixID == gid {
			return g.Name
		}
	}
	return ""
}

func (h configHandler) getGroupRequire2FA(gid int) bool {
	for _, g := range h.cfg.Groups {
		if g.UnixID == gid {
			return g.Require2FA
		}
	}

	return false
}
