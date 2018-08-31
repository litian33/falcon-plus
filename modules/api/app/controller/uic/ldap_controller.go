package uic

import (
	"crypto/tls"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/open-falcon/falcon-plus/modules/api/app/model/uic"
	"github.com/spf13/viper"
	"gopkg.in/ldap.v2"
)

func LdapLogin(userInfo *APILoginInput) (*uic.User,error) {
	// The username and password we want to check
	username := userInfo.Name
	password := userInfo.Password

	bindusername := viper.GetString("ldap.binds.bind_dn")
	bindpassword := viper.GetString("ldap.binds.bind_passwd")

	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", viper.GetString("ldap.server.host"), viper.GetInt("ldap.server.port")))
	if err != nil {
		log.Error(err)
		return nil, err
	}
	defer l.Close()

	// Reconnect with TLS
	if viper.GetBool("ldap.server.use_ssl") {
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: viper.GetBool("ldap.server.ssl_skip_verify")})
		if err != nil {
			log.Error(err)
			return nil, err
		}
	}

	// First bind with a read only user
	err = l.Bind(bindusername, bindpassword)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		viper.GetString("ldap.binds.search_base_dn"),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(viper.GetString("ldap.binds.search_filter"), username),
		viper.GetStringSlice("ldap.attributes.remote"),
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	if len(sr.Entries) != 1 {
		log.Error("User does not exist or too many entries returned")
		return nil, errors.New("Ldap user does not exist or too many entries returned")
	}

	userdn := sr.Entries[0].DN

	// Bind as the user to verify their password
	err = l.Bind(userdn, password)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	rattrs := viper.GetStringSlice("ldap.attributes.remote")
	lattrs := viper.GetStringSlice("ldap.attributes.local")
	size := len(rattrs)
	names := make(map[string]string)
	for i := 0; i < size; i++ {
		names[rattrs[i]] = lattrs[i]
	}

	user := uic.User{}
	user.Name = username
	for _, v := range sr.Entries[0].Attributes {
		if v.Values == nil && len(v.Values) == 0 {
			continue
		}
		if data, ok := names[v.Name]; ok {
			switch data {
			case "surname":
				user.Cnname = v.Values[0]
			case "email":
				user.Email = v.Values[0]
			}
		}
	}

	return &user, nil
}
