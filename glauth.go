package main

import (
	"expvar"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/GeertJohan/yubigo"
	"github.com/docopt/docopt-go"
	"github.com/fsnotify/fsnotify"
	"github.com/jinzhu/copier"
	"github.com/nmcclain/ldap"
	"github.com/op/go-logging"
	"gopkg.in/amz.v1/aws"
	"gopkg.in/amz.v1/s3"
	"os"
	"strings"
)

// Set with buildtime vars
var LastGitTag string
var BuildTime string
var GitCommit string
var GitClean string
var GitBranch string
var GitTagIsCommit string

const programName = "glauth"

var usage = `glauth: securely expose your LDAP for external auth

Usage:
  glauth [options] -c <file|s3url>
  glauth -h --help
  glauth --version

Options:
  -c, --config <file>       Config file.
  -K <aws_key_id>           AWS Key ID.
  -S <aws_secret_key>       AWS Secret Key.
  -r <aws_region>           AWS Region [default: us-east-1].
  -h, --help                Show this screen.
  --version                 Show version.
`

var (
	log      *logging.Logger
	args     map[string]interface{}
	stderr   *logging.LogBackend
	yubiAuth *yubigo.YubiAuth
	// exposed expvar variables
	// TODO: Should be renamed according to golang naming conventions for exported vars, StatsFrontend, StatsBackend, StatsGeneral
	stats_frontend = expvar.NewMap("proxy_frontend")
	stats_backend  = expvar.NewMap("proxy_backend")
	stats_general  = expvar.NewMap("proxy")

	activeConfig = &config{}
)

// interface for backend handler
type Backend interface {
	ldap.Binder
	ldap.Searcher
	ldap.Closer
}

// config file
type configBackend struct {
	BaseDN      string
	Datastore   string
	Insecure    bool     // For LDAP backend only
	Servers     []string // For LDAP backend only
	NameFormat  string
	GroupFormat string
	SSHKeyAttr  string
}
type configFrontend struct {
	AllowedBaseDNs []string // For LDAP backend only
	Listen         string
	Cert           string
	Key            string
	TLS            bool
}
type configLDAP struct {
	Enabled bool
	Listen  string
}
type configLDAPS struct {
	Enabled bool
	Listen  string
	Cert    string
	Key     string
}
type configAPI struct {
	Cert        string
	Enabled     bool
	Key         string
	Listen      string
	SecretToken string
	TLS         bool
}
type configUser struct {
	Name          string
	OtherGroups   []int
	PassSHA256    string
	PassAppSHA256 []string
	PrimaryGroup  int
	SSHKeys       []string
	OTPSecret     string
	Yubikey       []string
	Disabled      bool
	UnixID        int
	Mail          string
	LoginShell    string
	GivenName     string
	SN            string
	Homedir       string
}
type configGroup struct {
	Name          string
	UnixID        int
	IncludeGroups []int
}
type config struct {
	API                configAPI
	Backend            configBackend
	Debug              bool
	WatchConfig        bool
	YubikeyClientID    string
	YubikeySecret      string
	Frontend           configFrontend
	LDAP               configLDAP
	LDAPS              configLDAPS
	Groups             []configGroup
	Syslog             bool
	Users              []configUser
	ConfigFile         string
	AwsAccessKeyId     string
	AwsSecretAccessKey string
	AwsRegion          string
}

// Reads builtime vars and returns a full string containing info about
// the currently running version of the software. Primarily used by the
// --version flag at runtime.
func getVersionString() string {

	var versionstr string

	versionstr = "GLauth"

	// Notate the git context of the build
	switch {
	// If a release, use the tag
	case GitClean == "1" && GitTagIsCommit == "1":
		versionstr += " " + LastGitTag + "\n\n"

	// If this branch had a tag before, mention the branch and the tag to give a rough idea of the base version
	case len(GitBranch) > 1 && len(LastGitTag) > 1:
		versionstr += "\nNon-release build from branch " + GitBranch + ", based on tag " + LastGitTag + "\n\n"

	// If no previous tag specified, just mention the branch
	case len(GitBranch) > 1:
		versionstr += "\nNon-release build from branch " + GitBranch + "\n\n"

	// Fallback message, if all else fails
	default:
		versionstr += "\nNon-release build\n\n"
	}

	// Include build time
	if len(BuildTime) > 1 {
		versionstr += "Build time: " + BuildTime + "\n"
	}

	// Add commit hash
	if GitClean == "1" && len(GitCommit) > 1 {
		versionstr += "Commit: " + GitCommit + "\n"
	}

	return versionstr

}

func main() {
	stderr = initLogging()
	log.Debug("AP start")

	if err := parseArgs(); err != nil {
		log.Fatalf("Could not parse command-line arguments", err.Error())
	}
	if err := doConfig(); err != nil {
		log.Fatalf("Configuration file error: %s", err.Error())
	}

	startService()
}

func startService() {
	// stats
	stats_general.Set("version", stringer(LastGitTag))

	// web API
	if activeConfig.API.Enabled {
		log.Debug("Web API enabled")
		go RunAPI(activeConfig)
	}

	startConfigWatcher()

	// configure the backend
	s := ldap.NewServer()
	s.EnforceLDAP = true
	var handler Backend
	switch activeConfig.Backend.Datastore {
	case "ldap":
		handler = newLdapHandler(activeConfig)
	case "config":
		handler = newConfigHandler(activeConfig, yubiAuth)
	default:
		log.Fatalf("Unsupported backend %s - must be 'config' or 'ldap'.", activeConfig.Backend.Datastore)
	}
	log.Notice(fmt.Sprintf("Using %s backend", activeConfig.Backend.Datastore))
	s.BindFunc("", handler)
	s.SearchFunc("", handler)
	s.CloseFunc("", handler)

	if activeConfig.LDAP.Enabled {
		// Dont block if also starting a LDAPS server afterwards
		shouldBlock := !activeConfig.LDAPS.Enabled

		if shouldBlock {
			startLDAP(&activeConfig.LDAP, s)
		} else {
			go startLDAP(&activeConfig.LDAP, s)
		}
	}

	if activeConfig.LDAPS.Enabled {
		// Always block here
		startLDAPS(&activeConfig.LDAPS, s)
	}

	log.Critical("AP exit")
}

func startConfigWatcher() {
	configFileLocation := getConfigLocation()

	if strings.HasPrefix(configFileLocation, "s3://") {
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("Could not start config-watcher: %s", err.Error())
	}

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if activeConfig.WatchConfig {
					if event.Op.String() == "WRITE" {
						if err := doConfig(); err != nil {
							log.Warningf("Could not reload config: %sHolding on to old config", err.Error())
						} else {
							log.Notice("Config was reloaded")
						}
					}
				}
			case err := <-watcher.Errors:
				if activeConfig.WatchConfig {
					log.Info("Error!", err)
				}
			}
		}
	}()

	watcher.Add(configFileLocation)
}

func startLDAP(ldapConfig *configLDAP, server *ldap.Server) {
	log.Notice(fmt.Sprintf("LDAP server listening on %s", ldapConfig.Listen))
	if err := server.ListenAndServe(ldapConfig.Listen); err != nil {
		log.Fatalf("LDAP Server Failed: %s", err.Error())
	}
}

func startLDAPS(ldapsConfig *configLDAPS, server *ldap.Server) {
	log.Notice(fmt.Sprintf("LDAPS server listening on %s", ldapsConfig.Listen))
	if err := server.ListenAndServeTLS(ldapsConfig.Listen, ldapsConfig.Cert, ldapsConfig.Key); err != nil {
		log.Fatalf("LDAP Server Failed: %s", err.Error())
	}
}

func parseArgs() error {
	var err error

	if args, err = docopt.Parse(usage, nil, true, getVersionString(), false); err != nil {
		return err
	}

	return nil
}

func getConfigLocation() string {
	return args["--config"].(string)
}

func parseConfigFile(configFileLocation string) (*config, error) {
	cfg := config{}
	// setup defaults
	cfg.LDAP.Enabled = false
	cfg.LDAPS.Enabled = true
	cfg.Backend.NameFormat = "cn"
	cfg.Backend.GroupFormat = "ou"
	cfg.Backend.SSHKeyAttr = "sshPublicKey"

	// parse the config file
	if strings.HasPrefix(configFileLocation, "s3://") {
		if _, present := aws.Regions[args["-r"].(string)]; present == false {
			return &cfg, fmt.Errorf("Invalid AWS region: %s", args["-r"])
		}
		region := aws.Regions[args["-r"].(string)]
		auth, err := aws.EnvAuth()
		if err != nil {
			if args["-K"] == nil || args["-S"] == nil {
				return &cfg, fmt.Errorf("AWS credentials not found: must use -K and -S flags, or set these env vars:\n\texport AWS_ACCESS_KEY_ID=\"AAA...\"\n\texport AWS_SECRET_ACCESS_KEY=\"BBBB...\"\n")
			}
			auth = aws.Auth{
				AccessKey: args["-K"].(string),
				SecretKey: args["-S"].(string),
			}
		}
		// parse S3 url
		s3url := strings.TrimPrefix(configFileLocation, "s3://")
		parts := strings.SplitN(s3url, "/", 2)
		if len(parts) != 2 {
			return &cfg, fmt.Errorf("Invalid S3 URL: %s", s3url)
		}
		b := s3.New(auth, region).Bucket(parts[0])
		tomlData, err := b.Get(parts[1])
		if err != nil {
			return &cfg, err
		}
		if _, err := toml.Decode(string(tomlData), &cfg); err != nil {
			return &cfg, err
		}
	} else { // local config file
		if _, err := toml.DecodeFile(configFileLocation, &cfg); err != nil {
			return &cfg, err
		}
	}

	return &cfg, nil
}

func handleConfig(cfg config) (*config, error) {
	if len(cfg.Frontend.Listen) > 0 && (len(cfg.LDAP.Listen) > 0 || len(cfg.LDAPS.Listen) > 0) {
		// Both old server-config and new - dont allow
		return &cfg, fmt.Errorf("Both old and new server-config in use - please remove old format ([frontend]) and migrate to new format ([ldap], [ldaps])")
	}

	if len(cfg.Frontend.Listen) > 0 {
		// We're going with old format - parse it into new
		log.Warning("Config [frontend] is deprecated - please move to [ldap] and [ldaps] as-per documentation")

		cfg.LDAP.Enabled = !cfg.Frontend.TLS
		cfg.LDAPS.Enabled = cfg.Frontend.TLS

		if cfg.Frontend.TLS {
			cfg.LDAPS.Listen = cfg.Frontend.Listen
		} else {
			cfg.LDAP.Listen = cfg.Frontend.Listen
		}

		if len(cfg.Frontend.Cert) > 0 {
			cfg.LDAPS.Cert = cfg.Frontend.Cert
		}
		if len(cfg.Frontend.Key) > 0 {
			cfg.LDAPS.Key = cfg.Frontend.Key
		}
	}

	if !cfg.LDAP.Enabled && !cfg.LDAPS.Enabled {
		return &cfg, fmt.Errorf("No server configuration found: please provide either LDAP or LDAPS configuration")
	}

	if cfg.LDAPS.Enabled {
		// LDAPS enabled - verify requirements (cert, key, listen)
		if len(cfg.LDAPS.Cert) == 0 || len(cfg.LDAPS.Key) == 0 {
			return &cfg, fmt.Errorf("LDAPS was enabled but no certificate or key were specified: please disable LDAPS or use the 'cert' and 'key' options")
		}

		if len(cfg.LDAPS.Listen) == 0 {
			return &cfg, fmt.Errorf("No LDAPS bind address was specified: please disable LDAPS or use the 'listen' option")
		}
	}

	if cfg.LDAP.Enabled {
		// LDAP enabled - verify listen
		if len(cfg.LDAP.Listen) == 0 {
			return &cfg, fmt.Errorf("No LDAP bind address was specified: please disable LDAP or use the 'listen' option")
		}
	}

	switch cfg.Backend.Datastore {
	case "":
		cfg.Backend.Datastore = "config"
	case "config":
	case "ldap":
	default:
		return &cfg, fmt.Errorf("Invalid backend %s - must be 'config' or 'ldap'", cfg.Backend.Datastore)
	}
	return &cfg, nil
}

// doConfig reads the cli flags and config file
func doConfig() error {
	// Parse config-file into config{} struct
	cfg, err := parseConfigFile(getConfigLocation())
	if err != nil {
		return err
	}

	// Handle validation and parsing of old [frontend] section into [ldap] and/or [ldaps] sections
	cfg, err = handleConfig(*cfg)
	if err != nil {
		return err
	}

	// Before greenlighting new config entirely, lets make sure the yubiauth works - in case they changed
	if activeConfig.YubikeyClientID != cfg.YubikeyClientID || activeConfig.YubikeySecret != cfg.YubikeySecret {
		if len(cfg.YubikeyClientID) > 0 && len(cfg.YubikeySecret) > 0 {
			_yubiAuth, err := yubigo.NewYubiAuth(cfg.YubikeyClientID, cfg.YubikeySecret)
			if err != nil {
				return err
			}

			// No errors, override
			yubiAuth = _yubiAuth
		}
	}

	// All config is validated and alright, copy to ativeConfig
	if err := copier.Copy(activeConfig, cfg); err != nil {
		return err
	}

	// Handle logging settings for new config
	// - we do this last to make sure we only respect a fully validated config
	stderr = initLogging()

	if activeConfig.Debug {
		logging.SetLevel(logging.DEBUG, programName)
		log.Debug("Debugging enabled")
	}
	if activeConfig.Syslog {
		enableSyslog(stderr)
	}

	return nil
}

// initLogging sets up logging to stderr
func initLogging() *logging.LogBackend {
	log = logging.MustGetLogger(programName)

	format := "%{color}%{time:15:04:05.000000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}"
	logBackend := logging.NewLogBackend(os.Stderr, "", 0)

	logging.SetBackend(logBackend)
	logging.SetLevel(logging.NOTICE, programName)
	logging.SetFormatter(logging.MustStringFormatter(format))
	return logBackend
}

// enableSyslog turns on syslog and turns off color
func enableSyslog(stderrBackend *logging.LogBackend) {
	format := "%{time:15:04:05.000000} %{shortfunc} ▶ %{level:.4s} %{id:03x} %{message}"
	logging.SetFormatter(logging.MustStringFormatter(format))
	syslogBackend, err := logging.NewSyslogBackend("")
	if err != nil {
		log.Fatal(err)
	}

	logging.SetBackend(stderrBackend, syslogBackend)

	log.Debug("Syslog enabled")
}
