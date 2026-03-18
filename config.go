package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level runtime configuration structure.
type Config struct {
	Listen     string
	Port       int
	TLSCert    string
	TLSKey     string
	GlobalAuth *Auth
	Routes     map[string]*RouteConfig
}

// Auth holds HTTP Basic Auth credentials.
type Auth struct {
	User     string
	Password string
}

// RouteConfig describes a single reverse-proxy route.
type RouteConfig struct {
	Dest         string
	NoTLSVerify  bool
	Auth         *Auth  // nil = inherit global-auth; explicitly cleared = no auth
	AuthExplicit bool   // true when auth was set explicitly (even as empty)
	Timeout       string            // e.g. "30s", "2m"
	AddHeaders    map[string]string  // headers to add/overwrite on upstream request
	DeleteHeaders    []string           // headers to remove from upstream request
	DeleteHasWildcard bool              // true if any DeleteHeaders entry contains '*'
}

func (c *Config) validate() error {
	if len(c.Routes) == 0 {
		return fmt.Errorf("no routes configured")
	}
	for path, r := range c.Routes {
		if r.Dest == "" {
			return fmt.Errorf("route %q has no dest", path)
		}
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("both tls-cert and tls-key must be provided together")
	}
	return nil
}

// ---- YAML file types ----
// These mirror the config.yml structure exactly and are only used during loading.

type fileConfig struct {
	Global fileGlobal           `yaml:"global"`
	Routes map[string]fileRoute `yaml:"routes"`
}

type fileGlobal struct {
	Listen     string   `yaml:"listen"`
	Port       int      `yaml:"port"`
	TLSCert    string   `yaml:"tls-cert"`
	TLSKey     string   `yaml:"tls-key"`
	GlobalAuth []string `yaml:"global-auth"` // ["USER", "PASSWORD"]
}

type fileRoute struct {
	Dest        string   `yaml:"dest"`
	NoTLSVerify bool     `yaml:"noTLSverify"`
	Auth        []string `yaml:"auth"`    // ["USER", "PASSWORD"] or absent
	Timeout      string            `yaml:"timeout"`
	AddHeaders    map[string]string  `yaml:"add-header"`
	DeleteHeaders []string           `yaml:"delete-header"`

	// authPresent records whether the "auth" key existed in the YAML at all.
	authPresent bool
}

// UnmarshalYAML implements yaml.Unmarshaler so we can detect whether the
// "auth" key was present in the document (even when its value is empty/null).
func (r *fileRoute) UnmarshalYAML(value *yaml.Node) error {
	// Alias type prevents infinite recursion when calling Decode.
	type plain fileRoute
	var tmp plain
	if err := value.Decode(&tmp); err != nil {
		return err
	}
	*r = fileRoute(tmp)

	// Walk the mapping node's key-value pairs to detect "auth" key presence.
	if value.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(value.Content); i += 2 {
			if value.Content[i].Value == "auth" {
				r.authPresent = true
				break
			}
		}
	}
	return nil
}

// loadConfigFile reads a config.yml file and returns a Config.
func loadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parsing %q: %w", path, err)
	}

	cfg := &Config{
		Listen:  fc.Global.Listen,
		Port:    fc.Global.Port,
		TLSCert: fc.Global.TLSCert,
		TLSKey:  fc.Global.TLSKey,
		Routes:  make(map[string]*RouteConfig, len(fc.Routes)),
	}
	if cfg.Port == 0 {
		cfg.Port = 8080
	}

	if len(fc.Global.GlobalAuth) == 2 {
		cfg.GlobalAuth = &Auth{
			User:     fc.Global.GlobalAuth[0],
			Password: fc.Global.GlobalAuth[1],
		}
	} else if len(fc.Global.GlobalAuth) != 0 {
		return nil, fmt.Errorf("global-auth must be a two-element list [USER, PASSWORD]")
	}

	for path, fr := range fc.Routes {
		rc := &RouteConfig{
			Dest:          fr.Dest,
			NoTLSVerify:   fr.NoTLSVerify,
			Timeout:       fr.Timeout,
			AuthExplicit:  fr.authPresent,
			AddHeaders:       fr.AddHeaders,
			DeleteHeaders:    fr.DeleteHeaders,
			DeleteHasWildcard: hasWildcard(fr.DeleteHeaders),
		}
		if fr.authPresent {
			if len(fr.Auth) == 2 {
				rc.Auth = &Auth{User: fr.Auth[0], Password: fr.Auth[1]}
			} else if len(fr.Auth) != 0 {
				return nil, fmt.Errorf("route %q: auth must be a two-element list [USER, PASSWORD]", path)
			}
			// len == 0 with authPresent means explicit no-auth; rc.Auth stays nil
		}
		cfg.Routes[path] = rc
	}

	return cfg, nil
}
