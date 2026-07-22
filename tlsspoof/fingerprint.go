package main

import (
	"strings"

	utls "github.com/refraction-networking/utls"
)

type FingerprintConfig struct {
	Chrome  string
	Firefox string
	Safari  string
	IOS     string
	Edge    string
}

func pickFingerprint(ua string, cfg FingerprintConfig) utls.ClientHelloID {
	ua = strings.ToLower(ua)
	var auto utls.ClientHelloID
	var pinned string

	switch {
	case strings.Contains(ua, "firefox"):
		auto = utls.HelloFirefox_Auto
		pinned = cfg.Firefox
	case strings.Contains(ua, "edg/"):
		auto = utls.HelloEdge_Auto
		pinned = cfg.Edge
	case strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome"):
		auto = utls.HelloSafari_Auto
		pinned = cfg.Safari
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		auto = utls.HelloIOS_Auto
		pinned = cfg.IOS
	case strings.Contains(ua, "chrome"):
		auto = utls.HelloChrome_Auto
		pinned = cfg.Chrome
	default:
		auto = utls.HelloChrome_Auto
		pinned = cfg.Chrome
	}

	if pinned != "" && pinned != "auto" {
		return utls.ClientHelloID{Client: auto.Client, Version: pinned}
	}
	return auto
}
