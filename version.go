package main

// Build information - can be overridden during build with ldflags
var (
	// Application branding
	AppName      = "DiskOver"
	AppAuthor    = "Robin DUBREUIL"
	AppCopyright = "Copyright (c) 2025"
	AppLicense   = "GPLv3"
	
	// Version information
	Version   = "MAIN"
	BuildTime = "development"
	GitCommit = "unknown"
	BuildUser = "unknown"
	BuildHost = "unknown"
)

// GetVersionInfo returns formatted version information
func GetVersionInfo() map[string]string {
	return map[string]string{
		"name":       AppName,
		"version":    Version,
		"author":     AppAuthor,
		"copyright":  AppCopyright,
		"license":    AppLicense,
		"build_time": BuildTime,
		"git_commit": GitCommit,
		"build_user": BuildUser,
		"build_host": BuildHost,
	}
}

// GetVersionString returns a formatted version string
func GetVersionString() string {
	return AppName + " v" + Version
}