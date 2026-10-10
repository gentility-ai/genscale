// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !gokrazy

package dns

const (
	resolvConf = "/etc/resolv.conf"
	backupConf = "/etc/resolv.pre-gentility-backup.conf" // genscale: see GENSCALE.md
)
