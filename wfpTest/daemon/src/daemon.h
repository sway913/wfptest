// Copyright (c) 2020 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

#include "common.h"
#line HEADER_FILE("daemon.h")

#ifndef DAEMON_H
#define DAEMON_H
#pragma once

#include <vector>
#include <iostream>
#include <list>


class OriginalNetworkScan
{
public:
	OriginalNetworkScan() = default;    // Required by Q_DECLARE_METATYPE
	OriginalNetworkScan(const std::wstring &gatewayIp, const std::wstring &interfaceName,
		const std::wstring &ipAddress, const std::wstring &ipAddress6)
		: _gatewayIp{ gatewayIp }, _interfaceName{ interfaceName }, _ipAddress{ ipAddress },
		_ipAddress6{ ipAddress6 }
	{
	}

	bool operator==(const OriginalNetworkScan& rhs) const
	{
		return gatewayIp() == rhs.gatewayIp() &&
			interfaceName() == rhs.interfaceName() &&
			ipAddress() == rhs.ipAddress();
	}

	bool operator!=(const OriginalNetworkScan& rhs) const
	{
		return !(*this == rhs);
	}

	// Check whether the OriginalNetworkScan has valid (non-empty) values for
	// all fields.
	// Note that on Windows, we don't use the gatewayIp or interfaceName, these
	// are set to "N/A" which are considered valid.
	bool ipv4Valid() const { return !gatewayIp().empty() && !interfaceName().empty() && !ipAddress().empty(); }

	// Whether the host has IPv6 available (as a global IP)
	bool hasIpv6() const { return !ipAddress6().empty(); }

public:
	void gatewayIp(const std::wstring &value) { _gatewayIp = value; }
	void interfaceName(const std::wstring &value) { _interfaceName = value; }
	void ipAddress(const std::wstring &value) { _ipAddress = value; }
	void ipAddress6(const std::wstring &value) { _ipAddress6 = value; }

	const std::wstring &gatewayIp() const { return _gatewayIp; }
	const std::wstring &interfaceName() const { return _interfaceName; }
	const std::wstring &ipAddress() const { return _ipAddress; }
	const std::wstring &ipAddress6() const { return _ipAddress6; }

private:
	std::wstring _gatewayIp, _interfaceName, _ipAddress, _ipAddress6;
};


// Descriptor for a set of firewall rules to be appled.
//
struct FirewallParams
{
    // These parameters are specified by VPNConnection (some are passed through
    // from the VPNMethod)

    // DNS servers to permit through firewall - set once DNS has been applied
    // VPN network interface - see VPNMethod::getNetworkAdapter()
    // The following flags indicate which general rulesets are needed. Note that
    // this is after some sanity filtering, i.e. an allow rule may be listed
    // as not needed if there were no block rules preceding it. The rulesets
    // should be thought of as in last-match order.

    bool blockAll;      // Block all traffic by default
    bool allowVPN;      // Exempt traffic through VPN tunnel
    bool allowDHCP;     // Exempt DHCP traffic
    bool blockIPv6;     // Block all IPv6 traffic
    bool allowLAN;      // Exempt LAN traffic, including IPv6 LAN traffic
    bool blockDNS;      // Block all DNS traffic except specified DNS servers
    bool allowPIA;      // Exempt PIA executables
    bool allowLoopback; // Exempt loopback traffic
    bool allowHnsd;     // Exempt Handshake DNS traffic

    // Have we connected to the VPN since it was enabled?  (Some rules are only
    // activated once we successfully connect, but remain active even if we lose
    // the connection while reconnecting.)
    bool hasConnected;
    // When connected or connecting, whether the VPN is being used as the
    // default route.  ('true' when not connected.)
    bool defaultRoute;

	std::list<std::string> effectiveDnsServers;

    // Whether to enable split tunnel.  Split tunnel is enabled whenever the
    // setting is enabled, even if the PIA client is not logged in.  This is
    // important to block Only VPN apps - otherwise, they may leak even after
    // PIA is started/connected, because they could have existing connections
    // that were permitted.
    //
    // Bypass VPN apps though are only affected when we connect
    // - persistent connections from those apps would be
    // fine since they bypass the VPN anyway.
    //
    // On Mac, this causes the kext to be loaded, but on Windows the WFP callout
    // is not loaded until we connect (app blocks can be implemented in WFP
    // without loading the callout driver).
    bool enableSplitTunnel;
    // Original network information used (among other things) to manage apps for split
    // tunnel.
	OriginalNetworkScan netScan;
	std::vector<std::wstring> excludeApps; // Apps to exclude if VPN exemptions are enabled
	std::vector<std::wstring> vpnOnlyApps; // Apps to force on the VPN
};


// The main application class for the daemon, housing the main thread
// message loop and associated functionality.
//
class Daemon : public Singleton<Daemon>
{
public:
    explicit Daemon();
    ~Daemon();

    void reportError(Error error);

protected:
    virtual void applyFirewallRules(const FirewallParams& params) {}

public:
	virtual void start();
	virtual void queueApplyFirewallRules();

protected:
    // Check whether the daemon is currently active.  When this changes, we emit
    // firstClientConnected() or lastClientDisconnected().
    // Normally the daemon is active when any active client is connected, but it
    // can also remain active if an active client exits unexpectedly
    // (DaemonState::invalidClientExit).
    bool isActive() const;
	

private:
    void reapplyFirewallRules();
	void checkSplitTunnelSupport();

protected:
    bool _started, _stopping;

    unsigned int _pendingSerializations;
};

#define g_daemon (Daemon::instance())

#define g_account (g_daemon->account())
#define g_data (g_daemon->data())
#define g_settings (g_daemon->settings())
#define g_state (g_daemon->state())

#endif // DAEMON_H
