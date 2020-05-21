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
#line SOURCE_FILE("daemon.cpp")

#include "daemon.h"

#include "version.h"
#include "brand.h"
#include "builtin/util.h"

#if defined(Q_OS_WIN)
#include <Windows.h>
#include <VersionHelpers.h>
#include "win/win_util.h"
#include <AclAPI.h>
#include <AccCtrl.h>
#pragma comment(lib, "advapi32.lib")
#endif


Daemon::Daemon()
    : _started(false)
    , _stopping(false)
    , _pendingSerializations(0)
{
   

    // Check whether the host supports split tunnel and record errors.
    // This function will also attempt to create the net_cls VFS on Linux if it doesn't exist.
    checkSplitTunnelSupport();
	/*queueApplyFirewallRules();*/
}

Daemon::~Daemon()
{
    //qInfo() << "Daemon shutdown complete";
}

void Daemon::reportError(Error error)
{
	std::cout << "reportError" << std::endl;
}



bool Daemon::isActive() const
{
	return false;
}

void Daemon::start()
{
	_started = true;
}

void Daemon::queueApplyFirewallRules() {
	reapplyFirewallRules();
}

void Daemon::reapplyFirewallRules()
{
    FirewallParams params {};


    bool killswitchEnabled = false;

    // For OpenVPN, split tunnel is available, and does not require a reconnect
    // to toggle.  However, for WireGuard, split tunnel is not currently
    // available at all.
    //
    // Check the connected/connecting method if we're currently connected or
    // connecting; otherwise use the chosen method.
    bool allowSplitTunnel = true;

    // Enable the split tunnel when:
    // - It's "allowed" (supported by the connection method)
    // - It's enabled by the user
    if(allowSplitTunnel)
    {
        params.enableSplitTunnel = true;
    }

    // For convenience we expose the netScan in params.
    // This way we can use it in code that takes a FirewallParams argument
    // - such as the split tunnel code
    params.netScan = {
                       L"",
					   L"",
					   L"",
					   L""
                     };

    params.excludeApps.reserve(1);
    params.vpnOnlyApps.reserve(0);
	params.excludeApps.push_back(L"C:\\Users\\ztz\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\360安全浏览器\\360安全浏览器.lnk");
    // Though split tunnel in general can be toggled while connected,
    // defaultRoute can't.  The user can toggle split tunnel as long as the
    // effective value for defaultRoute doesn't change.  If it does, we'll still
    // update split tunnel, but the default route change will require a
    // reconnect.
    params.defaultRoute = true;

    // When not using the VPN as the default route, force Handshake into the
    // VPN with an "include" rule.  (Just routing the Handshake seeds into the
    // VPN is not sufficient; hnsd uses a local recursive DNS resolver that will
    // query authoritative DNS servers, and we want that to go through the VPN.)

	params.blockAll = false;
	params.allowVPN = true;
    params.blockIPv6 = false;
	params.allowLAN = true;
    // Block DNS when:
    // - not using Existing DNS
    // - the VPN connection is enabled, and
    // - we've connected at least once since the VPN was enabled
    params.blockDNS = false;
    params.allowPIA = false;
    params.allowHnsd = false;

 /*   qInfo() << "Reapplying firewall rules;"
            << "state:" << qEnumToString(_connection->state())
            << "clients:" << _clients.size()
            << "loggedIn:" << _account.loggedIn()
            << "killswitch:" << _settings.killswitch()
            << "vpnEnabled:" << _state.vpnEnabled()
            << "blockIPv6:" << _settings.blockIPv6()
            << "allowLAN:" << _settings.allowLAN()
            << "dnsType:" << (pConnSettings ? pConnSettings->dnsType() : QStringLiteral("N/A"))
            << "dnsServers:" << params.effectiveDnsServers;*/

    applyFirewallRules(params);
}

// Check whether the host supports split tunnel and record errors
// This function will also attempt to create the net_cls VFS on Linux if it doesn't exist
void Daemon::checkSplitTunnelSupport()
{
    std::string errors;

#if defined(Q_OS_WIN)
    // WFP has serious issues in Windows 7 RTM.  Though we still support the
    // client on Win 7 RTM, the split tunnel feature requires SP1 or newer.
    //
    // Some of the issues:
    // https://support.microsoft.com/en-us/help/981889/a-windows-filtering-platform-wfp-driver-hotfix-rollup-package-is-avail
    if(!::IsWindows7SP1OrGreater()) {
        errors = "win_version_invalid";
    }
#endif
}
