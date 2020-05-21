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
#line SOURCE_FILE("win/win_daemon.cpp")

#include "win_daemon.h"
#include "win.h"
#include <set>


// The 'bind' callout GUID is the GUID used in 1.7 and earlier; the WFP callout
// only handled the bind layer in those releases.
GUID PIA_WFP_CALLOUT_BIND_V4 = {0xb16b0a6e, 0x2b2a, 0x41a3, { 0x8b, 0x39, 0xbd, 0x3f, 0xfc, 0x85, 0x5f, 0xf8 } };
GUID PIA_WFP_CALLOUT_CONNECT_V4 = { 0xb80ca14a, 0xa807, 0x4ef2, { 0x87, 0x2d, 0x4b, 0x1a, 0x51, 0x82, 0x54, 0x2 } };

WinUnbiasedDeadline::WinUnbiasedDeadline()
    : _expireTime{getUnbiasedTime()} // Initially expired
{
}

ULONGLONG WinUnbiasedDeadline::getUnbiasedTime() const
{
    ULONGLONG time;
    // Per doc, this can only fail if the pointer given is nullptr, which it's
    // not.
    ::QueryUnbiasedInterruptTime(&time);
    return time;
}

void WinUnbiasedDeadline::setRemainingTime(const std::chrono::microseconds &time)
{
    _expireTime = getUnbiasedTime();
    if(time > std::chrono::microseconds::zero())
    {
        // The unbiased interrupt time is in 100ns units, multiply by 10.
        _expireTime += static_cast<unsigned long long>(time.count()) * 10;
    }
}

std::chrono::microseconds WinUnbiasedDeadline::remaining() const
{
    ULONGLONG now = getUnbiasedTime();
    if(now >= _expireTime)
        return {};
    return std::chrono::microseconds{(_expireTime - now) / 10};
}

WinDaemon::WinDaemon()
    : Daemon{}
    , MessageWnd(WindowType::Invisible)
    , _firewall(new FirewallEngine())
    , _lastConnected{false}
{
	_filters = FirewallFilters{};
	_filterAdapterLuid = 0;

	if (!_firewall->open() || !_firewall->installProvider())
	{
		//qCritical() << "Unable to initialize WFP firewall";
		delete _firewall;
		_firewall = nullptr;
	}
	else
	{
		_firewall->removeAll();
	}


}

WinDaemon::~WinDaemon()
{
	if (_firewall)
	{
		// qInfo() << "Cleaning up WFP objects";
		_firewall->removeAll();
		_firewall->uninstallProvider();
		//_firewall->checkLeakedObjects();
	}
}

    //qInfo() << "WinDaemon shutdown complete";


void WinDaemon::checkNetworkAdapter()
{
    // To check the network adapter state, just call getNetworkAdapter() and let
    // it update DaemonState.  Ignore the result and any exception for a missing
    // adapter.
    try
    {
        //getNetworkAdapter();
    }
    catch(const Error &)
    {
        // Ignored, indicates no adapter.
    }
}

void WinDaemon::onAboutToConnect()
{
    // Reapply split tunnel rules.  If an app updates, the executables found
    // from the rules might change (likely for UWP apps because the package
    // install paths are versioned, less likely for native apps but possible if
    // the link target changes).
    //
    // If this does happen, this means the user may have to reconnect for the
    // updated rules to apply, but this is much better than restarting the
    // service or having to make a change to the rules just to force this
    // update.
    //_appMonitor.setSplitTunnelRules(_settings.splitTunnelRules());

    // If the WFP callout driver is installed but not loaded yet, load it now.
    // The driver is loaded this way for resiliency:
    // - Loading on boot would mean that a failure in the callout driver would
    //   render the system unbootable (bluescreen on boot)
    // - Loading on first client connect would prevent the user from seeing an
    //   advertised update or installing it
    //
    // This may slow down the first connection attempt slightly, but the driver
    // does not take long to load and the resiliency gains are worth this
    // tradeoff.

    // Do a manual check of the callout state right now if needed
    //_wfpCalloutMonitor.doManualCheck();

    // Skip this quickly if the driver isn't installed to avoid holding up
    // connections (don't open SCM or the service an additional time).
    // TODO - Also check master toggle for split tunnel
    //if(_wfpCalloutMonitor.lastState() == DaemonState::NetExtensionState::NotInstalled)
    //{
    //    qInfo() << "Callout driver hasn't been installed, nothing to start.";
    //    return;
    //}

    //qInfo() << "Starting callout driver";
    //auto startResult = startCalloutDriver(10000);
    //switch(startResult)
    //{
    //    case ServiceStatus::ServiceNotInstalled:
    //        // Normally the check above should detect this.
    //        qWarning() << "Callout driver is not installed, but monitor is in state"
    //            << qEnumToString(_wfpCalloutMonitor.lastState());
    //        break;
    //    case ServiceStatus::ServiceAlreadyStarted:
    //        qInfo() << "Callout driver is already running";
    //        break;
    //    case ServiceStatus::ServiceStarted:
    //        qInfo() << "Callout driver was started successfully";
    //        break;
    //    case ServiceStatus::ServiceRebootNeeded:
    //        // TODO - Display this in the client UI
    //        qWarning() << "Callout driver requires system reboot";
    //        break;
    //    default:
    //        qWarning() << "Callout driver couldn't be started:" << startResult;
    //        break;
    //}
}



LRESULT WinDaemon::proc(UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_POWERBROADCAST:
        switch(wParam)
        {
        case PBT_APMRESUMEAUTOMATIC:
        case PBT_APMSUSPEND:
            // After the system resumes, allow 1 minute for the TAP adapter to
            // come back.
            //
            // This isn't perfectly reliable since it's a hard-coded timeout,
            // but there is no way to know at this point whether the TAP adapter
            // is really missing or if it's still coming back from the resume.
            // PBT_APMRESUMEAUTOMATIC typically occurs before the TAP adapter is
            // restored.  PBM_APMRESUMESUSPEND _seems_ to typically occur after
            // it is restored, but the doc indicates that this isn't sent in all
            // cases, we can't rely on it.
            //
            // This just suppresses the "TAP adapter missing" error, so the
            // failure modes are acceptable:
            // - if the adapter is really missing, we take 1 minute to actually
            //   show the error
            // - if the adapter is present but takes >1 minute to come back, we
            //   show the error incorrectly in the interim
            //
            // We also trigger the grace period for a suspend message, just in
            // case a connection attempt would occur between the suspend message
            // and the resume message.
            _resumeGracePeriod.setRemainingTime(std::chrono::minutes{1});
            checkNetworkAdapter();  // Check now in case we were showing the error already
            //qInfo() << "OS suspend/resume:" << wParam;
            break;
        default:
            break;
        }
        return 0;

    default:
        return MessageWnd::proc(uMsg, wParam, lParam);
    }
}


static void logFilter(const char* filterName, int currentState, bool enableCondition, bool invalidateCondition = false)
{
	if (enableCondition ? currentState != 1 || invalidateCondition : currentState != 0)
		printf("%s: %s -> %s \n", filterName, currentState == 1 ? "ON" : currentState == 0 ? "OFF" : "MIXED", enableCondition ? "ON" : "OFF");
	else
		printf("%s: %s  \n", filterName, enableCondition ? "ON" : "OFF");
}

static void logFilter(const char* filterName, const GUID& filterVariable, bool enableCondition, bool invalidateCondition = false)
{
	logFilter(filterName, filterVariable == zeroGuid ? 0 : 1, enableCondition, invalidateCondition);
}

template<class FilterObjType, size_t N>
static void logFilter(const char* filterName, const FilterObjType(&filterVariables)[N], bool enableCondition, bool invalidateCondition = false)
{
	int state = filterVariables[0] == zeroGuid ? 0 : 1;
	for (size_t i = 1; i < N; i++)
	{
		int s = filterVariables[i] == zeroGuid ? 0 : 1;
		if (s != state)
		{
			state = 2;
			break;
		}
	}
	logFilter(filterName, state, enableCondition, invalidateCondition);
}


void WinDaemon::applyFirewallRules(const FirewallParams& params)
{
    if (!_firewall)
        return;
	std::string dns = "";
	std::list<std::string> dnsServers; // default-constructed if missing
	dnsServers.push_back(dns);
	dnsServers.push_back(dns);

	FirewallTransaction tx(_firewall);

#define deactivateFilter(filterVariable, removeCondition) \
    do { \
        /* Remove existing rule if necessary */ \
        if ((removeCondition) && filterVariable != zeroGuid) \
        { \
            if (!_firewall->remove(filterVariable)) { \
                std::cout << "Failed to remove WFP filter:" << #filterVariable << std::endl; \
            } \
            filterVariable = {zeroGuid}; \
        } \
    } \
    while(false)
#define activateFilter(filterVariable, addCondition, ...) \
    do { \
        /* Add new rule if necessary */ \
        if ((addCondition) && filterVariable == zeroGuid) \
        { \
            if ((filterVariable = _firewall->add(__VA_ARGS__)) == zeroGuid) { \
                reportError(Error(Error::FirewallRuleFailed, "")); \
            } \
        } \
    } \
    while(false)
#define updateFilter(filterVariable, removeCondition, addCondition, ...) \
    do { \
        deactivateFilter(_filters.filterVariable, removeCondition); \
        activateFilter(_filters.filterVariable, addCondition, __VA_ARGS__); \
    } while(false)
#define updateBooleanFilter(filterVariable, enableCondition, ...) \
    do { \
        const bool enable = (enableCondition); \
        updateFilter(filterVariable, !enable, enable, __VA_ARGS__); \
    } while(false)
#define updateBooleanInvalidateFilter(filterVariable, enableCondition, invalidateCondition, ...) \
    do { \
        const bool enable = (enableCondition); \
        const bool disable = !enable || (invalidateCondition); \
        updateFilter(filterVariable, disable, enable, __VA_ARGS__); \
    } while(false)
#define filterActive(filterVariable) (_filters.filterVariable != zeroGuid)


	//updateBooleanFilter(blockAll[0], params.blockAll, EverythingFilter<FWP_ACTION_BLOCK, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(0));

	// Firewall rules, listed in order of ascending priority (as if the last
	// matching rule applies, but note that it is the priority argument that
	// actually determines precedence).

	// As a bit of an exception to the normal firewall rule logic, the WFP
	// rules handle the blockIPv6 rule by changing the priority of the IPv6
	// part of the killswitch rule instead of having a dedicated IPv6 block.

	// Block all other traffic when killswitch is enabled. If blockIPv6 is
	// true, block IPv6 regardless of killswitch state.
	logFilter("blockAll(IPv4)", _filters.blockAll[0], params.blockAll);
	WfpFilterObject fobj = _filters.blockAll[0];
	updateBooleanFilter(blockAll[0], params.blockAll, EverythingFilter<FWP_ACTION_BLOCK, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(0));
	logFilter("blockAll(IPv6)", _filters.blockAll[1], params.blockAll || params.blockIPv6);
	updateBooleanFilter(blockAll[1], params.blockAll || params.blockIPv6, EverythingFilter<FWP_ACTION_BLOCK, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V6>(params.blockIPv6 ? 4 : 0));

	// Exempt traffic going over the VPN adapter.  This is the TAP adapter for
	// OpenVPN, or the WinTUN adapter for Wireguard.
	UINT64 luid = 0;
	logFilter("allowVPN", _filters.permitAdapter, luid && params.allowVPN, luid != _filterAdapterLuid);
	updateBooleanInvalidateFilter(permitAdapter[0], luid && params.allowVPN, luid != _filterAdapterLuid, InterfaceFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(luid, 2));
	updateBooleanInvalidateFilter(permitAdapter[1], luid && params.allowVPN, luid != _filterAdapterLuid, InterfaceFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V6>(luid, 2));
	//_filterAdapterLuid = luid;

	// Note: This is where the IPv6 block rule is ordered if blockIPv6 is true.

   // Exempt DHCP traffic.
	logFilter("allowDHCP", _filters.permitDHCP, params.allowDHCP);
	updateBooleanFilter(permitDHCP[0], params.allowDHCP, DHCPFilter<FWP_ACTION_PERMIT, FWP_IP_VERSION_V4>(6));
	updateBooleanFilter(permitDHCP[1], params.allowDHCP, DHCPFilter<FWP_ACTION_PERMIT, FWP_IP_VERSION_V6>(6));

	// Permit LAN traffic depending on settings
	logFilter("allowLAN", _filters.permitLAN, params.allowLAN);
	updateBooleanFilter(permitLAN[0], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>("192.168.0.0/16", 8));
	updateBooleanFilter(permitLAN[1], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>("172.16.0.0/12", 8));
	updateBooleanFilter(permitLAN[2], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>("10.0.0.0/8", 8));
	updateBooleanFilter(permitLAN[3], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>("224.0.0.0/4", 8));
	updateBooleanFilter(permitLAN[4], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>("169.254.0.0/16", 8));
	updateBooleanFilter(permitLAN[5], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>("255.255.255.255/32", 8));
	updateBooleanFilter(permitLAN[6], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V6>("fc00::/7", 8));
	updateBooleanFilter(permitLAN[7], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V6>("fe80::/10", 8));
	updateBooleanFilter(permitLAN[8], params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V6>("ff00::/8", 8));

	// Permit the IPv6 global Network Prefix - this allows on-link IPv6 hosts to communicate using their global IPs
	// which is more common in practice than link-local
	updateBooleanFilter(permitLAN[9], params.netScan.hasIpv6() && params.allowLAN, IPSubnetFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V6>("0/64", 8));
	// First 64 bits of a global IPv6 IP is the Network Prefix.

	// Add rules to block non-PIA DNS servers if connected and DNS leak protection is enabled
	logFilter("blockDNS", _filters.blockDNS, params.blockDNS);
	updateBooleanFilter(blockDNS[0], params.blockDNS, DNSFilter<FWP_ACTION_BLOCK, FWP_IP_VERSION_V4>(10));
	updateBooleanFilter(blockDNS[1], params.blockDNS, DNSFilter<FWP_ACTION_BLOCK, FWP_IP_VERSION_V6>(10));
	logFilter("allowDNS(1)", _filters.permitDNS[0], 0, 0);
	const std::string testAddr = "";
	updateBooleanInvalidateFilter(permitDNS[0], 0, 0, IPAddressFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(testAddr, 14));

	logFilter("allowDNS(2)", _filters.permitDNS[1], 0, 0);
	updateBooleanInvalidateFilter(permitDNS[1], 0, 0, IPAddressFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(testAddr, 14));

	// Always permit traffic from known applications.
	logFilter("allowPIA", _filters.permitPIA, params.allowPIA);
	std::wstring exePath = L"D:\\work\\qihoo\\wfpTest\\x64\\Debug\\wfpTest.exe";
	updateBooleanFilter(permitPIA[0], params.allowPIA, ApplicationFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(exePath, 15));


	// Always permit loopback traffic, including IPv6.
	logFilter("allowLoopback", _filters.permitLocalhost, params.allowLoopback);
	updateBooleanFilter(permitLocalhost[0], params.allowLoopback, LocalhostFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4>(15));
	updateBooleanFilter(permitLocalhost[1], params.allowLoopback, LocalhostFilter<FWP_ACTION_PERMIT, FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V6>(15));

	// Get the current set of excluded app IDs.  If they've changed we recreate
	// all app rules, but if they stay the same we don't recreate them.
	std::set<const AppIdKey*, PtrValueLess> newExcludedApps, newVpnOnlyApps;
}


void WinDaemon::checkWintunInstallation()
{
    /*const auto &installedProducts = findInstalledWintunProducts();
    qInfo() << "WinTUN installed products:" << installedProducts.size();
    for(const auto &product : installedProducts)
        qInfo() << "-" << product;
    _state.wintunMissing(installedProducts.empty());*/
}

void WinDaemon::wireguardServiceFailed()
{
    // If the connection failed after the WG service was started, check whether
    // WinTUN is installed, it might be due to a lack of the driver.  We don't
    // do this for other failures, there's no need to do it for every attempt if
    // we can't reach the server at all to authenticate.
    checkWintunInstallation();
}

void WinDaemon::wireguardConnectionSucceeded()
{
    // Only re-check WinTUN if we thought it was missing.  It is likely present
    // now since the connection succeeded.  This avoids doing this
    // potentially-expensive check in the normal case.
  /*  if(_state.wintunMissing())
        checkWintunInstallation();*/
}
