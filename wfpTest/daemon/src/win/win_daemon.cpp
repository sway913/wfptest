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
	//_filters = FirewallFilters{};
    //if (!_firewall->open() || !_firewall->installProvider())
    //{
    //    //qCritical() << "Unable to initialize WFP firewall";
    //    delete _firewall;
    //    _firewall = nullptr;
    //}
    //else
    //{
    //    _firewall->removeAll();
    //}

    // Qt for some reason passes Unix CA directories to OpenSSL by default on
    // Windows.  This results in the daemon attempting to load CA certificates
    // from C:\etc\ssl\, etc., which are not privileged directories on Windows.
    //
    // This seems to be an oversight.  QSslSocketPrivate::ensureCiphersAndCertsLoaded()
    // enables s_loadRootCertsOnDemand on Windows supposedly to permit fetching
    // CAs from Windows Update.  It's not clear how Windows would actually be
    // notified to fetch the certificates though, since Qt handles TLS itself
    // with OpenSSL.  The implementation of QSslCertificate::verify() does load
    // updated system certificates if this flag is set, but that still doesn't
    // mean that Windows would know to fetch a new root.
    //
    // Qt has already loaded the system CA certs as the default CAs by this
    // point, this just sets s_loadRootCertsOnDemand back to false to prevent
    // the Unix paths from being applied.
    //
    // This might break QSslCertificate::verify(), but PIA does not use this
    // since it is not provided on the Mac SecureTransport backend, we implement
    // this operation with OpenSSL directly.  Qt does not use
    // QSslCertificate::verify(), it's just provided for application use.  (It's

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

void WinDaemon::applyFirewallRules(const FirewallParams& params)
{
    if (!_firewall)
        return;
    
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
