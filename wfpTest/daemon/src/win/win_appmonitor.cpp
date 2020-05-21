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
#line SOURCE_FILE("win/win_appmonitor.cpp")

#include "win_appmonitor.h"
#include <Psapi.h>
#include <comutil.h>
#include <array>
#include <mutex>

#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Wbemuuid.lib")




WinAppTracker::WinAppTracker(SplitType type)
    : _type{type}
{
}

std::set<const AppIdKey*, PtrValueLess> WinAppTracker::getAppIds() const
{
    std::set<const AppIdKey*, PtrValueLess> ids;
    for(const auto &excludedApp : _apps)
        ids.insert(&excludedApp.first);
    for(const auto &proc : _procData)
        ids.insert(&proc.second._procAppId);
    return ids;
}


void WinAppTracker::checkMatchingProcess(WinHandle &procHandle, AppIdKey &appId,
                                         Pid_t pid)
{
    // If we already have this process, there's nothing to do.  Just take the
    // process handle to indicate that this was ours.
    // This can happen if a process is created just as we start to scan for a
    // new app rule; we might observe the process just before receiving the
    // "create" event.
    if(_procData.count(pid))
    {
		std::cout << "Already have" << "PID" << pid << "-" << &appId << "- nothing to do" << std::endl;
        procHandle = {};
        appId = {};
        return;
    }

    // Check if it's a matching app itself.  Do this before checking if it's a
    // descendant - it's possible it could be both if one excluded app launches
    // another.
    auto itMatchingApp = _apps.find(appId);
    if(itMatchingApp != _apps.end())
    {
        // It matches one of our apps - take the process handle and app ID; this
        // indicates that the other trackers don't need to be checked.  (Do this
        // even if we do not actually add this process entry.)
        WinHandle takenProcHandle;
        AppIdKey takenAppId;
        procHandle.swap(takenProcHandle);
        appId.swap(takenAppId);

        // Add it only if there are signer names for this app - if there aren't,
        // we'd never match any descendants, skip it.
        if(!itMatchingApp->second._signerNames.empty())
        {
			std::cout << "PID" << pid << "is" <<  "app";
            addSplitProcess(itMatchingApp, std::move(takenProcHandle), pid,
                               std::move(takenAppId));
            dump();
            // This does not cause excluded app IDs to change (it's an explicit app
            // ID we already knew about)
        }
        // Otherwise, there's no need to add it, since it can't match any
        // descendants, but we still took the process handle and app ID so we
        // won't check any other trackers or descendants of other rules in this
        // tracker.
    }
}



void WinAppTracker::dump() const
{
    std::size_t processes{0};
	std::cout << "===" << "app tracker dump ===" << std::endl;
	std::cout << _apps.size() << "apps" << std::endl;
    for(auto itExclApp = _apps.begin(); itExclApp != _apps.end(); ++itExclApp)
    {
        const auto &app = *itExclApp;

        processes += app.second._runningProcesses.size();
		std::cout << "[" << app.second._runningProcesses.size() << "] " << std::endl;
        for(const auto &pid : app.second._runningProcesses)
        {
            auto itProcData = _procData.find(pid);
            if(itProcData == _procData.end())
            {
				std::cout << " -" << pid << "**MISSING**";
                continue;
            }

			std::cout << " -" << pid << std::endl;
            if(itProcData->second._excludedAppPos != itExclApp)
            {
				std::cout << "  ^ **MISMATCH**" << std::endl;
            }
        }
    }

	std::cout << "Total" << processes << "processes" << std::endl;
    if(processes != _procData.size())
    {
		std::cout << "**MISMATCH** Expected" << processes << "- have" << _procData.size() << std::endl;
    }
}

void WinAppTracker::addSplitProcess(ExcludedApps_t::iterator itMatchingApp,
                                    WinHandle procHandle, Pid_t pid,
                                    AppIdKey appId)
{
    assert(itMatchingApp != _apps.end()); // Ensured by caller
	assert(_procData.count(pid) == 0);    // Ensured by caller
	assert(itMatchingApp->second._runningProcesses.count(pid) == 0);    // Class invariant

    itMatchingApp->second._runningProcesses.emplace(pid);
    ProcessData &data = _procData[pid];
    data._procHandle = std::move(procHandle);
    //data._pNotifier.reset(new QWinEventNotifier{data._procHandle.get()});
    //data._procAppId = std::move(appId);
    //data._excludedAppPos = itMatchingApp;

    //connect(data._pNotifier.get(), &QWinEventNotifier::activated, this,
    //        &WinAppTracker::onProcessExited);
}

void WinAppTracker::onProcessExited(HANDLE procHandle)
{
    Pid_t pid = ::GetProcessId(procHandle);

    // If this PID isn't known, there's nothing to do.  It might be possible for
    // this to happen if a process exit races with an app removal, although this
    // depends on whether it's possible for a queued QWinEventNotifier signal to
    // be received after it has been destroyed.
    auto itProcData = _procData.find(pid);
    if(itProcData == _procData.end())
    {
		std::cout << "Already removed PID" << pid << std::endl;
        return;
    }

	//std::cout << "PID" << pid << "exited -" << traceEnum(_type) << "app" << itProcData->second._procAppId << "- group" << itProcData->second._excludedAppPos->first;

    // Remove everything about this process.  We don't remember extra app IDs
    // that we have found once the process exits.  In principle, we could try to
    // remember them so there's no exclusion race if the helper process starts
    // again, but there are a number of trade-offs here:
    //
    // - There's no way to reliably know the extra app IDs the first time an app
    //   is added.  If we try to remember them here, the behavior would change
    //   between the first app launch and subsequent launches.  Consistent
    //   behavior is preferred even if it is imprecise.
    //
    // - This is more robust if an app is excluded unexpectedly.  For example,
    //   if an excluded app occasionally runs "tracert.exe", it'll exclude it
    //   while it's being run by that app (probably desirable), but then it goes
    //   back to normal as soon as it exits (it won't affect a tracert from the
    //   shell, etc.).  The only potential problem is if tracert.exe is run in
    //   both excluded and non-excluded contexts simultaneously.
    //
    // - This approach minimizes the possibility of leaking state if there is an
    //   error in the state tracking of WinAppTracker.

    // Remove the PID from the excluded app group.
	assert(itProcData->second._excludedAppPos != _apps.end());    // Class invariant
    itProcData->second._excludedAppPos->second._runningProcesses.erase(pid);

    // Remove the process data.  Note that this closes procHandle, which is a
    // copy of the handle owned by the process data.
    _procData.erase(itProcData);

    // App IDs have most likely changed.  It's possible they didn't if there is
    // still a PID tracked with this same app ID, but again, let the firewall
    // handle that.
    dump();
    //emit appIdsChanged();
}

WinSplitTunnelTracker::WinSplitTunnelTracker()
    : _vpnOnly{WinAppTracker::SplitType::VpnOnly},
      _excluded{WinAppTracker::SplitType::Excluded}
{
   /* connect(&_vpnOnly, &WinAppTracker::appIdsChanged, this,
            &WinSplitTunnelTracker::appIdsChanged);
    connect(&_excluded, &WinAppTracker::appIdsChanged, this,
            &WinSplitTunnelTracker::appIdsChanged);*/
}

AppIdKey WinSplitTunnelTracker::getProcAppId(const WinHandle &procHandle) const
{
	std::wstring imgPath{ L"" };
    if(imgPath.empty())
        return {};

    // It's definitely not a link, so no need to load a WinLinkReader here
    return AppIdKey{imgPath};
}

std::set<const AppIdKey*, PtrValueLess> WinSplitTunnelTracker::getExcludedAppIds() const
{
    return _excluded.getAppIds();
}

std::set<const AppIdKey*, PtrValueLess> WinSplitTunnelTracker::getVpnOnlyAppIds() const
{
    return _vpnOnly.getAppIds();
}


void WinSplitTunnelTracker::processCreated(WinHandle procHandle, Pid_t pid,
                                           WinHandle parentHandle, Pid_t parentPid)
{
	std::wstring imgPath{ L"" };
    AppIdKey appId;
    if(!imgPath.empty())
    {
        // As in getProcAppId(), definitely not a link, no need to load a link
        // reader
        appId.reset(imgPath);
    }
    // Can't do anything if we couldn't get this process's app ID.
    if(!appId)
    {
		std::cout << "Couldn't get app ID for PID" << pid << "(from parent" << parentPid << ")" << std::endl;
        return;
    }

    // First, check if the process is a direct match to any tracker's rules.
    // Check direct matches for all trackers before checking descendants, in
    // case a process matching one rule invokes another matching process of a
    // different rule type.
    //
    // The app trackers take the process handle if it's matched, so we're done
    // as soon as the process handle is taken.  (The WinAppTracker traces for
    // this.)
    _vpnOnly.checkMatchingProcess(procHandle, appId, pid);
    if(!procHandle)
        return;
    _excluded.checkMatchingProcess(procHandle, appId, pid);
    if(!procHandle)
        return;

    // Check if the process is a descendant of a known parent process.  If one
    // of the trackers matches it this way, then we don't need to find the
    // parent's AppIdKey.
  /*  _vpnOnly.checkMatchingChild(procHandle, appId, imgPath, pid, parentPid);
    if(!procHandle)
        return;
    _excluded.checkMatchingChild(procHandle, appId, imgPath, pid, parentPid);
    if(!procHandle)
        return;*/

    // As discussed in checkNewParent(), it's possible to observe a new child
    // from WMI without having observed the creation of the parent process.
    // Since nothing has matched yet, find the AppIdKey for the parent process,
    // and check if the parent matches any rule.  (If it does, the matching
    // WinAppTracker also checks if the new child should be considered a
    // descendant.)
    AppIdKey parentAppId{getProcAppId(parentHandle)};
    if(!parentAppId)
    {
		std::cout << "Couldn't get app ID for parent" << parentPid << "of new process" << pid << "-" << imgPath.c_str() << std::endl;
        return;
    }
    //_vpnOnly.checkNewParent(procHandle, appId, imgPath, pid, parentHandle,
    //                        parentAppId, parentPid);
    //if(!procHandle || !parentHandle)
    //    return;
    //_excluded.checkNewParent(procHandle, appId, imgPath, pid, parentHandle,
    //                         parentAppId, parentPid);
}

void WinSplitTunnelTracker::dump() const
{
    _vpnOnly.dump();
    _excluded.dump();
}

// This WBEM event sink is used to implement WinAppMonitor.
class WinAppMonitor::WbemEventSink : public IWbemObjectSink
{
public:
    WbemEventSink(WinAppMonitor &monitor, WinComPtr<ISWbemDateTime> pWbemDateTime)
        : _refs{0}, _pWbemDateTime{std::move(pWbemDateTime)}, _pMonitor{&monitor}
    {
        assert(_pWbemDateTime);   // Ensured by caller
    }
    // Not copiable due to ref count
    WbemEventSink(const WbemEventSink &) = delete;
    WbemEventSink &operator=(const WbemEventSink &) = delete;
    // Destructor just sanity-checks reference count
    virtual ~WbemEventSink() { assert(_refs == 0);}

public:
    // IUnknown
    virtual ULONG STDMETHODCALLTYPE AddRef() override;
    virtual ULONG STDMETHODCALLTYPE Release() override;
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppv) override;

    // IWbemObjectSink
    virtual HRESULT STDMETHODCALLTYPE Indicate(LONG lObjectCount,
                                               IWbemClassObject **apObjArray) override;
    virtual HRESULT STDMETHODCALLTYPE SetStatus(LONG lFlags, HRESULT hResult,
                                                BSTR strParam,
                                                IWbemClassObject *pObjParam) override;

    // Disconnect WinAppMonitor because it's being destroyed
    void disconnect();

private:
    void handleEventObject(IWbemClassObject *pObj);
    DWORD readPidProp(IWbemClassObject &obj, const wchar_t *pPropName);
    void readNewProcess(IWbemClassObject &obj);

private:
    // IUnknown ref count - atomic
    LONG _refs;
    // Date/time converter - used only from notification callback
    WinComPtr<ISWbemDateTime> _pWbemDateTime;
    // Monitor where changes are sent - protected with a mutex, cleared when
    // monitor tells us to disconnect
    std::mutex _monitorMutex;
    WinAppMonitor *_pMonitor;
};

ULONG WinAppMonitor::WbemEventSink::AddRef()
{
    return ::InterlockedIncrement(&_refs);
}

ULONG WinAppMonitor::WbemEventSink::Release()
{
    LONG refs = ::InterlockedDecrement(&_refs);
    if(refs == 0)
        delete this;
    return refs;
}

HRESULT WinAppMonitor::WbemEventSink::QueryInterface(REFIID riid, void **ppv)
{
    if(riid == IID_IUnknown)
    {
        IUnknown *pThisItf{this};
        *ppv = pThisItf;
        AddRef();
        return WBEM_S_NO_ERROR;
    }
    if(riid == IID_IWbemObjectSink)
    {
        IWbemObjectSink *pThisItf{this};
        *ppv = pThisItf;
        AddRef();
        return WBEM_S_NO_ERROR;
    }
    return E_NOINTERFACE;
}

HRESULT WinAppMonitor::WbemEventSink::Indicate(long lObjectCount,
                                               IWbemClassObject **apObjArray)
{
	std::unique_lock<std::mutex> locker(_monitorMutex);
    if(!_pMonitor)
        return WBEM_S_NO_ERROR; // Ignore notifications, disconnected

	std::cout << "Notifications:" << lObjectCount << std::endl;
    IWbemClassObject **ppObj = apObjArray;
    IWbemClassObject **ppObjEnd = apObjArray + lObjectCount;
    while(ppObj != ppObjEnd)
    {
        handleEventObject(*ppObj);
        ++ppObj;
    }

    return WBEM_S_NO_ERROR;
}

HRESULT WinAppMonitor::WbemEventSink::SetStatus(LONG lFlags, HRESULT hResult,
                                                BSTR strParam,
                                                IWbemClassObject *pObjParam)
{
    switch(lFlags)
    {
        case WBEM_STATUS_COMPLETE:
			std::cout << "Event sink call complete -" << hResult << std::endl;
            break;
        case WBEM_STATUS_PROGRESS:
			std::cout << "Event sink call progress -" << hResult << std::endl;
            break;
        default:
			std::cout << "Event sink call unexpected status" << lFlags << "-" << hResult << std::endl;
            break;
    }
    return WBEM_S_NO_ERROR;
}

void WinAppMonitor::WbemEventSink::disconnect()
{
	std::unique_lock<std::mutex> lock(_monitorMutex);
    _pMonitor = nullptr;
}

void WinAppMonitor::WbemEventSink::handleEventObject(IWbemClassObject *pObj)
{
    // Get the TargetInstance property - the process that was created
    WinComVariant targetVar;
    HRESULT targetErr = pObj->Get(L"TargetInstance", 0, targetVar.receive(),
                                  nullptr, nullptr);
    if(FAILED(targetErr))
    {
		std::cout << "Failed to read target from event -" << targetErr << std::endl;
        return;
    }

    HRESULT convErr = ::VariantChangeType(&targetVar.get(), &targetVar.get(), 0,
                                          VT_UNKNOWN);
    if(FAILED(convErr) || !targetVar.get().punkVal)
    {
		std::cout << "Failed to convert target to IUnknown -" << convErr << std::endl;
        return;
    }

    WinComPtr<IUnknown> pTgtUnk{targetVar.get().punkVal};
    pTgtUnk->AddRef();

    auto pTgtObj = pTgtUnk.queryInterface<IWbemClassObject>(IID_IWbemClassObject);
    if(!pTgtObj)
    {
		std::cout << "Failed to get object interface from target" << std::endl;
        return;
    }

    readNewProcess(*pTgtObj);
}

DWORD WinAppMonitor::WbemEventSink::readPidProp(IWbemClassObject &obj,
                                                const wchar_t *pPropName)
{
    // Get the property
    WinComVariant pidVar;
    HRESULT pidErr = obj.Get(pPropName, 0, pidVar.receive(), nullptr, nullptr);
    if(FAILED(pidErr))
    {
        //std::cout << "Failed to read" << QStringView{pPropName} << "from new process -" << pidErr;
        return 0;
    }

    HRESULT pidConvErr = ::VariantChangeType(&pidVar.get(), &pidVar.get(), 0,
                                             VT_UI4);
    if(FAILED(pidConvErr))
    {
        //std::cout << "Failed to convert" << QStringView{pPropName} << "to VT_UI4 -" << pidConvErr;
        return 0;
    }

    return V_UI4(&pidVar.get());
}

void WinAppMonitor::WbemEventSink::readNewProcess(IWbemClassObject &obj)
{
    assert(_pWbemDateTime);   // Class invariant

    // Get the process ID and parent process ID
    DWORD pid = readPidProp(obj, L"ProcessId");
    DWORD ppid = readPidProp(obj, L"ParentProcessId");

    if(!pid || !ppid)
        return; // Traced by readPidProp()

	std::cout << "Parent" << ppid << "->" << pid;

    // Get the creation time
    WinComVariant createVar;
    HRESULT createErr = obj.Get(L"CreationDate", 0, createVar.receive(),
                                nullptr, nullptr);
    if(FAILED(createErr))
    {
		std::cout << "Failed to read creation date from process" << pid << "-" << createErr;
        return;
    }
    HRESULT createConvErr = ::VariantChangeType(&createVar.get(), &createVar.get(),
                                                0, VT_BSTR);
    if(FAILED(createConvErr))
    {
		std::cout << "Failed to convert creation date of process" << pid
            << "to VT_BSTR -" << createConvErr << "- type is"
            << V_VT(&createVar.get());
        return;
    }
    // Creation times are (bizarrely) encoded as strings
    HRESULT setTimeErr = _pWbemDateTime->put_Value(V_BSTR(&createVar.get()));
    if(FAILED(setTimeErr))
    {
		/*std::cout << "Failed to parse creation date of process" << pid
            << "-" << setTimeErr << "- value is"
            << QStringView{V_BSTR(&createVar.get())};*/
        return;
    }
    BSTR createFileTimeBstrPtr{nullptr};
    HRESULT getTimeErr = _pWbemDateTime->GetFileTime(false, &createFileTimeBstrPtr);
    // Own the BSTR
    _bstr_t createFileTimeBstr{createFileTimeBstrPtr, false};
    createFileTimeBstrPtr = nullptr;
    if(FAILED(getTimeErr))
    {
		/*std::cout << "Failed to get creation date of process" << pid
            << "-" << getTimeErr << "- value is"
            << QStringView{V_BSTR(&createVar.get())};*/
        return;
    }

    // Parse the new string, which is now a stringified FILETIME
    ULARGE_INTEGER timeLi;
    timeLi.QuadPart = static_cast<std::uint64_t>(_wtoi64(createFileTimeBstr));
    // This time typically only has millisecond precision, drop the
    // 100-nanosecond part anyway to be sure it's consistent with the test below
    timeLi.QuadPart -= (timeLi.QuadPart % 10);
    FILETIME createFileTime;
    createFileTime.dwLowDateTime = timeLi.LowPart;
    createFileTime.dwHighDateTime = timeLi.HighPart;

    // Open the process
    WinHandle procHandle{::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid)};
    if(!procHandle)
    {
		std::cout << "Unable to open process" << pid;
        return;
    }

    // Check if it's really the right process - the PID could have been reused
    FILETIME actualCreateTime, ignored1, ignored2, ignored3;
    if(!::GetProcessTimes(procHandle.get(), &actualCreateTime, &ignored1,
                          &ignored2, &ignored3))
    {
		std::cout << "Unable to get creation time of" << pid;
        return;
    }

    // Drop the 100-nanosecond precision down to millisecond precision for
    // consistency with the WMI time
    timeLi.HighPart = actualCreateTime.dwHighDateTime;
    timeLi.LowPart = actualCreateTime.dwLowDateTime;
    timeLi.QuadPart -= (timeLi.QuadPart % 10);
    FILETIME approxCreateTime;
    approxCreateTime.dwHighDateTime = timeLi.HighPart;
    approxCreateTime.dwLowDateTime = timeLi.LowPart;

    if(approxCreateTime.dwLowDateTime != createFileTime.dwLowDateTime ||
        approxCreateTime.dwHighDateTime != createFileTime.dwHighDateTime)
    {
    /*    std::cout << "Ignoring PID" << pid
            << "- PID was reused.  Expected creation time"
            << FileTimeTracer{createFileTime} << "- got"
            << FileTimeTracer{approxCreateTime};*/
    }

    // Open the parent process
    WinHandle parentHandle{::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, ppid)};
    // Check if this is really the right parent process, in case the PID was
    // reused
    FILETIME parentCreateTime;
    if(!::GetProcessTimes(parentHandle.get(), &parentCreateTime, &ignored1,
                          &ignored2, &ignored3))
    {
		std::cout << "Unable to get creation time of" << ppid << "(parent of" << pid << ")";
        return;
    }

    // If the parent process is newer, the PID was reused.  (If they're the
    // same, we're unsure but we assume it's the correct one.)
    if(::CompareFileTime(&parentCreateTime, &actualCreateTime) > 0)
    {
        //std::cout << "Ignoring PID" << pid
        //    << "- parent PID" << ppid << "was reused.  Child was created at"
        //    << FileTimeTracer{actualCreateTime} << "- parent reported"
        //    << FileTimeTracer{parentCreateTime};
        // There's no reason to check the child if the parent PID was reused.
        // - If this had been a child of a process that we're excluding, we
        //   would still have a HANDLE open to the process and the PID wouldn't
        //   have been reused.
        // - If the parent was actually an excluded process that we didn't know
        //   about, there's no way to figure that out now since the process is
        //   gone.
        return;
    }

    // We opened the process successfully, notify WinAppMonitor
    // (_monitorMutex is locked by Indicate())
    assert(_pMonitor);    // Checked by Indicate()
    _pMonitor->_tracker.processCreated(std::move(procHandle), pid,
                                       std::move(parentHandle), ppid);
}

WinAppMonitor::WinAppMonitor()
{
    //connect(&_tracker, &WinSplitTunnelTracker::appIdsChanged, this,
    //        &WinAppMonitor::appIdsChanged);

    //// Create the WMI locator
    //auto pLocator = WinComPtr<IWbemLocator>::createInprocInst(CLSID_WbemLocator, IID_IWbemLocator);
    //if(!pLocator)
    //{
    //    std::cout << "Unable to create WMI locator";   // Error traced by WinComPtr
    //    return;
    //}

    //// Connect to WMI
    //HRESULT connectErr = pLocator->ConnectServer(_bstr_t{L"ROOT\\CIMV2"},
    //                                             nullptr, nullptr, nullptr,
    //                                             WBEM_FLAG_CONNECT_USE_MAX_WAIT,
    //                                             nullptr, nullptr,
    //                                             _pSvcs.receive());
    //if(FAILED(connectErr) || !_pSvcs)
    //{
    //    std::cout << "Unable to connect to WMI -" << connectErr;
    //    return;
    //}

    HRESULT proxyErr = ::CoSetProxyBlanket(_pSvcs.get(),
                                           RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                                           nullptr, RPC_C_AUTHN_LEVEL_CALL,
                                           RPC_C_IMP_LEVEL_IMPERSONATE,
                                           nullptr, EOAC_NONE);
    if(FAILED(proxyErr))
    {
		std::cout << "Unable to configure WMI proxy -";
        return;
    }
}

WinAppMonitor::~WinAppMonitor()
{
    deactivate();
}

void WinAppMonitor::activate()
{
    if(_pSink || _pSinkStubSink)
        return; // Already active, skip trace

    if(!_pSvcs)
    {
        std::cout << "Can't activate monitor, couldn't connect to WMI";
        return;
    }

    std::cout << "Activating monitor";

    auto pAptmt = WinComPtr<IUnsecuredApartment>::createLocalInst(CLSID_UnsecuredApartment, IID_IUnsecuredApartment);
    if(!pAptmt)
    {
        std::cout << "Unable to create apartment for WMI notifications";
        return;
    }

    // Create an SWbemDateTime object - we need this to convert the funky
    // datetime strings from WMI into a usable value.
    auto pWbemDateTime = WinComPtr<ISWbemDateTime>::createInprocInst(CLSID_SWbemDateTime, __uuidof(ISWbemDateTime));
    if(!pWbemDateTime)
    {
        // This hoses us because we can't verify process handles that we would
        // open.
        std::cout << "Unable to create WbemDateTime converter";
        return;
    }

    WinComPtr<WbemEventSink> pNewSink{new WbemEventSink{*this, std::move(pWbemDateTime)}};
    pNewSink->AddRef();    // New object

    WinComPtr<IUnknown> pSinkStubUnk;
    HRESULT stubErr = pAptmt->CreateObjectStub(pNewSink.get(), pSinkStubUnk.receive());
    if(FAILED(stubErr) || !pSinkStubUnk)
    {
        std::cout << "Unable to create WMI sink stub -" << stubErr;
        return;
    }

    auto pNewSinkStubSink = pSinkStubUnk.queryInterface<IWbemObjectSink>(IID_IWbemObjectSink);
    if(!pNewSinkStubSink)
    {
        std::cout << "Stub failed to return sink interface";
        return;
    }

    HRESULT queryErr = _pSvcs->ExecNotificationQueryAsync(
        _bstr_t{L"WQL"},
        _bstr_t{L"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE "
                "TargetInstance ISA 'Win32_Process'"},
        WBEM_FLAG_SEND_STATUS,
        nullptr,
        pNewSinkStubSink);
    if(FAILED(queryErr))
    {
        std::cout << "Unable to execute WMI query -" << queryErr;
        return;
    }

    std::cout << "Successfully activated monitor";
    _pSink = std::move(pNewSink);
    _pSinkStubSink = std::move(pNewSinkStubSink);
}

void WinAppMonitor::deactivate()
{
    if(!_pSinkStubSink && !_pSink)
        return; // Skip trace

    std::cout << "Deactivating monitor";
    if(_pSvcs && _pSinkStubSink)
        _pSvcs->CancelAsyncCall(_pSinkStubSink.get());
    // We don't know when the sink will actually be released, so we have to
    // disconnect it from WinAppMonitor.
    if(_pSink)
        _pSink->disconnect();
    _pSinkStubSink.reset();
    _pSink.reset();
}


void WinAppMonitor::dump() const
{
    std::cout << "_pSvcs:" << !!_pSvcs << "- pSink:" << !!_pSink
        << "- pSinkStubSink:" << !!_pSinkStubSink;
    _tracker.dump();
}
