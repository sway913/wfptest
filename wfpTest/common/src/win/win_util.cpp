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
#line SOURCE_FILE("win_util.cpp")

#include "win_util.h"
#include <Windows.h>

#pragma comment(lib, "User32.lib")


std::wstring expandEnvString(const wchar_t *pEnvStr)
{
    std::wstring expanded;
    expanded.resize(MAX_PATH);
	auto len = 0;
    //len = ::ExpandEnvironmentStringsW(pEnvStr, expanded.c_str(), expanded.size());
    if(len < 0 || len > expanded.size())
        return {};
    expanded.resize(len-1); // len includes the terminating null char
    return expanded;
}


ProcAddress::~ProcAddress()
{
    if(_moduleHandle)
        ::FreeLibrary(_moduleHandle);
}

std::wstring WinErrTracer::message() const
{
    LPWSTR errMsg{nullptr};

    auto len = ::FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                                nullptr, code(), 0,
                                reinterpret_cast<LPWSTR>(&errMsg), 0, nullptr);
	std::wstring msg = std::wstring(errMsg);
    ::LocalFree(errMsg);

    return msg;
}

void broadcastMessage(const LPCWSTR &message)
{
    UINT msg = ::RegisterWindowMessageW(message);
    if(!msg)
    {
        /*qWarning() << "Unable to register desired message for broadcast - error"
            << ::GetLastError();*/
    }
    else
    {
        //qDebug () << "Broadcasting message " << QString::fromWCharArray(message);
        PostMessage(HWND_BROADCAST, msg, 0, 0);
    }
}
