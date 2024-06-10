configuration 'DoD_WinSvr_2012_R2_MS_and_DC_v3r7'
{
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
    Import-DSCResource -ModuleName 'AuditPolicyDSC'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'

          param
          (
             [Parameter(Mandatory = $false)]
             [System.String]$ADD_YOUR_ENTERPRISE_ADMINS,
             [Parameter(Mandatory = $false)]
             [System.String]$ADD_YOUR_DOMAIN_ADMINS
          )

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
          {
              ValueName = 'EnumerateAdministrators'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
          {
              ValueName = 'NoDriveTypeAutoRun'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 255
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoInternetOpenWith'
          {
              ValueName = 'NoInternetOpenWith'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior'
          {
              ValueName = 'PreXPSP2ShellProtocolBehavior'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
          {
              ValueName = 'NoAutorun'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 1
          }




          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\LocalSourcePath'
          {
              ValueName = 'LocalSourcePath'
              TargetType = 'ComputerConfiguration'
              ValueType = 'ExpandString'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
              ValueData = $null
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\UseWindowsUpdate'
          {
              ValueName = 'UseWindowsUpdate'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
              ValueData = 2
          }

          RegistryPolicyFile 'DEL_\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\RepairContentServerSource'
          {
              ValueName = 'RepairContentServerSource'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
              ValueData = ''
          }

          RegistryPolicyFile 'DEL_\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy'
          {
              ValueName = 'DisableBkGndGroupPolicy'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
          {
              ValueName = 'MSAOptional'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
          {
              ValueName = 'DisableAutomaticRestartSignOn'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
          {
              ValueName = 'LocalAccountTokenFilterPolicy'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
          {
              ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon'
          {
              ValueName = 'AutoAdminLogon'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
              ValueData = '0'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod'
          {
              ValueName = 'ScreenSaverGracePeriod'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
              ValueData = '5'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Biometrics\Enabled'
          {
              ValueName = 'Enabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Biometrics'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Control Panel\International\BlockUserInputMethodsForSignIn'
          {
              ValueName = 'BlockUserInputMethodsForSignIn'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Control Panel\International'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\EventViewer\MicrosoftEventVwrDisableLinks'
          {
              ValueName = 'MicrosoftEventVwrDisableLinks'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\EventViewer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
          {
              ValueName = 'DisableEnclosureDownload'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Internet Explorer\Feeds'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds\AllowBasicAuthInClear'
          {
              ValueName = 'AllowBasicAuthInClear'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Internet Explorer\Feeds'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Peernet\Disabled'
          {
              ValueName = 'Disabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Peernet'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
          {
              ValueName = 'DCSettingIndex'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
          {
              ValueName = 'ACSettingIndex'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\SQMClient\Windows\CEIPEnable'
          {
              ValueName = 'CEIPEnable'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\SQMClient\Windows'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\AppCompat\DisableInventory'
          {
              ValueName = 'DisableInventory'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\AppCompat'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\AppCompat\DisablePcaUI'
          {
              ValueName = 'DisablePcaUI'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\AppCompat'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Appx\AllowAllTrustedApps'
          {
              ValueName = 'AllowAllTrustedApps'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Appx'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\CredUI\DisablePasswordReveal'
          {
              ValueName = 'DisablePasswordReveal'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\CredUI'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Device Metadata\PreventDeviceMetadataFromNetwork'
          {
              ValueName = 'PreventDeviceMetadataFromNetwork'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Device Metadata'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\AllowRemoteRPC'
          {
              ValueName = 'AllowRemoteRPC'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSystemRestore'
          {
              ValueName = 'DisableSystemRestore'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSendGenericDriverNotFoundToWER'
          {
              ValueName = 'DisableSendGenericDriverNotFoundToWER'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSendRequestAdditionalSoftwareToWER'
          {
              ValueName = 'DisableSendRequestAdditionalSoftwareToWER'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DontSearchWindowsUpdate'
          {
              ValueName = 'DontSearchWindowsUpdate'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DriverSearching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DontPromptForWindowsUpdate'
          {
              ValueName = 'DontPromptForWindowsUpdate'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DriverSearching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\SearchOrderConfig'
          {
              ValueName = 'SearchOrderConfig'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DriverSearching'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DriverServerSelection'
          {
              ValueName = 'DriverServerSelection'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DriverSearching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Application\MaxSize'
          {
              ValueName = 'MaxSize'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\EventLog\Application'
              ValueData = 32768
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Security\MaxSize'
          {
              ValueName = 'MaxSize'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\EventLog\Security'
              ValueData = 196608
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Setup\MaxSize'
          {
              ValueName = 'MaxSize'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\EventLog\Setup'
              ValueData = 32768
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\System\MaxSize'
          {
              ValueName = 'MaxSize'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\EventLog\System'
              ValueData = 32768
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
          {
              ValueName = 'NoHeapTerminationOnCorruption'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Explorer'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
          {
              ValueName = 'NoAutoplayfornonVolume'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Explorer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
          {
              ValueName = 'NoDataExecutionPrevention'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Explorer'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoUseStoreOpenWith'
          {
              ValueName = 'NoUseStoreOpenWith'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Explorer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
          {
              ValueName = 'NoBackgroundPolicy'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
          {
              ValueName = 'NoGPOListChanges'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports'
          {
              ValueName = 'PreventHandwritingErrorReports'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\HandwritingErrorReports'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\SafeForScripting'
          {
              ValueName = 'SafeForScripting'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Installer'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\EnableUserControl'
          {
              ValueName = 'EnableUserControl'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Installer'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\DisableLUAPatching'
          {
              ValueName = 'DisableLUAPatching'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Installer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
          {
              ValueName = 'AlwaysInstallElevated'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Installer'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableLLTDIO'
          {
              ValueName = 'EnableLLTDIO'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnDomain'
          {
              ValueName = 'AllowLLTDIOOnDomain'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnPublicNet'
          {
              ValueName = 'AllowLLTDIOOnPublicNet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitLLTDIOOnPrivateNet'
          {
              ValueName = 'ProhibitLLTDIOOnPrivateNet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableRspndr'
          {
              ValueName = 'EnableRspndr'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnDomain'
          {
              ValueName = 'AllowRspndrOnDomain'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnPublicNet'
          {
              ValueName = 'AllowRspndrOnPublicNet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitRspndrOnPrivateNet'
          {
              ValueName = 'ProhibitRspndrOnPrivateNet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LocationAndSensors\DisableLocation'
          {
              ValueName = 'DisableLocation'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LocationAndSensors'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA'
          {
              ValueName = 'NC_AllowNetBridge_NLA'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Network Connections'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation'
          {
              ValueName = 'NC_StdDomainUserSetLocation'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Network Connections'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
          {
              ValueName = 'NoLockScreenSlideshow'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Personalization'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
          {
              ValueName = 'EnableScriptBlockLogging'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
              ValueData = 1
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
          {
              ValueName = 'EnableScriptBlockInvocationLogging'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer'
          {
              ValueName = 'DisableQueryRemoteServer'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\EnableQueryRemoteServer'
          {
              ValueName = 'EnableQueryRemoteServer'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\EnumerateLocalUsers'
          {
              ValueName = 'EnumerateLocalUsers'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\System'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\DisableLockScreenAppNotifications'
          {
              ValueName = 'DisableLockScreenAppNotifications'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\System'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
          {
              ValueName = 'DontDisplayNetworkSelectionUI'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\System'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\EnableSmartScreen'
          {
              ValueName = 'EnableSmartScreen'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\System'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing'
          {
              ValueName = 'PreventHandwritingDataSharing'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\TabletPC'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\TCPIP\v6Transition\Force_Tunneling'
          {
              ValueName = 'Force_Tunneling'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows\TCPIP\v6Transition'
              ValueData = 'Enabled'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars'
          {
              ValueName = 'EnableRegistrars'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableUPnPRegistrar'
          {
              ValueName = 'DisableUPnPRegistrar'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableInBand802DOT11Registrar'
          {
              ValueName = 'DisableInBand802DOT11Registrar'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableFlashConfigRegistrar'
          {
              ValueName = 'DisableFlashConfigRegistrar'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableWPDRegistrar'
          {
              ValueName = 'DisableWPDRegistrar'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
              ValueData = 0
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WCN\Registrars\MaxWCNDeviceNumber'
          {
              ValueName = 'MaxWCNDeviceNumber'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
              ValueData = ''
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WCN\Registrars\HigherPrecedenceRegistrar'
          {
              ValueName = 'HigherPrecedenceRegistrar'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\UI\DisableWcnUi'
          {
              ValueName = 'DisableWcnUi'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WCN\UI'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled'
          {
              ValueName = 'ScenarioExecutionEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowBasic'
          {
              ValueName = 'AllowBasic'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WinRM\Client'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
          {
              ValueName = 'AllowUnencryptedTraffic'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WinRM\Client'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowDigest'
          {
              ValueName = 'AllowDigest'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WinRM\Client'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\AllowBasic'
          {
              ValueName = 'AllowBasic'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WinRM\Service'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
          {
              ValueName = 'AllowUnencryptedTraffic'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WinRM\Service'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
          {
              ValueName = 'DisableRunAs'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WinRM\Service'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
          {
              ValueName = 'DisableHTTPPrinting'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Printers'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
          {
              ValueName = 'DisableWebPnPDownload'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Printers'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DoNotInstallCompatibleDriverFromWindowsUpdate'
          {
              ValueName = 'DoNotInstallCompatibleDriverFromWindowsUpdate'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Printers'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
          {
              ValueName = 'fAllowToGetHelp'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 0
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
          {
              ValueName = 'fAllowFullControl'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = ''
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
          {
              ValueName = 'MaxTicketExpiry'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = ''
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
          {
              ValueName = 'MaxTicketExpiryUnits'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = ''
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
          {
              ValueName = 'fUseMailto'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
          {
              ValueName = 'fPromptForPassword'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
          {
              ValueName = 'MinEncryptionLevel'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir'
          {
              ValueName = 'PerSessionTempDir'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit'
          {
              ValueName = 'DeleteTempDirsOnExit'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited'
          {
              ValueName = 'fAllowUnsolicited'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 0
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicitedFullControl'
          {
              ValueName = 'fAllowUnsolicitedFullControl'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
          {
              ValueName = 'fEncryptRPCTraffic'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
          {
              ValueName = 'DisablePasswordSaving'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
          {
              ValueName = 'fDisableCdm'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\LoggingEnabled'
          {
              ValueName = 'LoggingEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableCcm'
          {
              ValueName = 'fDisableCcm'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableLPT'
          {
              ValueName = 'fDisableLPT'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisablePNPRedir'
          {
              ValueName = 'fDisablePNPRedir'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fEnableSmartCard'
          {
              ValueName = 'fEnableSmartCard'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\RedirectOnlyDefaultClientPrinter'
          {
              ValueName = 'RedirectOnlyDefaultClientPrinter'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'DELVALS_\Software\policies\Microsoft\Windows NT\Terminal Services\RAUnsolicit'
          {
              ValueName = ''
              TargetType = 'ComputerConfiguration'

              Ensure = 'Present'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services\RAUnsolicit'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsMediaPlayer\DisableAutoUpdate'
          {
              ValueName = 'DisableAutoUpdate'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\WindowsMediaPlayer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsMediaPlayer\GroupPrivacyAcceptance'
          {
              ValueName = 'GroupPrivacyAcceptance'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\WindowsMediaPlayer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WMDRM\DisableOnline'
          {
              ValueName = 'DisableOnline'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\WMDRM'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
          {
              ValueName = 'UseLogonCredential'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode'
          {
              ValueName = 'SafeDllSearchMode'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Control\Session Manager'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
          {
              ValueName = 'DriverLoadPolicy'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel'
          {
              ValueName = 'WarningLevel'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Eventlog\Security'
              ValueData = 90
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\IPSEC\NoDefaultExempt'
          {
              ValueName = 'NoDefaultExempt'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\IPSEC'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
          {
              ValueName = 'SMB1'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10\Start'
          {
              ValueName = 'Start'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\MrxSmb10'
              ValueData = 4
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
          {
              ValueName = 'NoNameReleaseOnDemand'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
          {
              ValueName = 'DisableIPSourceRouting'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
          {
              ValueName = 'EnableICMPRedirect'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery'
          {
              ValueName = 'PerformRouterDiscovery'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime'
          {
              ValueName = 'KeepAliveTime'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
              ValueData = 300000
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions'
          {
              ValueName = 'TcpMaxDataRetransmissions'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableIPAutoConfigurationLimits'
          {
              ValueName = 'EnableIPAutoConfigurationLimits'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
          {
              ValueName = 'DisableIPSourceRouting'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\TcpMaxDataRetransmissions'
          {
              ValueName = 'TcpMaxDataRetransmissions'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
          {
              ValueName = 'EnumerateAdministrators'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
          {
              ValueName = 'NoDriveTypeAutoRun'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 255
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoInternetOpenWith'
          {
              ValueName = 'NoInternetOpenWith'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior'
          {
              ValueName = 'PreXPSP2ShellProtocolBehavior'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
          {
              ValueName = 'NoAutorun'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 1
          }




          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\LocalSourcePath'
          {
              ValueName = 'LocalSourcePath'
              TargetType = 'ComputerConfiguration'
              ValueType = 'ExpandString'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
              ValueData = $null
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\UseWindowsUpdate'
          {
              ValueName = 'UseWindowsUpdate'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
              ValueData = 2
          }

          RegistryPolicyFile 'DEL_\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\RepairContentServerSource'
          {
              ValueName = 'RepairContentServerSource'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
              ValueData = ''
          }

          RegistryPolicyFile 'DEL_\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy'
          {
              ValueName = 'DisableBkGndGroupPolicy'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
          {
              ValueName = 'MSAOptional'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
          {
              ValueName = 'DisableAutomaticRestartSignOn'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
          {
              ValueName = 'LocalAccountTokenFilterPolicy'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
          {
              ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon'
          {
              ValueName = 'AutoAdminLogon'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
              ValueData = '0'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod'
          {
              ValueName = 'ScreenSaverGracePeriod'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
              ValueData = '5'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Biometrics\Enabled'
          {
              ValueName = 'Enabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Biometrics'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Control Panel\International\BlockUserInputMethodsForSignIn'
          {
              ValueName = 'BlockUserInputMethodsForSignIn'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Control Panel\International'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\EventViewer\MicrosoftEventVwrDisableLinks'
          {
              ValueName = 'MicrosoftEventVwrDisableLinks'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\EventViewer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
          {
              ValueName = 'DisableEnclosureDownload'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Internet Explorer\Feeds'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds\AllowBasicAuthInClear'
          {
              ValueName = 'AllowBasicAuthInClear'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Internet Explorer\Feeds'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Peernet\Disabled'
          {
              ValueName = 'Disabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Peernet'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
          {
              ValueName = 'DCSettingIndex'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
          {
              ValueName = 'ACSettingIndex'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\SQMClient\Windows\CEIPEnable'
          {
              ValueName = 'CEIPEnable'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\SQMClient\Windows'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\AppCompat\DisableInventory'
          {
              ValueName = 'DisableInventory'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\AppCompat'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\AppCompat\DisablePcaUI'
          {
              ValueName = 'DisablePcaUI'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\AppCompat'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Appx\AllowAllTrustedApps'
          {
              ValueName = 'AllowAllTrustedApps'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Appx'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\CredUI\DisablePasswordReveal'
          {
              ValueName = 'DisablePasswordReveal'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\CredUI'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Device Metadata\PreventDeviceMetadataFromNetwork'
          {
              ValueName = 'PreventDeviceMetadataFromNetwork'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Device Metadata'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\AllowRemoteRPC'
          {
              ValueName = 'AllowRemoteRPC'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSystemRestore'
          {
              ValueName = 'DisableSystemRestore'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSendGenericDriverNotFoundToWER'
          {
              ValueName = 'DisableSendGenericDriverNotFoundToWER'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSendRequestAdditionalSoftwareToWER'
          {
              ValueName = 'DisableSendRequestAdditionalSoftwareToWER'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DontSearchWindowsUpdate'
          {
              ValueName = 'DontSearchWindowsUpdate'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DriverSearching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DontPromptForWindowsUpdate'
          {
              ValueName = 'DontPromptForWindowsUpdate'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DriverSearching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\SearchOrderConfig'
          {
              ValueName = 'SearchOrderConfig'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DriverSearching'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DriverServerSelection'
          {
              ValueName = 'DriverServerSelection'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\DriverSearching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Application\MaxSize'
          {
              ValueName = 'MaxSize'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\EventLog\Application'
              ValueData = 32768
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Security\MaxSize'
          {
              ValueName = 'MaxSize'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\EventLog\Security'
              ValueData = 196608
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Setup\MaxSize'
          {
              ValueName = 'MaxSize'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\EventLog\Setup'
              ValueData = 32768
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\System\MaxSize'
          {
              ValueName = 'MaxSize'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\EventLog\System'
              ValueData = 32768
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
          {
              ValueName = 'NoHeapTerminationOnCorruption'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Explorer'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
          {
              ValueName = 'NoAutoplayfornonVolume'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Explorer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
          {
              ValueName = 'NoDataExecutionPrevention'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Explorer'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoUseStoreOpenWith'
          {
              ValueName = 'NoUseStoreOpenWith'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Explorer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
          {
              ValueName = 'NoBackgroundPolicy'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
          {
              ValueName = 'NoGPOListChanges'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports'
          {
              ValueName = 'PreventHandwritingErrorReports'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\HandwritingErrorReports'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\SafeForScripting'
          {
              ValueName = 'SafeForScripting'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Installer'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\EnableUserControl'
          {
              ValueName = 'EnableUserControl'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Installer'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\DisableLUAPatching'
          {
              ValueName = 'DisableLUAPatching'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Installer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
          {
              ValueName = 'AlwaysInstallElevated'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Installer'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableLLTDIO'
          {
              ValueName = 'EnableLLTDIO'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnDomain'
          {
              ValueName = 'AllowLLTDIOOnDomain'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnPublicNet'
          {
              ValueName = 'AllowLLTDIOOnPublicNet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitLLTDIOOnPrivateNet'
          {
              ValueName = 'ProhibitLLTDIOOnPrivateNet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableRspndr'
          {
              ValueName = 'EnableRspndr'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnDomain'
          {
              ValueName = 'AllowRspndrOnDomain'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnPublicNet'
          {
              ValueName = 'AllowRspndrOnPublicNet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitRspndrOnPrivateNet'
          {
              ValueName = 'ProhibitRspndrOnPrivateNet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LLTD'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LocationAndSensors\DisableLocation'
          {
              ValueName = 'DisableLocation'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\LocationAndSensors'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA'
          {
              ValueName = 'NC_AllowNetBridge_NLA'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Network Connections'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation'
          {
              ValueName = 'NC_StdDomainUserSetLocation'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Network Connections'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
          {
              ValueName = 'NoLockScreenSlideshow'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\Personalization'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
          {
              ValueName = 'EnableScriptBlockLogging'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
              ValueData = 1
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
          {
              ValueName = 'EnableScriptBlockInvocationLogging'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer'
          {
              ValueName = 'DisableQueryRemoteServer'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\EnableQueryRemoteServer'
          {
              ValueName = 'EnableQueryRemoteServer'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\EnumerateLocalUsers'
          {
              ValueName = 'EnumerateLocalUsers'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\System'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\DisableLockScreenAppNotifications'
          {
              ValueName = 'DisableLockScreenAppNotifications'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\System'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
          {
              ValueName = 'DontDisplayNetworkSelectionUI'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\System'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\EnableSmartScreen'
          {
              ValueName = 'EnableSmartScreen'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\System'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing'
          {
              ValueName = 'PreventHandwritingDataSharing'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\TabletPC'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\TCPIP\v6Transition\Force_Tunneling'
          {
              ValueName = 'Force_Tunneling'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows\TCPIP\v6Transition'
              ValueData = 'Enabled'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars'
          {
              ValueName = 'EnableRegistrars'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableUPnPRegistrar'
          {
              ValueName = 'DisableUPnPRegistrar'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableInBand802DOT11Registrar'
          {
              ValueName = 'DisableInBand802DOT11Registrar'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableFlashConfigRegistrar'
          {
              ValueName = 'DisableFlashConfigRegistrar'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableWPDRegistrar'
          {
              ValueName = 'DisableWPDRegistrar'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
              ValueData = 0
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WCN\Registrars\MaxWCNDeviceNumber'
          {
              ValueName = 'MaxWCNDeviceNumber'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
              ValueData = ''
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WCN\Registrars\HigherPrecedenceRegistrar'
          {
              ValueName = 'HigherPrecedenceRegistrar'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\UI\DisableWcnUi'
          {
              ValueName = 'DisableWcnUi'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WCN\UI'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled'
          {
              ValueName = 'ScenarioExecutionEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowBasic'
          {
              ValueName = 'AllowBasic'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WinRM\Client'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
          {
              ValueName = 'AllowUnencryptedTraffic'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WinRM\Client'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowDigest'
          {
              ValueName = 'AllowDigest'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WinRM\Client'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\AllowBasic'
          {
              ValueName = 'AllowBasic'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WinRM\Service'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
          {
              ValueName = 'AllowUnencryptedTraffic'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WinRM\Service'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
          {
              ValueName = 'DisableRunAs'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows\WinRM\Service'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
          {
              ValueName = 'DisableHTTPPrinting'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Printers'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
          {
              ValueName = 'DisableWebPnPDownload'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Printers'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DoNotInstallCompatibleDriverFromWindowsUpdate'
          {
              ValueName = 'DoNotInstallCompatibleDriverFromWindowsUpdate'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Printers'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
          {
              ValueName = 'RestrictRemoteClients'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Rpc'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
          {
              ValueName = 'fAllowToGetHelp'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 0
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
          {
              ValueName = 'fAllowFullControl'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = ''
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
          {
              ValueName = 'MaxTicketExpiry'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = ''
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
          {
              ValueName = 'MaxTicketExpiryUnits'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = ''
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
          {
              ValueName = 'fUseMailto'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
          {
              ValueName = 'fPromptForPassword'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
          {
              ValueName = 'MinEncryptionLevel'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir'
          {
              ValueName = 'PerSessionTempDir'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit'
          {
              ValueName = 'DeleteTempDirsOnExit'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited'
          {
              ValueName = 'fAllowUnsolicited'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 0
          }

          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicitedFullControl'
          {
              ValueName = 'fAllowUnsolicitedFullControl'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
          {
              ValueName = 'fEncryptRPCTraffic'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
          {
              ValueName = 'DisablePasswordSaving'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
          {
              ValueName = 'fDisableCdm'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\LoggingEnabled'
          {
              ValueName = 'LoggingEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableCcm'
          {
              ValueName = 'fDisableCcm'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableLPT'
          {
              ValueName = 'fDisableLPT'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisablePNPRedir'
          {
              ValueName = 'fDisablePNPRedir'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fEnableSmartCard'
          {
              ValueName = 'fEnableSmartCard'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\RedirectOnlyDefaultClientPrinter'
          {
              ValueName = 'RedirectOnlyDefaultClientPrinter'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
              ValueData = 1
          }

          RegistryPolicyFile 'DELVALS_\Software\policies\Microsoft\Windows NT\Terminal Services\RAUnsolicit'
          {
              ValueName = ''
              TargetType = 'ComputerConfiguration'

              Ensure = 'Present'
              ValueType = 'String'
              Key = 'Software\policies\Microsoft\Windows NT\Terminal Services\RAUnsolicit'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsMediaPlayer\DisableAutoUpdate'
          {
              ValueName = 'DisableAutoUpdate'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\WindowsMediaPlayer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsMediaPlayer\GroupPrivacyAcceptance'
          {
              ValueName = 'GroupPrivacyAcceptance'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\WindowsMediaPlayer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WMDRM\DisableOnline'
          {
              ValueName = 'DisableOnline'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\policies\Microsoft\WMDRM'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
          {
              ValueName = 'UseLogonCredential'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode'
          {
              ValueName = 'SafeDllSearchMode'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Control\Session Manager'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
          {
              ValueName = 'DriverLoadPolicy'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel'
          {
              ValueName = 'WarningLevel'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Eventlog\Security'
              ValueData = 90
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\IPSEC\NoDefaultExempt'
          {
              ValueName = 'NoDefaultExempt'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\IPSEC'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
          {
              ValueName = 'SMB1'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10\Start'
          {
              ValueName = 'Start'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\MrxSmb10'
              ValueData = 4
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
          {
              ValueName = 'NoNameReleaseOnDemand'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
          {
              ValueName = 'DisableIPSourceRouting'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
          {
              ValueName = 'EnableICMPRedirect'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery'
          {
              ValueName = 'PerformRouterDiscovery'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime'
          {
              ValueName = 'KeepAliveTime'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
              ValueData = 300000
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions'
          {
              ValueName = 'TcpMaxDataRetransmissions'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableIPAutoConfigurationLimits'
          {
              ValueName = 'EnableIPAutoConfigurationLimits'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
          {
              ValueName = 'DisableIPSourceRouting'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\TcpMaxDataRetransmissions'
          {
              ValueName = 'TcpMaxDataRetransmissions'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
              ValueData = 3
          }

          <# RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\SaveZoneInformation'
          {
              ValueName = 'SaveZoneInformation'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\HideZoneInfoOnProperties'
          {
              ValueName = 'HideZoneInfoOnProperties'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\ScanWithAntiVirus'
          {
              ValueName = 'ScanWithAntiVirus'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoInplaceSharing'
          {
              ValueName = 'NoInplaceSharing'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoReadingPane'
          {
              ValueName = 'NoReadingPane'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPreviewPane'
          {
              ValueName = 'NoPreviewPane'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0\NoImplicitFeedback'
          {
              ValueName = 'NoImplicitFeedback'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0\NoExplicitFeedback'
          {
              ValueName = 'NoExplicitFeedback'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaveActive'
          {
              ValueName = 'ScreenSaveActive'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaverIsSecure'
          {
              ValueName = 'ScreenSaverIsSecure'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\NoCloudApplicationNotification'
          {
              ValueName = 'NoCloudApplicationNotification'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\NoToastApplicationNotificationOnLockScreen'
          {
              ValueName = 'NoToastApplicationNotificationOnLockScreen'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer\PreventCodecDownload'
          {
              ValueName = 'PreventCodecDownload'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\HideZoneInfoOnProperties'
          {
              ValueName = 'HideZoneInfoOnProperties'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\SaveZoneInformation'
          {
              ValueName = 'SaveZoneInformation'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\ScanWithAntiVirus'
          {
              ValueName = 'ScanWithAntiVirus'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoInplaceSharing'
          {
              ValueName = 'NoInplaceSharing'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoReadingPane'
          {
              ValueName = 'NoReadingPane'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPreviewPane'
          {
              ValueName = 'NoPreviewPane'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0\NoImplicitFeedback'
          {
              ValueName = 'NoImplicitFeedback'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0\NoExplicitFeedback'
          {
              ValueName = 'NoExplicitFeedback'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaveActive'
          {
              ValueName = 'ScreenSaveActive'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaverIsSecure'
          {
              ValueName = 'ScreenSaverIsSecure'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\NoCloudApplicationNotification'
          {
              ValueName = 'NoCloudApplicationNotification'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\NoToastApplicationNotificationOnLockScreen'
          {
              ValueName = 'NoToastApplicationNotificationOnLockScreen'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer\PreventCodecDownload'
          {
              ValueName = 'PreventCodecDownload'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer'
              ValueData = 1
          } #>

          AuditPolicySubcategory 'Audit Credential Validation (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Credential Validation'
          }

          AuditPolicySubcategory 'Audit Credential Validation (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Credential Validation'
          }

          AuditPolicySubcategory 'Audit Computer Account Management (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Computer Account Management'
          }

          AuditPolicySubcategory 'Audit Computer Account Management (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Computer Account Management'
          }

          AuditPolicySubcategory 'Audit Other Account Management Events (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Other Account Management Events'
          }

          AuditPolicySubcategory 'Audit Other Account Management Events (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Other Account Management Events'
          }

          AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Security Group Management'
          }

          AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Security Group Management'
          }

          AuditPolicySubcategory 'Audit User Account Management (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'User Account Management'
          }

          AuditPolicySubcategory 'Audit User Account Management (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'User Account Management'
          }

          AuditPolicySubcategory 'Audit Process Creation (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Process Creation'
          }

          AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Process Creation'
          }

          AuditPolicySubcategory 'Audit Directory Service Access (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Directory Service Access'
          }

          AuditPolicySubcategory 'Audit Directory Service Access (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Directory Service Access'
          }

          AuditPolicySubcategory 'Audit Directory Service Changes (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Directory Service Changes'
          }

          AuditPolicySubcategory 'Audit Directory Service Changes (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Directory Service Changes'
          }

          AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Account Lockout'
          }

          AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Absent'
              Name = 'Account Lockout'
          }

          AuditPolicySubcategory 'Audit Logoff (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Logoff'
          }

          AuditPolicySubcategory 'Audit Logoff (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Logoff'
          }

          AuditPolicySubcategory 'Audit Logon (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Logon'
          }

          AuditPolicySubcategory 'Audit Logon (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Logon'
          }

          AuditPolicySubcategory 'Audit Special Logon (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Special Logon'
          }

          AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Special Logon'
          }

          AuditPolicySubcategory 'Audit Removable Storage (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Removable Storage'
          }

          AuditPolicySubcategory 'Audit Removable Storage (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Removable Storage'
          }

          AuditPolicySubcategory 'Audit Central Access Policy Staging (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Central Policy Staging'
          }

          AuditPolicySubcategory 'Audit Central Access Policy Staging (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Central Policy Staging'
          }

          AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Audit Policy Change'
          }

          AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Audit Policy Change'
          }

          AuditPolicySubcategory 'Audit Authentication Policy Change (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Authentication Policy Change'
          }

          AuditPolicySubcategory 'Audit Authentication Policy Change (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Authentication Policy Change'
          }

          AuditPolicySubcategory 'Audit Authorization Policy Change (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Authorization Policy Change'
          }

          AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Authorization Policy Change'
          }

          AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Sensitive Privilege Use'
          }

          AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Sensitive Privilege Use'
          }

          AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'IPsec Driver'
          }

          AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'IPsec Driver'
          }

          AuditPolicySubcategory 'Audit Other System Events (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Other System Events'
          }

          AuditPolicySubcategory 'Audit Other System Events (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Other System Events'
          }

          AuditPolicySubcategory 'Audit Security State Change (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Security State Change'
          }

          AuditPolicySubcategory 'Audit Security State Change (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Security State Change'
          }

          AuditPolicySubcategory 'Audit Security System Extension (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Security System Extension'
          }

          AuditPolicySubcategory 'Audit Security System Extension (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Security System Extension'
          }

          AuditPolicySubcategory 'Audit System Integrity (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'System Integrity'
          }

          AuditPolicySubcategory 'Audit System Integrity (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'System Integrity'
          }

          AuditPolicySubcategory 'Audit Credential Validation (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Credential Validation'
          }

          AuditPolicySubcategory 'Audit Credential Validation (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Credential Validation'
          }

          AuditPolicySubcategory 'Audit Other Account Management Events (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Other Account Management Events'
          }

          AuditPolicySubcategory 'Audit Other Account Management Events (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Other Account Management Events'
          }

          AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Security Group Management'
          }

          AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Security Group Management'
          }

          AuditPolicySubcategory 'Audit User Account Management (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'User Account Management'
          }

          AuditPolicySubcategory 'Audit User Account Management (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'User Account Management'
          }

          AuditPolicySubcategory 'Audit Process Creation (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Process Creation'
          }

          AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Process Creation'
          }

          AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Account Lockout'
          }

          AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Absent'
              Name = 'Account Lockout'
          }

          AuditPolicySubcategory 'Audit Logoff (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Logoff'
          }

          AuditPolicySubcategory 'Audit Logoff (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Logoff'
          }

          AuditPolicySubcategory 'Audit Logon (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Logon'
          }

          AuditPolicySubcategory 'Audit Logon (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Logon'
          }

          AuditPolicySubcategory 'Audit Special Logon (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Special Logon'
          }

          AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Special Logon'
          }

          AuditPolicySubcategory 'Audit Removable Storage (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Removable Storage'
          }

          AuditPolicySubcategory 'Audit Removable Storage (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Removable Storage'
          }

          AuditPolicySubcategory 'Audit Central Access Policy Staging (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Central Policy Staging'
          }

          AuditPolicySubcategory 'Audit Central Access Policy Staging (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Central Policy Staging'
          }

          AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Audit Policy Change'
          }

          AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Audit Policy Change'
          }

          AuditPolicySubcategory 'Audit Authentication Policy Change (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Authentication Policy Change'
          }

          AuditPolicySubcategory 'Audit Authentication Policy Change (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Authentication Policy Change'
          }

          AuditPolicySubcategory 'Audit Authorization Policy Change (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Authorization Policy Change'
          }

          AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Authorization Policy Change'
          }

          AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Sensitive Privilege Use'
          }

          AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Sensitive Privilege Use'
          }

          AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'IPsec Driver'
          }

          AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'IPsec Driver'
          }

          AuditPolicySubcategory 'Audit Other System Events (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Other System Events'
          }

          AuditPolicySubcategory 'Audit Other System Events (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'Other System Events'
          }

          AuditPolicySubcategory 'Audit Security State Change (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Security State Change'
          }

          AuditPolicySubcategory 'Audit Security State Change (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Security State Change'
          }

          AuditPolicySubcategory 'Audit Security System Extension (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'Security System Extension'
          }

          AuditPolicySubcategory 'Audit Security System Extension (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Absent'
              Name = 'Security System Extension'
          }

          AuditPolicySubcategory 'Audit System Integrity (Success) - Inclusion'
          {
              AuditFlag = 'Success'
              Ensure = 'Present'
              Name = 'System Integrity'
          }

          AuditPolicySubcategory 'Audit System Integrity (Failure) - Inclusion'
          {
              AuditFlag = 'Failure'
              Ensure = 'Present'
              Name = 'System Integrity'
          }

          SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
          {
              Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
              Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
          }

          SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
          {
              Domain_member_Maximum_machine_account_password_age = '30'
              Name = 'Domain_member_Maximum_machine_account_password_age'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
          {
              User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
              Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
          }

          <#          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
          {
              Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.,By using this IS (which includes any device attached to this IS)"," you consent to the following conditions:,-The USG routinely intercepts and monitors communications on this IS for purposes including"," but not limited to"," penetration testing"," COMSEC monitoring"," network operations and defense"," personnel misconduct (PM)"," law enforcement (LE)"," and counterintelligence (CI) investigations.,-At any time"," the USG may inspect and seize data stored on this IS.,-Communications using"," or data stored on"," this IS are not private"," are subject to routine monitoring"," interception"," and search"," and may be disclosed or used for any USG-authorized purpose.,-This IS includes security measures (e.g."," authentication and access controls) to protect USG interests--not for your personal benefit or privacy.,-Notwithstanding the above"," using this IS does not constitute consent to PM"," LE or CI investigative searching or monitoring of the content of privileged communications"," or work product"," related to personal representation or services by attorneys"," psychotherapists"," or clergy"," and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
              Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
          } #>

          SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
          {
              Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
              Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
          }

          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Prompt_user_to_change_password_before_expiration'
          {
              Interactive_logon_Prompt_user_to_change_password_before_expiration = '14'
              Name = 'Interactive_logon_Prompt_user_to_change_password_before_expiration'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Shares_that_can_be_accessed_anonymously'
          {
              Network_access_Shares_that_can_be_accessed_anonymously = 'String'
              Name = 'Network_access_Shares_that_can_be_accessed_anonymously'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths_and_subpaths'
          {
              Network_access_Remotely_accessible_registry_paths_and_subpaths = 'Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog'
              Name = 'Network_access_Remotely_accessible_registry_paths_and_subpaths'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
          {
              Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
              Name = 'Network_security_LAN_Manager_authentication_level'
          }

          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_require_CTRL_ALT_DEL'
          {
              Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled'
              Name = 'Interactive_logon_Do_not_require_CTRL_ALT_DEL'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
          {
              Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
              Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
          }

          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
          {
              Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
              Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
          }

          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
          {
              Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
              Name = 'Interactive_logon_Smart_card_removal_behavior'
          }

          SecurityOption 'SecurityRegistry(INF): Devices_Allowed_to_format_and_eject_removable_media'
          {
              Devices_Allowed_to_format_and_eject_removable_media = 'Administrators'
              Name = 'Devices_Allowed_to_format_and_eject_removable_media'
          }

          SecurityOption 'SecurityRegistry(INF): Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
          {
              Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled'
              Name = 'Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
          }

          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_display_last_user_name'
          {
              Interactive_logon_Do_not_display_last_user_name = 'Enabled'
              Name = 'Interactive_logon_Do_not_display_last_user_name'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
          {
              Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
              Name = 'Network_security_LDAP_client_signing_requirements'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
          {
              Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled'
              Name = 'Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
          {
              Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
              Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
          {
              User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent'
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
          {
              Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
              Name = 'Microsoft_network_server_Digitally_sign_communications_always'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
          {
              User_Account_Control_Only_elevate_executables_that_are_signed_and_validated = 'Disabled'
              Name = 'User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
          }

          SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
          {
              System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
              Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
          {
              Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
              Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
          }

          SecurityOption 'SecurityRegistry(INF): System_settings_Optional_subsystems'
          {
              System_settings_Optional_subsystems = 'String'
              Name = 'System_settings_Optional_subsystems'
          }

          SecurityOption 'SecurityRegistry(INF): Domain_controller_Refuse_machine_account_password_changes'
          {
              Domain_controller_Refuse_machine_account_password_changes = 'Disabled'
              Name = 'Domain_controller_Refuse_machine_account_password_changes'
          }

          SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
          {
              Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
              Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
          }

          SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
          {
              System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
              Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
          }

          SecurityOption 'SecurityRegistry(INF): System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
          {
              System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled'
              Name = 'System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
          }

          SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
          {
              System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
              Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
          }

          SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_access_of_global_system_objects'
          {
              Audit_Audit_the_access_of_global_system_objects = 'Disabled'
              Name = 'Audit_Audit_the_access_of_global_system_objects'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
          {
              Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
              Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
          {
              Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
              Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
          }

          SecurityOption 'SecurityRegistry(INF): Devices_Prevent_users_from_installing_printer_drivers'
          {
              Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'
              Name = 'Devices_Prevent_users_from_installing_printer_drivers'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
          {
              User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
              Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
          {
              Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
              Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
          }

          SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
          {
              Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
              Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
          {
              User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'
              Name = 'User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
          {
              Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
              Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
          }

          SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
          {
              Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
              Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
          {
              Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
              Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
          }

          SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
          {
              Domain_member_Disable_machine_account_password_changes = 'Disabled'
              Name = 'Domain_member_Disable_machine_account_password_changes'
          }

          SecurityOption 'SecurityRegistry(INF): Domain_controller_LDAP_server_signing_requirements'
          {
              Domain_controller_LDAP_server_signing_requirements = 'Require Signing'
              Name = 'Domain_controller_LDAP_server_signing_requirements'
          }

          SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_use_of_Backup_and_Restore_privilege'
          {
              Audit_Audit_the_use_of_Backup_and_Restore_privilege = 'Disabled'
              Name = 'Audit_Audit_the_use_of_Backup_and_Restore_privilege'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
          {
              Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'
              Name = 'Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
          {
              Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
              Name = 'Microsoft_network_client_Digitally_sign_communications_always'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
          {
              User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Sharing_and_security_model_for_local_accounts'
          {
              Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - Local users authenticate as themselves'
              Name = 'Network_access_Sharing_and_security_model_for_local_accounts'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
          {
              Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
              Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
          }

          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
          {
              Interactive_logon_Machine_inactivity_limit = '900'
              Name = 'Interactive_logon_Machine_inactivity_limit'
          }

          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
          {
              Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
              Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Server_SPN_target_name_validation_level'
          {
              Microsoft_network_server_Server_SPN_target_name_validation_level = 'Off'
              Name = 'Microsoft_network_server_Server_SPN_target_name_validation_level'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
          {
              User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
              Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
          {
              User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
              Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
          }

          SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
          {
              Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
              Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Named_Pipes_that_can_be_accessed_anonymously'
          {
              Network_access_Named_Pipes_that_can_be_accessed_anonymously = 'lsarpc,netlogon,samr'
              Name = 'Network_access_Named_Pipes_that_can_be_accessed_anonymously'
          }

          SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
          {
              Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
              Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
          {
              User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
              Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
          {
              Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
              Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
          {
              User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
              Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
          {
              Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
              Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
          {
              Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
              Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths'
          {
              Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion'
              Name = 'Network_access_Remotely_accessible_registry_paths'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
          {
              Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
              Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
          }

          Service 'Services(INF): SCPolicySvc'
          {
              State = 'Running'
              Name = 'SCPolicySvc'
          }

          <#          SecuritySetting 'SecuritySetting(INF): PasswordHistorySize'
          {
              PasswordHistorySize = 24
              Name = 'PasswordHistorySize'
          }

          SecuritySetting 'SecuritySetting(INF): LockoutDuration'
          {
              Name = 'LockoutDuration'
              LockoutDuration = 15
          }

          SecuritySetting 'SecuritySetting(INF): LockoutBadCount'
          {
              Name = 'LockoutBadCount'
              LockoutBadCount = 3
          }

          SecuritySetting 'SecuritySetting(INF): MinimumPasswordAge'
          {
              Name = 'MinimumPasswordAge'
              MinimumPasswordAge = 1
          }

          SecuritySetting 'SecuritySetting(INF): NewGuestName'
          {
              NewGuestName = 'Visitor'
              Name = 'NewGuestName'
          }

          SecuritySetting 'SecuritySetting(INF): ResetLockoutCount'
          {
              ResetLockoutCount = 15
              Name = 'ResetLockoutCount'
          }

          SecuritySetting 'SecuritySetting(INF): ForceLogoffWhenHourExpire'
          {
              Name = 'ForceLogoffWhenHourExpire'
              ForceLogoffWhenHourExpire = 1
          }

          SecuritySetting 'SecuritySetting(INF): EnableGuestAccount'
          {
              EnableGuestAccount = 0
              Name = 'EnableGuestAccount'
          }

          SecuritySetting 'SecuritySetting(INF): MaximumPasswordAge'
          {
              MaximumPasswordAge = 60
              Name = 'MaximumPasswordAge'
          }

          SecuritySetting 'SecuritySetting(INF): MinimumPasswordLength'
          {
              Name = 'MinimumPasswordLength'
              MinimumPasswordLength = 14
          }

          SecuritySetting 'SecuritySetting(INF): PasswordComplexity'
          {
              PasswordComplexity = 1
              Name = 'PasswordComplexity'
          }

          SecuritySetting 'SecuritySetting(INF): ClearTextPassword'
          {
              ClearTextPassword = 0
              Name = 'ClearTextPassword'
          }

          SecuritySetting 'SecuritySetting(INF): NewAdministratorName'
          {
              NewAdministratorName = 'X_Admin'
              Name = 'NewAdministratorName'
          }

          SecuritySetting 'SecuritySetting(INF): LSAAnonymousNameLookup'
          {
              LSAAnonymousNameLookup = 0
              Name = 'LSAAnonymousNameLookup'
          } #>

          UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
          {
              Identity = @('')
              Policy = 'Create_permanent_shared_objects'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Load_and_unload_device_drivers'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
          {
              Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
              Policy = 'Create_global_objects'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Increase_scheduling_priority'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
          {
              Identity = @('')
              Policy = 'Lock_pages_in_memory'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits'
          {
              Identity = @('*S-1-5-20', '*S-1-5-19')
              Policy = 'Generate_security_audits'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
          {
              Identity = @('')
              Policy = 'Act_as_part_of_the_operating_system'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Perform_volume_maintenance_tasks'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
          {
              Identity = @('*S-1-5-32-546')
              Policy = 'Deny_log_on_through_Remote_Desktop_Services'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Restore_files_and_directories'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
          {
              Identity = @('*S-1-5-32-546')
              Policy = 'Deny_log_on_locally'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
          {
              Identity = @('')
              Policy = 'Access_Credential_Manager_as_a_trusted_caller'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
          {
              Identity = @('*S-1-5-32-546')
              Policy = 'Deny_log_on_as_a_batch_job'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
          {
              Identity = @('*S-1-5-32-546')
              Policy = 'Deny_access_to_this_computer_from_the_network'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
          {
              Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
              Policy = 'Impersonate_a_client_after_authentication'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
          {
              Identity = @('')
              Policy = 'Deny_log_on_as_a_service'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Debug_programs'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Modify_firmware_environment_values'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
          {
              Identity = @('*S-1-5-9', '*S-1-5-11', '*S-1-5-32-544')
              Policy = 'Access_this_computer_from_the_network'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Profile_single_process'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Create_a_pagefile'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Manage_auditing_and_security_log'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Force_shutdown_from_a_remote_system'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_through_Remote_Desktop_Services'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Allow_log_on_through_Remote_Desktop_Services'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Take_ownership_of_files_or_other_objects'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Allow_log_on_locally'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
          {
              Identity = @('')
              Policy = 'Create_a_token_object'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Add_workstations_to_domain'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Add_workstations_to_domain'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Create_symbolic_links'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Back_up_files_and_directories'
              Force = $True
          }

          SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
          {
              Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
              Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
          }

          SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
          {
              Domain_member_Maximum_machine_account_password_age = '30'
              Name = 'Domain_member_Maximum_machine_account_password_age'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
          {
              User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
              Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
          }

          <#          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
          {
              Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.,By using this IS (which includes any device attached to this IS)"," you consent to the following conditions:,-The USG routinely intercepts and monitors communications on this IS for purposes including"," but not limited to"," penetration testing"," COMSEC monitoring"," network operations and defense"," personnel misconduct (PM)"," law enforcement (LE)"," and counterintelligence (CI) investigations.,-At any time"," the USG may inspect and seize data stored on this IS.,-Communications using"," or data stored on"," this IS are not private"," are subject to routine monitoring"," interception"," and search"," and may be disclosed or used for any USG-authorized purpose.,-This IS includes security measures (e.g."," authentication and access controls) to protect USG interests--not for your personal benefit or privacy.,-Notwithstanding the above"," using this IS does not constitute consent to PM"," LE or CI investigative searching or monitoring of the content of privileged communications"," or work product"," related to personal representation or services by attorneys"," psychotherapists"," or clergy"," and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
              Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
          } #>

          SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
          {
              Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
              Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
          }

          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Prompt_user_to_change_password_before_expiration'
          {
              Interactive_logon_Prompt_user_to_change_password_before_expiration = '14'
              Name = 'Interactive_logon_Prompt_user_to_change_password_before_expiration'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Shares_that_can_be_accessed_anonymously'
          {
              Network_access_Shares_that_can_be_accessed_anonymously = 'String'
              Name = 'Network_access_Shares_that_can_be_accessed_anonymously'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths_and_subpaths'
          {
              Network_access_Remotely_accessible_registry_paths_and_subpaths = 'Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog'
              Name = 'Network_access_Remotely_accessible_registry_paths_and_subpaths'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
          {
              Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
              Name = 'Network_security_LAN_Manager_authentication_level'
          }

          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_require_CTRL_ALT_DEL'
          {
              Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled'
              Name = 'Interactive_logon_Do_not_require_CTRL_ALT_DEL'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
          {
              Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
              Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
          }

          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
          {
              Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
              Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
          }

          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
          {
              Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
              Name = 'Interactive_logon_Smart_card_removal_behavior'
          }

          SecurityOption 'SecurityRegistry(INF): Devices_Allowed_to_format_and_eject_removable_media'
          {
              Devices_Allowed_to_format_and_eject_removable_media = 'Administrators'
              Name = 'Devices_Allowed_to_format_and_eject_removable_media'
          }

          SecurityOption 'SecurityRegistry(INF): Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
          {
              Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled'
              Name = 'Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
          }

          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_display_last_user_name'
          {
              Interactive_logon_Do_not_display_last_user_name = 'Enabled'
              Name = 'Interactive_logon_Do_not_display_last_user_name'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
          {
              Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
              Name = 'Network_security_LDAP_client_signing_requirements'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
          {
              Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled'
              Name = 'Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
          {
              Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
              Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
          {
              User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent'
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
          {
              Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
              Name = 'Microsoft_network_server_Digitally_sign_communications_always'
          }

          SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
          {
              System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
              Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
          {
              Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
              Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
          }

          SecurityOption 'SecurityRegistry(INF): System_settings_Optional_subsystems'
          {
              System_settings_Optional_subsystems = 'String'
              Name = 'System_settings_Optional_subsystems'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
          {
              User_Account_Control_Only_elevate_executables_that_are_signed_and_validated = 'Disabled'
              Name = 'User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
          }

          SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
          {
              Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
              Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
          }

          SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
          {
              System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
              Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
          }

          SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
          {
              System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
              Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
          }

          SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_access_of_global_system_objects'
          {
              Audit_Audit_the_access_of_global_system_objects = 'Disabled'
              Name = 'Audit_Audit_the_access_of_global_system_objects'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
          {
              Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
              Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
          {
              Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
              Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
          }

          SecurityOption 'SecurityRegistry(INF): Devices_Prevent_users_from_installing_printer_drivers'
          {
              Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'
              Name = 'Devices_Prevent_users_from_installing_printer_drivers'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
          {
              User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
              Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
          {
              Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
              Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
          }

          SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
          {
              Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
              Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
          {
              User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'
              Name = 'User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
          }

          SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
          {
              Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
              Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
          {
              Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
              Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
          }

          SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
          {
              Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
              Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
          }

          SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
          {
              Domain_member_Disable_machine_account_password_changes = 'Disabled'
              Name = 'Domain_member_Disable_machine_account_password_changes'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
          {
              Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
              Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
          }

          SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_use_of_Backup_and_Restore_privilege'
          {
              Audit_Audit_the_use_of_Backup_and_Restore_privilege = 'Disabled'
              Name = 'Audit_Audit_the_use_of_Backup_and_Restore_privilege'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
          {
              Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'
              Name = 'Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
          {
              Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
              Name = 'Microsoft_network_client_Digitally_sign_communications_always'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
          {
              User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Sharing_and_security_model_for_local_accounts'
          {
              Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - Local users authenticate as themselves'
              Name = 'Network_access_Sharing_and_security_model_for_local_accounts'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
          {
              Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
              Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
          }

          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
          {
              Interactive_logon_Machine_inactivity_limit = '900'
              Name = 'Interactive_logon_Machine_inactivity_limit'
          }

          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
          {
              Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
              Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Server_SPN_target_name_validation_level'
          {
              Microsoft_network_server_Server_SPN_target_name_validation_level = 'Off'
              Name = 'Microsoft_network_server_Server_SPN_target_name_validation_level'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
          {
              User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
              Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
          {
              User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
              Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
          }

          SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
          {
              Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
              Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Named_Pipes_that_can_be_accessed_anonymously'
          {
              Network_access_Named_Pipes_that_can_be_accessed_anonymously = 'String'
              Name = 'Network_access_Named_Pipes_that_can_be_accessed_anonymously'
          }

          SecurityOption 'SecurityRegistry(INF): System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
          {
              System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled'
              Name = 'System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
          {
              User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
              Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
          }

          SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
          {
              Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
              Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
          }

          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
          {
              User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
              Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
          {
              Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
              Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
          }

          SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
          {
              Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
              Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths'
          {
              Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion'
              Name = 'Network_access_Remotely_accessible_registry_paths'
          }

          SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
          {
              Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
              Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
          }

          Service 'Services(INF): SCPolicySvc'
          {
              State = 'Running'
              Name = 'SCPolicySvc'
          }

          <#          SecuritySetting 'SecuritySetting(INF): PasswordHistorySize'
          {
              PasswordHistorySize = 24
              Name = 'PasswordHistorySize'
          }

          SecuritySetting 'SecuritySetting(INF): LockoutDuration'
          {
              Name = 'LockoutDuration'
              LockoutDuration = 15
          }

          SecuritySetting 'SecuritySetting(INF): LockoutBadCount'
          {
              Name = 'LockoutBadCount'
              LockoutBadCount = 3
          }

          SecuritySetting 'SecuritySetting(INF): MinimumPasswordAge'
          {
              Name = 'MinimumPasswordAge'
              MinimumPasswordAge = 1
          }

          SecuritySetting 'SecuritySetting(INF): NewGuestName'
          {
              NewGuestName = 'Visitor'
              Name = 'NewGuestName'
          }

          SecuritySetting 'SecuritySetting(INF): ResetLockoutCount'
          {
              ResetLockoutCount = 15
              Name = 'ResetLockoutCount'
          }

          SecuritySetting 'SecuritySetting(INF): ForceLogoffWhenHourExpire'
          {
              Name = 'ForceLogoffWhenHourExpire'
              ForceLogoffWhenHourExpire = 1
          }

          SecuritySetting 'SecuritySetting(INF): EnableGuestAccount'
          {
              EnableGuestAccount = 0
              Name = 'EnableGuestAccount'
          }

          SecuritySetting 'SecuritySetting(INF): MaximumPasswordAge'
          {
              MaximumPasswordAge = 60
              Name = 'MaximumPasswordAge'
          }

          SecuritySetting 'SecuritySetting(INF): MinimumPasswordLength'
          {
              Name = 'MinimumPasswordLength'
              MinimumPasswordLength = 14
          }

          SecuritySetting 'SecuritySetting(INF): PasswordComplexity'
          {
              PasswordComplexity = 1
              Name = 'PasswordComplexity'
          }

          SecuritySetting 'SecuritySetting(INF): ClearTextPassword'
          {
              ClearTextPassword = 0
              Name = 'ClearTextPassword'
          }

          SecuritySetting 'SecuritySetting(INF): NewAdministratorName'
          {
              NewAdministratorName = 'X_Admin'
              Name = 'NewAdministratorName'
          }

          SecuritySetting 'SecuritySetting(INF): LSAAnonymousNameLookup'
          {
              LSAAnonymousNameLookup = 0
              Name = 'LSAAnonymousNameLookup'
          } #>

          UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
          {
              Identity = @('')
              Policy = 'Create_permanent_shared_objects'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Load_and_unload_device_drivers'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
          {
              Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
              Policy = 'Create_global_objects'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Increase_scheduling_priority'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
          {
              Identity = @('')
              Policy = 'Lock_pages_in_memory'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits'
          {
              Identity = @('*S-1-5-19', '*S-1-5-20')
              Policy = 'Generate_security_audits'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
          {
              Identity = @('')
              Policy = 'Act_as_part_of_the_operating_system'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Perform_volume_maintenance_tasks'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
          {
              Identity = @($ADD_YOUR_DOMAIN_ADMINS, $ADD_YOUR_ENTERPRISE_ADMINS, '*S-1-5-32-546', '*S-1-5-113')
              Policy = 'Deny_log_on_through_Remote_Desktop_Services'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Restore_files_and_directories'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
          {
              Identity = @($ADD_YOUR_DOMAIN_ADMINS, $ADD_YOUR_ENTERPRISE_ADMINS, '*S-1-5-32-546')
              Policy = 'Deny_log_on_locally'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
          {
              Identity = @('')
              Policy = 'Access_Credential_Manager_as_a_trusted_caller'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
          {
              Identity = @($ADD_YOUR_DOMAIN_ADMINS, $ADD_YOUR_ENTERPRISE_ADMINS, '*S-1-5-32-546')
              Policy = 'Deny_log_on_as_a_batch_job'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
          {
              Identity = @($ADD_YOUR_DOMAIN_ADMINS, $ADD_YOUR_ENTERPRISE_ADMINS, '*S-1-5-32-546', '*S-1-5-113')
              Policy = 'Deny_access_to_this_computer_from_the_network'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
          {
              Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
              Policy = 'Impersonate_a_client_after_authentication'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
          {
              Identity = @($ADD_YOUR_DOMAIN_ADMINS, $ADD_YOUR_ENTERPRISE_ADMINS)
              Policy = 'Deny_log_on_as_a_service'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Debug_programs'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Modify_firmware_environment_values'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
          {
              Identity = @('*S-1-5-32-544', '*S-1-5-11')
              Policy = 'Access_this_computer_from_the_network'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Profile_single_process'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Create_a_pagefile'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Manage_auditing_and_security_log'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Force_shutdown_from_a_remote_system'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_through_Remote_Desktop_Services'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Allow_log_on_through_Remote_Desktop_Services'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Take_ownership_of_files_or_other_objects'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
          {
              Identity = @('')
              Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Allow_log_on_locally'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
          {
              Identity = @('')
              Policy = 'Create_a_token_object'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Create_symbolic_links'
              Force = $True
          }

          UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
          {
              Identity = @('*S-1-5-32-544')
              Policy = 'Back_up_files_and_directories'
              Force = $True
          }

          RefreshRegistryPolicy 'ActivateClientSideExtension'
          {
             IsSingleInstance = 'Yes'
          }
}
