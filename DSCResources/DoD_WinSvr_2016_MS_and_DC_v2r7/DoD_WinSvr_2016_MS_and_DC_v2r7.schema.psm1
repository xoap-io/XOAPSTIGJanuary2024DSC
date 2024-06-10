configuration 'DoD_WinSvr_2016_MS_and_DC_v2r7'
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

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
        {
          ValueName = 'NoAutorun'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
        {
          ValueName = 'NoDriveTypeAutoRun'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueData = 255
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

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
        {
          ValueName = 'DisableEnclosureDownload'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Internet Explorer\Feeds'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
        {
          ValueName = 'DCSettingIndex'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
        {
          ValueName = 'ACSettingIndex'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppCompat\DisableInventory'
        {
          ValueName = 'DisableInventory'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\AppCompat'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
        {
          ValueName = 'AllowTelemetry'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\DataCollection'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
        {
          ValueName = 'EnableVirtualizationBasedSecurity'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
        {
          ValueName = 'RequirePlatformSecurityFeatures'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
        {
          ValueName = 'HypervisorEnforcedCodeIntegrity'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
        {
          ValueName = 'LsaCfgFlags'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
          ValueName = 'MaxSize'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\EventLog\Application'
          ValueData = 32768
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
          ValueName = 'MaxSize'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\EventLog\Security'
          ValueData = 196608
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
        {
          ValueName = 'MaxSize'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\EventLog\System'
          ValueData = 32768
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
          ValueName = 'NoAutoplayfornonVolume'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\Explorer'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
        {
          ValueName = 'NoBackgroundPolicy'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
        {
          ValueName = 'NoGPOListChanges'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\EnableUserControl'
        {
          ValueName = 'EnableUserControl'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\Installer'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        {
          ValueName = 'AlwaysInstallElevated'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\Installer'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
        {
          ValueName = 'AllowInsecureGuestAuth'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\LanmanWorkstation'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
        {
          ValueName = '\\*\NETLOGON'
          TargetType = 'ComputerConfiguration'
          ValueType = 'String'
          Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
          ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
        {
          ValueName = '\\*\SYSVOL'
          TargetType = 'ComputerConfiguration'
          ValueType = 'String'
          Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
          ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
        {
          ValueName = 'NoLockScreenSlideshow'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\Personalization'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
        {
          ValueName = 'EnableScriptBlockLogging'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
          ValueData = 1
        }

        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
        {
          ValueName = 'EnableScriptBlockInvocationLogging'
          TargetType = 'ComputerConfiguration'
          Ensure = 'Absent'
          ValueType = 'String'
          Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
          ValueData = ''
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting'
        {
          ValueName = 'EnableTranscripting'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory'
        {
          ValueName = 'OutputDirectory'
          TargetType = 'ComputerConfiguration'
          ValueType = 'String'
          Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
          ValueData = 'C:\ProgramData\PS_Transcript'
        }

        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableInvocationHeader'
        {
          ValueName = 'EnableInvocationHeader'
          TargetType = 'ComputerConfiguration'
          Ensure = 'Absent'
          ValueType = 'String'
          Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
          ValueData = ''
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
        {
          ValueName = 'DontDisplayNetworkSelectionUI'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\System'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnumerateLocalUsers'
        {
          ValueName = 'EnumerateLocalUsers'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\System'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen'
        {
          ValueName = 'EnableSmartScreen'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\System'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
        {
          ValueName = 'AllowIndexingEncryptedStoresOrItems'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\Windows Search'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
          ValueName = 'AllowBasic'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
          ValueName = 'AllowUnencryptedTraffic'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
          ValueName = 'AllowDigest'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
          ValueName = 'AllowBasic'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
        {
          ValueName = 'AllowUnencryptedTraffic'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
        {
          ValueName = 'DisableRunAs'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
        {
          ValueName = 'DisableWebPnPDownload'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows NT\Printers'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
        {
          ValueName = 'DisableHTTPPrinting'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows NT\Printers'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
        {
          ValueName = 'RestrictRemoteClients'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows NT\Rpc'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
        {
          ValueName = 'DisablePasswordSaving'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
          ValueName = 'fDisableCdm'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
          ValueName = 'fPromptForPassword'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
        {
          ValueName = 'fEncryptRPCTraffic'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
        {
          ValueName = 'MinEncryptionLevel'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
          ValueData = 3
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
          ValueName = 'UseLogonCredential'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'System\CurrentControlSet\Control\SecurityProviders\WDigest'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        {
          ValueName = 'SMB1'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'System\CurrentControlSet\Services\LanmanServer\Parameters'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\MrxSmb10\Start'
        {
          ValueName = 'Start'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'System\CurrentControlSet\Services\MrxSmb10'
          ValueData = 4
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
        {
          ValueName = 'NoNameReleaseOnDemand'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'System\CurrentControlSet\Services\Netbt\Parameters'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
        {
          ValueName = 'DisableIPSourceRouting'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
          ValueData = 2
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
        {
          ValueName = 'EnableICMPRedirect'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
          ValueName = 'DisableIPSourceRouting'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'System\CurrentControlSet\Services\Tcpip6\Parameters'
          ValueData = 2
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
        {
          ValueName = 'EnumerateAdministrators'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
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

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
        {
          ValueName = 'NoDriveTypeAutoRun'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueData = 255
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

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
        {
          ValueName = 'DisableEnclosureDownload'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Internet Explorer\Feeds'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
        {
          ValueName = 'DCSettingIndex'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
        {
          ValueName = 'ACSettingIndex'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppCompat\DisableInventory'
        {
          ValueName = 'DisableInventory'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\AppCompat'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
        {
          ValueName = 'AllowTelemetry'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\DataCollection'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
        {
          ValueName = 'EnableVirtualizationBasedSecurity'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
        {
          ValueName = 'RequirePlatformSecurityFeatures'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
        {
          ValueName = 'HypervisorEnforcedCodeIntegrity'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
        {
          ValueName = 'LsaCfgFlags'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
          ValueName = 'MaxSize'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\EventLog\Application'
          ValueData = 32768
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
          ValueName = 'MaxSize'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\EventLog\Security'
          ValueData = 196608
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
        {
          ValueName = 'MaxSize'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\EventLog\System'
          ValueData = 32768
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
          ValueName = 'NoAutoplayfornonVolume'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\Explorer'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
        {
          ValueName = 'NoBackgroundPolicy'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
        {
          ValueName = 'NoGPOListChanges'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\EnableUserControl'
        {
          ValueName = 'EnableUserControl'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\Installer'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        {
          ValueName = 'AlwaysInstallElevated'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\Installer'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
        {
          ValueName = 'AllowInsecureGuestAuth'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\LanmanWorkstation'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
        {
          ValueName = '\\*\NETLOGON'
          TargetType = 'ComputerConfiguration'
          ValueType = 'String'
          Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
          ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
        {
          ValueName = '\\*\SYSVOL'
          TargetType = 'ComputerConfiguration'
          ValueType = 'String'
          Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
          ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
        {
          ValueName = 'NoLockScreenSlideshow'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\Personalization'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
        {
          ValueName = 'EnableScriptBlockLogging'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
          ValueData = 1
        }

        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
        {
          ValueName = 'EnableScriptBlockInvocationLogging'
          TargetType = 'ComputerConfiguration'
          Ensure = 'Absent'
          ValueType = 'String'
          Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
          ValueData = ''
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting'
        {
          ValueName = 'EnableTranscripting'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory'
        {
          ValueName = 'OutputDirectory'
          TargetType = 'ComputerConfiguration'
          ValueType = 'String'
          Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
          ValueData = 'C:\ProgramData\PS_Transcript'
        }

        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableInvocationHeader'
        {
          ValueName = 'EnableInvocationHeader'
          TargetType = 'ComputerConfiguration'
          Ensure = 'Absent'
          ValueType = 'String'
          Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
          ValueData = ''
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
        {
          ValueName = 'DontDisplayNetworkSelectionUI'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\System'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnumerateLocalUsers'
        {
          ValueName = 'EnumerateLocalUsers'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\System'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen'
        {
          ValueName = 'EnableSmartScreen'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\System'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
        {
          ValueName = 'AllowIndexingEncryptedStoresOrItems'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\Windows Search'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
          ValueName = 'AllowBasic'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
          ValueName = 'AllowUnencryptedTraffic'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
          ValueName = 'AllowDigest'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
          ValueName = 'AllowBasic'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
        {
          ValueName = 'AllowUnencryptedTraffic'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
        {
          ValueName = 'DisableRunAs'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
        {
          ValueName = 'DisableWebPnPDownload'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows NT\Printers'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
        {
          ValueName = 'DisableHTTPPrinting'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows NT\Printers'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
        {
          ValueName = 'DisablePasswordSaving'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
          ValueName = 'fDisableCdm'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
          ValueName = 'fPromptForPassword'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
        {
          ValueName = 'fEncryptRPCTraffic'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
        {
          ValueName = 'MinEncryptionLevel'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
          ValueData = 3
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
          ValueName = 'UseLogonCredential'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'System\CurrentControlSet\Control\SecurityProviders\WDigest'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        {
          ValueName = 'SMB1'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'System\CurrentControlSet\Services\LanmanServer\Parameters'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\MrxSmb10\Start'
        {
          ValueName = 'Start'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'System\CurrentControlSet\Services\MrxSmb10'
          ValueData = 4
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
        {
          ValueName = 'NoNameReleaseOnDemand'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'System\CurrentControlSet\Services\Netbt\Parameters'
          ValueData = 1
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
        {
          ValueName = 'DisableIPSourceRouting'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
          ValueData = 2
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
        {
          ValueName = 'EnableICMPRedirect'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
          ValueData = 0
        }

        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
          ValueName = 'DisableIPSourceRouting'
          TargetType = 'ComputerConfiguration'
          ValueType = 'Dword'
          Key = 'System\CurrentControlSet\Services\Tcpip6\Parameters'
          ValueData = 2
        }

        <# RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoReadingPane'
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

        RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPreviewPane'
        {
          ValueName = 'NoPreviewPane'
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

        AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
        {
          AuditFlag = 'Success'
          Ensure = 'Present'
          Name = 'Plug and Play Events'
        }

        AuditPolicySubcategory 'Audit PNP Activity (Failure) - Inclusion'
        {
          AuditFlag = 'Failure'
          Ensure = 'Absent'
          Name = 'Plug and Play Events'
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

        AuditPolicySubcategory 'Audit Group Membership (Success) - Inclusion'
        {
          AuditFlag = 'Success'
          Ensure = 'Present'
          Name = 'Group Membership'
        }

        AuditPolicySubcategory 'Audit Group Membership (Failure) - Inclusion'
        {
          AuditFlag = 'Failure'
          Ensure = 'Absent'
          Name = 'Group Membership'
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

        AuditPolicySubcategory 'Audit Other Object Access Events (Success) - Inclusion'
        {
          AuditFlag = 'Success'
          Ensure = 'Present'
          Name = 'Other Object Access Events'
        }

        AuditPolicySubcategory 'Audit Other Object Access Events (Failure) - Inclusion'
        {
          AuditFlag = 'Failure'
          Ensure = 'Present'
          Name = 'Other Object Access Events'
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

        AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
        {
          AuditFlag = 'Success'
          Ensure = 'Present'
          Name = 'Plug and Play Events'
        }

        AuditPolicySubcategory 'Audit PNP Activity (Failure) - Inclusion'
        {
          AuditFlag = 'Failure'
          Ensure = 'Absent'
          Name = 'Plug and Play Events'
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

        AuditPolicySubcategory 'Audit Group Membership (Success) - Inclusion'
        {
          AuditFlag = 'Success'
          Ensure = 'Present'
          Name = 'Group Membership'
        }

        AuditPolicySubcategory 'Audit Group Membership (Failure) - Inclusion'
        {
          AuditFlag = 'Failure'
          Ensure = 'Absent'
          Name = 'Group Membership'
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

        AuditPolicySubcategory 'Audit Other Object Access Events (Success) - Inclusion'
        {
          AuditFlag = 'Success'
          Ensure = 'Present'
          Name = 'Other Object Access Events'
        }

        AuditPolicySubcategory 'Audit Other Object Access Events (Failure) - Inclusion'
        {
          AuditFlag = 'Failure'
          Ensure = 'Present'
          Name = 'Other Object Access Events'
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

        SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
        {
          Domain_member_Maximum_machine_account_password_age = '30'
          Name = 'Domain_member_Maximum_machine_account_password_age'
        }

        <#          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
        {
          Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.,By using this IS (which includes any device attached to this IS)"," you consent to the following conditions:,-The USG routinely intercepts and monitors communications on this IS for purposes including"," but not limited to"," penetration testing"," COMSEC monitoring"," network operations and defense"," personnel misconduct (PM)"," law enforcement (LE)"," and counterintelligence (CI) investigations.,-At any time"," the USG may inspect and seize data stored on this IS.,-Communications using"," or data stored on"," this IS are not private"," are subject to routine monitoring"," interception"," and search"," and may be disclosed or used for any USG-authorized purpose.,-This IS includes security measures (e.g."," authentication and access controls) to protect USG interests--not for your personal benefit or privacy.,-Notwithstanding the above"," using this IS does not constitute consent to PM"," LE or CI investigative searching or monitoring of the content of privileged communications"," or work product"," related to personal representation or services by attorneys"," psychotherapists"," or clergy"," and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
          Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
        } #>

        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
          System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
          Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        }

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
          User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
          Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
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

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
          User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
          Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        }

        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
          Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
          Name = 'Network_security_LDAP_client_signing_requirements'
        }

        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
        {
          Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
          Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
        }

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
          User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
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

        SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
          Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
          Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        }

        SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
        {
          System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
          Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
        }

        SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
          Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
          Name = 'Network_security_LAN_Manager_authentication_level'
        }

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
          User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
          Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        }

        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
        {
        Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = @(
            MSFT_RestrictedRemoteSamSecurityDescriptor
            {
                Permission = 'Allow'
                Identity   = 'Administrators'
             }
        )
          Name = 'Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
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

        SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        {
          Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
          Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        }

        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
          Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
          Name = 'Microsoft_network_client_Digitally_sign_communications_always'
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

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
          User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
          Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
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

        SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        {
          Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
          Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        }

        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
          Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
          Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        }

        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
          Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
          Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
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

        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        {
          Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
          Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        }

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

        UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
        {
          Identity = @('*S-1-5-32-544')
          Policy = 'Perform_volume_maintenance_tasks'
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

        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
        {
          Identity = @('*S-1-5-113', '*S-1-5-32-546', $ADD_YOUR_ENTERPRISE_ADMINS, $ADD_YOUR_DOMAIN_ADMINS)
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
          Identity = @('*S-1-5-32-546', $ADD_YOUR_ENTERPRISE_ADMINS, $ADD_YOUR_DOMAIN_ADMINS)
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
          Identity = @('*S-1-5-32-546', $ADD_YOUR_ENTERPRISE_ADMINS, $ADD_YOUR_DOMAIN_ADMINS)
          Policy = 'Deny_log_on_as_a_batch_job'
          Force = $True
        }

        UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
        {
          Identity = @('*S-1-5-113', '*S-1-5-32-546', $ADD_YOUR_ENTERPRISE_ADMINS, $ADD_YOUR_DOMAIN_ADMINS)
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
          Identity = @($ADD_YOUR_ENTERPRISE_ADMINS, $ADD_YOUR_DOMAIN_ADMINS)
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
          Identity = @('*S-1-5-11', '*S-1-5-32-544')
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

        UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
        {
          Identity = @('*S-1-5-32-544')
          Policy = 'Increase_scheduling_priority'
          Force = $True
        }

        <# SecuritySetting 'SecuritySetting(INF): PasswordHistorySize'
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

        SecuritySetting 'SecuritySetting(INF): LSAAnonymousNameLookup'
        {
          LSAAnonymousNameLookup = 0
          Name = 'LSAAnonymousNameLookup'
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
        #>
        SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
        {
          Domain_member_Maximum_machine_account_password_age = '30'
          Name = 'Domain_member_Maximum_machine_account_password_age'
        }

        <#          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
        {
          Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.,By using this IS (which includes any device attached to this IS)"," you consent to the following conditions:,-The USG routinely intercepts and monitors communications on this IS for purposes including"," but not limited to"," penetration testing"," COMSEC monitoring"," network operations and defense"," personnel misconduct (PM)"," law enforcement (LE)"," and counterintelligence (CI) investigations.,-At any time"," the USG may inspect and seize data stored on this IS.,-Communications using"," or data stored on"," this IS are not private"," are subject to routine monitoring"," interception"," and search"," and may be disclosed or used for any USG-authorized purpose.,-This IS includes security measures (e.g."," authentication and access controls) to protect USG interests--not for your personal benefit or privacy.,-Notwithstanding the above"," using this IS does not constitute consent to PM"," LE or CI investigative searching or monitoring of the content of privileged communications"," or work product"," related to personal representation or services by attorneys"," psychotherapists"," or clergy"," and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
          Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
        } #>

        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
          System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
          Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        }

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
          User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
          Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        }

        SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
          Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
          Name = 'Network_security_LAN_Manager_authentication_level'
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

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
          User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
          Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        }

        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
          Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
          Name = 'Network_security_LDAP_client_signing_requirements'
        }

        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
        {
          Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
          Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
        }

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
          User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
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

        SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        {
          Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
          Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        }

        SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
        {
          System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
          Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
        }

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
          User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
          Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
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

        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
          Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
          Name = 'Microsoft_network_client_Digitally_sign_communications_always'
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

        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
          User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
          Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
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

        SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        {
          Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
          Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        }

        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
          Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
          Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        }

        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
          Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
          Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
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

        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        {
          Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
          Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        }

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

        UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
        {
          Identity = @('*S-1-5-32-544')
          Policy = 'Perform_volume_maintenance_tasks'
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
          Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
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

        UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
        {
          Identity = @('*S-1-5-32-544')
          Policy = 'Increase_scheduling_priority'
          Force = $True
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
         IsSingleInstance = 'Yes'
        }
}
