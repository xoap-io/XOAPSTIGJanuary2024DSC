configuration 'DoD_Internet_Explorer_11_v2r5'
{
     Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
     Import-DSCResource -ModuleName 'AuditPolicyDSC'
     Import-DSCResource -ModuleName 'SecurityPolicyDSC'

          <#  RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel\FormSuggest'
          {
              ValueName = 'FormSuggest'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel\FormSuggest Passwords'
          {
              ValueName = 'FormSuggest Passwords'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Internet Explorer\Main\Use FormSuggest'
          {
              ValueName = 'Use FormSuggest'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main'
              ValueData = 'no'
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Internet Explorer\Main\FormSuggest Passwords'
          {
              ValueName = 'FormSuggest Passwords'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main'
              ValueData = 'no'
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Internet Explorer\Main\FormSuggest PW Ask'
          {
              ValueName = 'FormSuggest PW Ask'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main'
              ValueData = 'no'
          }#>

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext\RunThisTimeEnabled'
          {
              ValueName = 'RunThisTimeEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext\VersionCheckEnabled'
          {
              ValueName = 'VersionCheckEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel\History'
          {
              ValueName = 'History'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Control Panel'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Download\RunInvalidSignatures'
          {
              ValueName = 'RunInvalidSignatures'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Download'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Download\CheckExeSignatures'
          {
              ValueName = 'CheckExeSignatures'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Download'
              ValueData = 'yes'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\IEDevTools\Disabled'
          {
              ValueName = 'Disabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Internet Explorer\IEDevTools'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\DisableEPMCompat'
          {
              ValueName = 'DisableEPMCompat'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\Isolation64Bit'
          {
              ValueName = 'Isolation64Bit'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\Isolation'
          {
              ValueName = 'Isolation'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main'
              ValueData = 'PMEM'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\NotifyDisableIEOptions'
          {
              ValueName = 'NotifyDisableIEOptions'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\(Reserved)'
          {
              ValueName = '(Reserved)'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\explorer.exe'
          {
              ValueName = 'explorer.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\iexplore.exe'
          {
              ValueName = 'iexplore.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\(Reserved)'
          {
              ValueName = '(Reserved)'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\explorer.exe'
          {
              ValueName = 'explorer.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\iexplore.exe'
          {
              ValueName = 'iexplore.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\(Reserved)'
          {
              ValueName = '(Reserved)'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\explorer.exe'
          {
              ValueName = 'explorer.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\iexplore.exe'
          {
              ValueName = 'iexplore.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\(Reserved)'
          {
              ValueName = '(Reserved)'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\explorer.exe'
          {
              ValueName = 'explorer.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\iexplore.exe'
          {
              ValueName = 'iexplore.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\(Reserved)'
          {
              ValueName = '(Reserved)'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\explorer.exe'
          {
              ValueName = 'explorer.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\iexplore.exe'
          {
              ValueName = 'iexplore.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\(Reserved)'
          {
              ValueName = '(Reserved)'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\explorer.exe'
          {
              ValueName = 'explorer.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\iexplore.exe'
          {
              ValueName = 'iexplore.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\(Reserved)'
          {
              ValueName = '(Reserved)'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\explorer.exe'
          {
              ValueName = 'explorer.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\iexplore.exe'
          {
              ValueName = 'iexplore.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\(Reserved)'
          {
              ValueName = '(Reserved)'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\explorer.exe'
          {
              ValueName = 'explorer.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\iexplore.exe'
          {
              ValueName = 'iexplore.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
              ValueData = '1'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverride'
          {
              ValueName = 'PreventOverride'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverrideAppRepUnknown'
          {
              ValueName = 'PreventOverrideAppRepUnknown'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\EnabledV9'
          {
              ValueName = 'EnabledV9'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy\ClearBrowsingHistoryOnExit'
          {
              ValueName = 'ClearBrowsingHistoryOnExit'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Privacy'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy\CleanHistory'
          {
              ValueName = 'CleanHistory'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Privacy'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy\EnableInPrivateBrowsing'
          {
              ValueName = 'EnableInPrivateBrowsing'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Privacy'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions\NoCrashDetection'
          {
              ValueName = 'NoCrashDetection'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\DisableSecuritySettingsCheck'
          {
              ValueName = 'DisableSecuritySettingsCheck'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX\BlockNonAdminActiveXInstall'
          {
              ValueName = 'BlockNonAdminActiveXInstall'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Internet Explorer\Security\ActiveX'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_zones_map_edit'
          {
              ValueName = 'Security_zones_map_edit'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_options_edit'
          {
              ValueName = 'Security_options_edit'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_HKLM_only'
          {
              ValueName = 'Security_HKLM_only'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\PreventIgnoreCertErrors'
          {
              ValueName = 'PreventIgnoreCertErrors'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\CertificateRevocation'
          {
              ValueName = 'CertificateRevocation'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\WarnOnBadCertRecving'
          {
              ValueName = 'WarnOnBadCertRecving'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\EnableSSL3Fallback'
          {
              ValueName = 'EnableSSL3Fallback'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\SecureProtocols'
          {
              ValueName = 'SecureProtocols'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
              ValueData = 2048
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0\1C00'
          {
              ValueName = '1C00'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1\1C00'
          {
              ValueName = '1C00'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2\1C00'
          {
              ValueName = '1C00'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4\1C00'
          {
              ValueName = '1C00'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History\DaysToKeep'
          {
              ValueName = 'DaysToKeep'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History'
              ValueData = 40
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\UNCAsIntranet'
          {
              ValueName = 'UNCAsIntranet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\270C'
          {
              ValueName = '270C'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\1C00'
          {
              ValueName = '1C00'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\270C'
          {
              ValueName = '270C'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1201'
          {
              ValueName = '1201'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1C00'
          {
              ValueName = '1C00'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
              ValueData = 65536
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\270C'
          {
              ValueName = '270C'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1201'
          {
              ValueName = '1201'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1C00'
          {
              ValueName = '1C00'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
              ValueData = 65536
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1406'
          {
              ValueName = '1406'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1407'
          {
              ValueName = '1407'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1802'
          {
              ValueName = '1802'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2402'
          {
              ValueName = '2402'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\120b'
          {
              ValueName = '120b'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\120c'
          {
              ValueName = '120c'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1206'
          {
              ValueName = '1206'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2102'
          {
              ValueName = '2102'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1209'
          {
              ValueName = '1209'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2103'
          {
              ValueName = '2103'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2200'
          {
              ValueName = '2200'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\270C'
          {
              ValueName = '270C'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1001'
          {
              ValueName = '1001'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1004'
          {
              ValueName = '1004'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2709'
          {
              ValueName = '2709'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2708'
          {
              ValueName = '2708'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\160A'
          {
              ValueName = '160A'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1201'
          {
              ValueName = '1201'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1C00'
          {
              ValueName = '1C00'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1804'
          {
              ValueName = '1804'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1A00'
          {
              ValueName = '1A00'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 65536
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1607'
          {
              ValueName = '1607'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2004'
          {
              ValueName = '2004'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2001'
          {
              ValueName = '2001'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1806'
          {
              ValueName = '1806'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1409'
          {
              ValueName = '1409'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2500'
          {
              ValueName = '2500'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2301'
          {
              ValueName = '2301'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1809'
          {
              ValueName = '1809'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1606'
          {
              ValueName = '1606'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2101'
          {
              ValueName = '2101'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\140C'
          {
              ValueName = '140C'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1406'
          {
              ValueName = '1406'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1400'
          {
              ValueName = '1400'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2000'
          {
              ValueName = '2000'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1407'
          {
              ValueName = '1407'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1802'
          {
              ValueName = '1802'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1803'
          {
              ValueName = '1803'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2402'
          {
              ValueName = '2402'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1608'
          {
              ValueName = '1608'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\120b'
          {
              ValueName = '120b'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\120c'
          {
              ValueName = '120c'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1206'
          {
              ValueName = '1206'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2102'
          {
              ValueName = '2102'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1209'
          {
              ValueName = '1209'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2103'
          {
              ValueName = '2103'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2200'
          {
              ValueName = '2200'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\270C'
          {
              ValueName = '270C'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1001'
          {
              ValueName = '1001'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1004'
          {
              ValueName = '1004'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2709'
          {
              ValueName = '2709'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2708'
          {
              ValueName = '2708'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\160A'
          {
              ValueName = '160A'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1201'
          {
              ValueName = '1201'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1C00'
          {
              ValueName = '1C00'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1804'
          {
              ValueName = '1804'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1A00'
          {
              ValueName = '1A00'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 196608
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1607'
          {
              ValueName = '1607'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2004'
          {
              ValueName = '2004'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1200'
          {
              ValueName = '1200'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1405'
          {
              ValueName = '1405'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1402'
          {
              ValueName = '1402'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1806'
          {
              ValueName = '1806'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1409'
          {
              ValueName = '1409'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2500'
          {
              ValueName = '2500'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2301'
          {
              ValueName = '2301'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1809'
          {
              ValueName = '1809'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1606'
          {
              ValueName = '1606'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2101'
          {
              ValueName = '2101'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2001'
          {
              ValueName = '2001'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\140C'
          {
              ValueName = '140C'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
              ValueData = 3
          }

          RefreshRegistryPolicy 'ActivateClientSideExtension'
          {
             IsSingleInstance = 'Yes'
          }
}
