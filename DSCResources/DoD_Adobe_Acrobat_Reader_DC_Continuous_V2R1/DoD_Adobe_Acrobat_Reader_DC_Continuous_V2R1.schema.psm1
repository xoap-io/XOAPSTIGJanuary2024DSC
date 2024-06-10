configuration DoD_Adobe_Acrobat_Reader_DC_Continuous_V2R1
{


    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
    Import-DSCResource -ModuleName 'AuditPolicyDSC'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Adobe\Acrobat Reader\DC\Installer\DisableMaintenance'
             {
                  ValueName = 'DisableMaintenance'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Adobe\Acrobat Reader\DC\Installer'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnhancedSecurityStandalone'
             {
                  ValueName = 'bEnhancedSecurityStandalone'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bProtectedMode'
             {
                  ValueName = 'bProtectedMode'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\iProtectedView'
             {
                  ValueName = 'iProtectedView'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
                  ValueData = 2
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\iFileAttachmentPerms'
             {
                  ValueName = 'iFileAttachmentPerms'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
                  ValueData = 1
             }


             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Adobe\Acrobat Reader\DC\Installer\DisableMaintenance'
             {
                  ValueName = 'DisableMaintenance'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Adobe\Acrobat Reader\DC\Installer'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnhancedSecurityStandalone'
             {
                  ValueName = 'bEnhancedSecurityStandalone'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bProtectedMode'
             {
                  ValueName = 'bProtectedMode'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\iProtectedView'
             {
                  ValueName = 'iProtectedView'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
                  ValueData = 2
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\iFileAttachmentPerms'
             {
                  ValueName = 'iFileAttachmentPerms'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnableFlash'
             {
                  ValueName = 'bEnableFlash'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
                  ValueData = 0
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bDisablePDFHandlerSwitching'
             {
                  ValueName = 'bDisablePDFHandlerSwitching'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bAcroSuppressUpsell'
             {
                  ValueName = 'bAcroSuppressUpsell'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnhancedSecurityInBrowser'
             {
                  ValueName = 'bEnhancedSecurityInBrowser'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bDisableTrustedFolders'
             {
                  ValueName = 'bDisableTrustedFolders'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bDisableTrustedSites'
             {
                  ValueName = 'bDisableTrustedSites'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cCloud\bAdobeSendPluginToggle'
             {
                  ValueName = 'bAdobeSendPluginToggle'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cCloud'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms\iURLPerms'
             {
                  ValueName = 'iURLPerms'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms\iUnknownURLPerms'
             {
                  ValueName = 'iUnknownURLPerms'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms'
                  ValueData = 3
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bToggleAdobeDocumentServices'
             {
                  ValueName = 'bToggleAdobeDocumentServices'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bTogglePrefsSync'
             {
                  ValueName = 'bTogglePrefsSync'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bToggleWebConnectors'
             {
                  ValueName = 'bToggleWebConnectors'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bToggleAdobeSign'
             {
                  ValueName = 'bToggleAdobeSign'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bUpdater'
             {
                  ValueName = 'bUpdater'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
                  ValueData = 0
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cSharePoint\bDisableSharePointFeatures'
             {
                  ValueName = 'bDisableSharePointFeatures'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cSharePoint'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWebmailProfiles\bDisableWebmail'
             {
                  ValueName = 'bDisableWebmail'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWebmailProfiles'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWelcomeScreen\bShowWelcomeScreen'
             {
                  ValueName = 'bShowWelcomeScreen'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWelcomeScreen'
                  ValueData = 0
             }

             RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer\DisableMaintenance'
             {
                  ValueName = 'DisableMaintenance'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer'
                  ValueData = 1
             }

<#              RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\AVGeneral\bFIPSMode'
             {
                  ValueName = 'bFIPSMode'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\AVGeneral'
                  ValueData = 1
             }

             RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\Security\cDigSig\cAdobeDownload\bLoadSettingsFromURL'
             {
                  ValueName = 'bLoadSettingsFromURL'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\Security\cDigSig\cAdobeDownload'
                  ValueData = 0
             }

             RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\Security\cDigSig\cEUTLDownload\bLoadSettingsFromURL'
             {
                  ValueName = 'bLoadSettingsFromURL'
                  TargetType = 'ComputerConfiguration'
                  ValueType = 'Dword'
                  Key = 'HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\Security\cDigSig\cEUTLDownload'
                  ValueData = 0
             } #>

             RefreshRegistryPolicy 'ActivateClientSideExtension'
             {
                 IsSingleInstance = 'Yes'
             }
}
