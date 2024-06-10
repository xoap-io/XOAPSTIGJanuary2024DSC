configuration DoD_Mozilla_Firefox_v6r5
{
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
    Import-DSCResource -ModuleName 'AuditPolicyDSC'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SSLVersionMin'
         {
              ValueName = 'SSLVersionMin'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Mozilla\Firefox'
              ValueData = 'tls1.2'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\ExtensionUpdate'
         {
              ValueName = 'ExtensionUpdate'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFormHistory'
         {
              ValueName = 'DisableFormHistory'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PasswordManagerEnabled'
         {
              ValueName = 'PasswordManagerEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableTelemetry'
         {
              ValueName = 'DisableTelemetry'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableDeveloperTools'
         {
              ValueName = 'DisableDeveloperTools'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableForgetButton'
         {
              ValueName = 'DisableForgetButton'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisablePrivateBrowsing'
         {
              ValueName = 'DisablePrivateBrowsing'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SearchSuggestEnabled'
         {
              ValueName = 'SearchSuggestEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\NetworkPrediction'
         {
              ValueName = 'NetworkPrediction'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFirefoxAccounts'
         {
              ValueName = 'DisableFirefoxAccounts'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFeedbackCommands'
         {
              ValueName = 'DisableFeedbackCommands'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\Preferences'
         {
              ValueName = 'Preferences'
              TargetType = 'ComputerConfiguration'
              ValueType = 'MultiString'
              Key = 'Software\Policies\Mozilla\Firefox'
              ValueData = '{  "security.default_personal_cert": {    "Value": "Ask Every Time",    "Status": "locked"  },  "browser.search.update": {    "Value": false,    "Status": "locked"  },  "dom.disable_window_move_resize": {    "Value": true,    "Status": "locked"  },  "dom.disable_window_flip": {    "Value": true,    "Status": "locked"  },   "browser.contentblocking.category": {    "Value": "strict",    "Status": "locked"  },  "extensions.htmlaboutaddons.recommendations.enabled": {    "Value": false,    "Status": "locked"  }}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisablePocket'
         {
              ValueName = 'DisablePocket'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFirefoxStudies'
         {
              ValueName = 'DisableFirefoxStudies'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\Certificates\ImportEnterpriseRoots'
         {
              ValueName = 'ImportEnterpriseRoots'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\Certificates'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisabledCiphers\TLS_RSA_WITH_3DES_EDE_CBC_SHA'
         {
              ValueName = 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\DisabledCiphers'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection\Fingerprinting'
         {
              ValueName = 'Fingerprinting'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\EnableTrackingProtection'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection\Cryptomining'
         {
              ValueName = 'Cryptomining'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\EnableTrackingProtection'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions\Enabled'
         {
              ValueName = 'Enabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions\Locked'
         {
              ValueName = 'Locked'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Search'
         {
              ValueName = 'Search'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\TopSites'
         {
              ValueName = 'TopSites'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\SponsoredTopSites'
         {
              ValueName = 'SponsoredTopSites'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Highlights'
         {
              ValueName = 'Highlights'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Pocket'
         {
              ValueName = 'Pocket'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\SponsoredPocket'
         {
              ValueName = 'SponsoredPocket'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Snippets'
         {
              ValueName = 'Snippets'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Locked'
         {
              ValueName = 'Locked'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\InstallAddonsPermission\Default'
         {
              ValueName = 'Default'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\InstallAddonsPermission'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\Permissions\Autoplay\Default'
         {
              ValueName = 'Default'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Mozilla\Firefox\Permissions\Autoplay'
              ValueData = 'block-audio-video'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Default'
         {
              ValueName = 'Default'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Locked'
         {
              ValueName = 'Locked'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking'
              ValueData = 1
         }

         RegistryPolicyFile 'DELVALS_\Software\Policies\Mozilla\Firefox\PopupBlocking\Allow'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'

              Ensure = 'Present'
              ValueType = 'String'
              Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking\Allow'
              ValueData = ''
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Allow\1'
         {
              ValueName = '1'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking\Allow'
              ValueData = '.mil'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Allow\2'
         {
              ValueName = '2'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking\Allow'
              ValueData = '.gov'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Cache'
         {
              ValueName = 'Cache'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Cookies'
         {
              ValueName = 'Cookies'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Downloads'
         {
              ValueName = 'Downloads'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\FormData'
         {
              ValueName = 'FormData'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\History'
         {
              ValueName = 'History'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Sessions'
         {
              ValueName = 'Sessions'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\SiteSettings'
         {
              ValueName = 'SiteSettings'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\OfflineApps'
         {
              ValueName = 'OfflineApps'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Locked'
         {
              ValueName = 'Locked'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\UserMessaging\ExtensionRecommendations'
         {
              ValueName = 'ExtensionRecommendations'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Mozilla\Firefox\UserMessaging'
              ValueData = 0
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }


}
