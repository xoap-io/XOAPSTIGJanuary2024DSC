configuration 'DoD_Microsoft_Edge_v1r7'
{
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
    Import-DSCResource -ModuleName 'AuditPolicyDSC'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SSLVersionMin'
        {
            ValueName = 'SSLVersionMin'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 'tls1.2'
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SyncDisabled'
       {
            ValueName = 'SyncDisabled'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 1
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportBrowserSettings'
       {
            ValueName = 'ImportBrowserSettings'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DeveloperToolsAvailability'
       {
            ValueName = 'DeveloperToolsAvailability'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 2
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PromptForDownloadLocation'
       {
            ValueName = 'PromptForDownloadLocation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 1
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverride'
       {
            ValueName = 'PreventSmartScreenPromptOverride'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 1
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverrideForFiles'
       {
            ValueName = 'PreventSmartScreenPromptOverrideForFiles'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 1
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\InPrivateModeAvailability'
       {
            ValueName = 'InPrivateModeAvailability'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 1
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AllowDeletingBrowserHistory'
       {
            ValueName = 'AllowDeletingBrowserHistory'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BackgroundModeEnabled'
       {
            ValueName = 'BackgroundModeEnabled'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultPopupsSetting'
       {
            ValueName = 'DefaultPopupsSetting'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 2
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\NetworkPredictionOptions'
       {
            ValueName = 'NetworkPredictionOptions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 2
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SearchSuggestEnabled'
       {
            ValueName = 'SearchSuggestEnabled'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportAutofillFormData'
       {
            ValueName = 'ImportAutofillFormData'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportCookies'
       {
            ValueName = 'ImportCookies'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportExtensions'
       {
            ValueName = 'ImportExtensions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportHistory'
       {
            ValueName = 'ImportHistory'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportHomepage'
       {
            ValueName = 'ImportHomepage'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportOpenTabs'
       {
            ValueName = 'ImportOpenTabs'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportPaymentInfo'
       {
            ValueName = 'ImportPaymentInfo'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportSavedPasswords'
       {
            ValueName = 'ImportSavedPasswords'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportSearchEngine'
       {
            ValueName = 'ImportSearchEngine'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportShortcuts'
       {
            ValueName = 'ImportShortcuts'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowed'
       {
            ValueName = 'AutoplayAllowed'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EnableMediaRouter'
       {
            ValueName = 'EnableMediaRouter'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutofillCreditCardEnabled'
       {
            ValueName = 'AutofillCreditCardEnabled'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutofillAddressEnabled'
       {
            ValueName = 'AutofillAddressEnabled'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PersonalizationReportingEnabled'
       {
            ValueName = 'PersonalizationReportingEnabled'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultGeolocationSetting'
       {
            ValueName = 'DefaultGeolocationSetting'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 2
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PasswordManagerEnabled'
       {
            ValueName = 'PasswordManagerEnabled'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }




       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\IsolateOrigins'
       {
            ValueName = 'IsolateOrigins'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = $null
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SmartScreenEnabled'
       {
            ValueName = 'SmartScreenEnabled'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 1
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SmartScreenPuaEnabled'
       {
            ValueName = 'SmartScreenPuaEnabled'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 1
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PaymentMethodQueryEnabled'
       {
            ValueName = 'PaymentMethodQueryEnabled'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AlternateErrorPagesEnabled'
       {
            ValueName = 'AlternateErrorPagesEnabled'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\UserFeedbackAllowed'
       {
            ValueName = 'UserFeedbackAllowed'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EdgeCollectionsEnabled'
       {
            ValueName = 'EdgeCollectionsEnabled'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ConfigureShare'
       {
            ValueName = 'ConfigureShare'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 1
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BrowserGuestModeEnabled'
       {
            ValueName = 'BrowserGuestModeEnabled'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BuiltInDnsClientEnabled'
       {
            ValueName = 'BuiltInDnsClientEnabled'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SitePerProcess'
       {
            ValueName = 'SitePerProcess'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 1
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ManagedSearchEngines'
       {
            ValueName = 'ManagedSearchEngines'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = '[{"allow_search_engine_discovery": false},{"is_default": true,"name": "Microsoft Bing","keyword": "bing","search_url": "https://www.bing.com/search?q={searchTerms}"},{"name": "Google","keyword": "google","search_url": "https://www.google.com/search?q={searchTerms}"}]'
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AuthSchemes'
       {
            ValueName = 'AuthSchemes'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 'ntlm,negotiate'
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultWebUsbGuardSetting'
       {
            ValueName = 'DefaultWebUsbGuardSetting'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 2
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultWebBluetoothGuardSetting'
       {
            ValueName = 'DefaultWebBluetoothGuardSetting'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 2
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\TrackingPrevention'
       {
            ValueName = 'TrackingPrevention'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 2
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\RelaunchNotification'
       {
            ValueName = 'RelaunchNotification'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 2
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ProxySettings'
       {
            ValueName = 'ProxySettings'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 'ADD YOUR PROXY CONFIGURATIONS HERE'
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EnableOnlineRevocationChecks'
       {
            ValueName = 'EnableOnlineRevocationChecks'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 1
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\QuicAllowed'
       {
            ValueName = 'QuicAllowed'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 0
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DownloadRestrictions'
       {
            ValueName = 'DownloadRestrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            Key = 'Software\Policies\Microsoft\Edge'
            ValueData = 1
       }

       RegistryPolicyFile 'DELVALS_\Software\Policies\Microsoft\Edge\AutoplayAllowlist'
       {
            ValueName = ''
            TargetType = 'ComputerConfiguration'

            Ensure = 'Present'
            ValueType = 'String'
            Key = 'Software\Policies\Microsoft\Edge\AutoplayAllowlist'
            ValueData = ''
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowlist\1'
       {
            ValueName = '1'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            Key = 'Software\Policies\Microsoft\Edge\AutoplayAllowlist'
            ValueData = '[*.]gov'
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowlist\2'
       {
            ValueName = '2'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            Key = 'Software\Policies\Microsoft\Edge\AutoplayAllowlist'
            ValueData = '[*.]mil'
       }

       RegistryPolicyFile 'DELVALS_\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
       {
            ValueName = ''
            TargetType = 'ComputerConfiguration'

            Ensure = 'Present'
            ValueType = 'String'
            Key = 'Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
            ValueData = ''
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist\1'
       {
            ValueName = '1'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            Key = 'Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
            ValueData = '*'
       }

       RegistryPolicyFile 'DELVALS_\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
       {
            ValueName = ''
            TargetType = 'ComputerConfiguration'

            Ensure = 'Present'
            ValueType = 'String'
            Key = 'Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
            ValueData = ''
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls\1'
       {
            ValueName = '1'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            Key = 'Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
            ValueData = '[*.]mil'
       }

       RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls\2'
       {
            ValueName = '2'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            Key = 'Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
            ValueData = '[*.]gov'
       }

       RefreshRegistryPolicy 'ActivateClientSideExtension'
       {
           IsSingleInstance = 'Yes'
       }
}
