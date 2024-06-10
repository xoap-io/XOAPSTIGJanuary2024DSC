configuration 'DoD_Google_Chrome_v2r8'
{
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
    Import-DSCResource -ModuleName 'AuditPolicyDSC'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\RemoteAccessHostFirewallTraversal'
         {
              ValueName = 'RemoteAccessHostFirewallTraversal'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultPopupsSetting'
         {
              ValueName = 'DefaultPopupsSetting'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 2
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultGeolocationSetting'
         {
              ValueName = 'DefaultGeolocationSetting'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 2
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderName'
         {
              ValueName = 'DefaultSearchProviderName'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 'Google Encrypted'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderEnabled'
         {
              ValueName = 'DefaultSearchProviderEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\PasswordManagerEnabled'
         {
              ValueName = 'PasswordManagerEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\BackgroundModeEnabled'
         {
              ValueName = 'BackgroundModeEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SyncDisabled'
         {
              ValueName = 'SyncDisabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\CloudPrintProxyEnabled'
         {
              ValueName = 'CloudPrintProxyEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\MetricsReportingEnabled'
         {
              ValueName = 'MetricsReportingEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SearchSuggestEnabled'
         {
              ValueName = 'SearchSuggestEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ImportSavedPasswords'
         {
              ValueName = 'ImportSavedPasswords'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\IncognitoModeAvailability'
         {
              ValueName = 'IncognitoModeAvailability'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SavingBrowserHistoryDisabled'
         {
              ValueName = 'SavingBrowserHistoryDisabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AllowDeletingBrowserHistory'
         {
              ValueName = 'AllowDeletingBrowserHistory'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\PromptForDownloadLocation'
         {
              ValueName = 'PromptForDownloadLocation'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowed'
         {
              ValueName = 'AutoplayAllowed'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SafeBrowsingExtendedReportingEnabled'
         {
              ValueName = 'SafeBrowsingExtendedReportingEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultWebUsbGuardSetting'
         {
              ValueName = 'DefaultWebUsbGuardSetting'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 2
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ChromeCleanupEnabled'
         {
              ValueName = 'ChromeCleanupEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ChromeCleanupReportingEnabled'
         {
              ValueName = 'ChromeCleanupReportingEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\EnableMediaRouter'
         {
              ValueName = 'EnableMediaRouter'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\UrlKeyedAnonymizedDataCollectionEnabled'
         {
              ValueName = 'UrlKeyedAnonymizedDataCollectionEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\WebRtcEventLogCollectionAllowed'
         {
              ValueName = 'WebRtcEventLogCollectionAllowed'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\NetworkPredictionOptions'
         {
              ValueName = 'NetworkPredictionOptions'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 2
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DeveloperToolsAvailability'
         {
              ValueName = 'DeveloperToolsAvailability'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 2
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\BrowserGuestModeEnabled'
         {
              ValueName = 'BrowserGuestModeEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutofillCreditCardEnabled'
         {
              ValueName = 'AutofillCreditCardEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutofillAddressEnabled'
         {
              ValueName = 'AutofillAddressEnabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ImportAutofillFormData'
         {
              ValueName = 'ImportAutofillFormData'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SafeBrowsingProtectionLevel'
         {
              ValueName = 'SafeBrowsingProtectionLevel'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderSearchURL'
         {
              ValueName = 'DefaultSearchProviderSearchURL'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 'https://www.google.com/search?q={searchTerms}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DownloadRestrictions'
         {
              ValueName = 'DownloadRestrictions'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultWebBluetoothGuardSetting'
         {
              ValueName = 'DefaultWebBluetoothGuardSetting'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 2
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\QuicAllowed'
         {
              ValueName = 'QuicAllowed'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\EnableOnlineRevocationChecks'
         {
              ValueName = 'EnableOnlineRevocationChecks'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SSLVersionMin'
         {
              ValueName = 'SSLVersionMin'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Google\Chrome'
              ValueData = 'tls1.2'
         }

         RegistryPolicyFile 'DELVALS_\Software\Policies\Google\Chrome\AutoplayAllowlist'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'

              Ensure = 'Present'
              ValueType = 'String'
              Key = 'Software\Policies\Google\Chrome\AutoplayAllowlist'
              ValueData = ''
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowlist\1'
         {
              ValueName = '1'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Google\Chrome\AutoplayAllowlist'
              ValueData = '[*.]mil'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowlist\2'
         {
              ValueName = '2'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Google\Chrome\AutoplayAllowlist'
              ValueData = '[*.]gov'
         }

         RegistryPolicyFile 'DELVALS_\Software\Policies\Google\Chrome\CookiesSessionOnlyForUrls'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'

              Ensure = 'Present'
              ValueType = 'String'
              Key = 'Software\Policies\Google\Chrome\CookiesSessionOnlyForUrls'
              ValueData = ''
         }

         RegistryPolicyFile 'DELVALS_\Software\Policies\Google\Chrome\ExtensionInstallAllowlist'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'

              Ensure = 'Present'
              ValueType = 'String'
              Key = 'Software\Policies\Google\Chrome\ExtensionInstallAllowlist'
              ValueData = ''
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ExtensionInstallAllowlist\1'
         {
              ValueName = '1'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Google\Chrome\ExtensionInstallAllowlist'
              ValueData = 'oiigbmnaadbkfbmpbfijlflahbdbdgdf'
         }

         RegistryPolicyFile 'DELVALS_\Software\Policies\Google\Chrome\ExtensionInstallBlocklist'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'

              Ensure = 'Present'
              ValueType = 'String'
              Key = 'Software\Policies\Google\Chrome\ExtensionInstallBlocklist'
              ValueData = ''
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ExtensionInstallBlocklist\1'
         {
              ValueName = '1'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Google\Chrome\ExtensionInstallBlocklist'
              ValueData = '*'
         }

         RegistryPolicyFile 'DELVALS_\Software\Policies\Google\Chrome\URLBlocklist'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'

              Ensure = 'Present'
              ValueType = 'String'
              Key = 'Software\Policies\Google\Chrome\URLBlocklist'
              ValueData = ''
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\URLBlocklist\1'
         {
              ValueName = '1'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Google\Chrome\URLBlocklist'
              ValueData = 'javascript://*'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
}
