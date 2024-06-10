configuration 'DoD_Microsoft_Defender_Antivirus_STIG_v2r4'
{
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
    Import-DSCResource -ModuleName 'AuditPolicyDSC'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'

        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\PUAProtection'
         {
              ValueName = 'PUAProtection'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows Defender'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\DisableAutoExclusions'
         {
              ValueName = 'DisableAutoExclusions'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows Defender\Exclusions'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning'
         {
              ValueName = 'DisableRemovableDriveScanning'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows Defender\Scan'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning'
         {
              ValueName = 'DisableEmailScanning'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows Defender\Scan'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\ScheduleDay'
         {
              ValueName = 'ScheduleDay'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows Defender\Scan'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\ASSignatureDue'
         {
              ValueName = 'ASSignatureDue'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows Defender\Signature Updates'
              ValueData = 7
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\AVSignatureDue'
         {
              ValueName = 'AVSignatureDue'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows Defender\Signature Updates'
              ValueData = 7
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\ScheduleDay'
         {
              ValueName = 'ScheduleDay'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows Defender\Signature Updates'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\DisableBlockAtFirstSeen'
         {
              ValueName = 'DisableBlockAtFirstSeen'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows Defender\Spynet'
              ValueData = 0
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting'
         {
              ValueName = 'SpynetReporting'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows Defender\Spynet'
              ValueData = 2
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent'
         {
              ValueName = 'SubmitSamplesConsent'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows Defender\Spynet'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\Threats_ThreatSeverityDefaultAction'
         {
              ValueName = 'Threats_ThreatSeverityDefaultAction'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows Defender\Threats'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\5'
         {
              ValueName = '5'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
              ValueData = '2'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\4'
         {
              ValueName = '4'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
              ValueData = '2'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\2'
         {
              ValueName = '2'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
              ValueData = '2'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\1'
         {
              ValueName = '1'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
              ValueData = '2'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules'
         {
              ValueName = 'ExploitGuard_ASR_Rules'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
              ValueData = 1
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
         {
              ValueName = 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              ValueData = '1'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
         {
              ValueName = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              ValueData = '1'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\3B576869-A4EC-4529-8536-B80A7769E899'
         {
              ValueName = '3B576869-A4EC-4529-8536-B80A7769E899'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              ValueData = '1'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'
         {
              ValueName = '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              ValueData = '1'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\D3E037E1-3EB8-44C8-A917-57927947596D'
         {
              ValueName = 'D3E037E1-3EB8-44C8-A917-57927947596D'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              ValueData = '1'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'
         {
              ValueName = '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              ValueData = '1'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'
         {
              ValueName = '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
              ValueData = '1'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection'
         {
              ValueName = 'EnableNetworkProtection'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
              ValueData = 1
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
}
