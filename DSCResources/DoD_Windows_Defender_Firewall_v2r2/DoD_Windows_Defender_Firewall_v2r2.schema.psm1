configuration 'DoD_Windows_Defender_Firewall_v2r2'
{
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
    Import-DSCResource -ModuleName 'AuditPolicyDSC'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PolicyVersion'
          {
              ValueName = 'PolicyVersion'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall'
              ValueData = 539
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
          {
              ValueName = 'EnableFirewall'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
          {
              ValueName = 'DefaultOutboundAction'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction'
          {
              ValueName = 'DefaultInboundAction'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize'
          {
              ValueName = 'LogFileSize'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
              ValueData = 16384
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets'
          {
              ValueName = 'LogDroppedPackets'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections'
          {
              ValueName = 'LogSuccessfulConnections'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall'
          {
              ValueName = 'EnableFirewall'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction'
          {
              ValueName = 'DefaultOutboundAction'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction'
          {
              ValueName = 'DefaultInboundAction'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize'
          {
              ValueName = 'LogFileSize'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
              ValueData = 16384
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets'
          {
              ValueName = 'LogDroppedPackets'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections'
          {
              ValueName = 'LogSuccessfulConnections'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall'
          {
              ValueName = 'EnableFirewall'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction'
          {
              ValueName = 'DefaultOutboundAction'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction'
          {
              ValueName = 'DefaultInboundAction'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge'
          {
              ValueName = 'AllowLocalPolicyMerge'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge'
          {
              ValueName = 'AllowLocalIPsecPolicyMerge'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize'
          {
              ValueName = 'LogFileSize'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
              ValueData = 16384
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets'
          {
              ValueName = 'LogDroppedPackets'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections'
          {
              ValueName = 'LogSuccessfulConnections'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
              ValueData = 1
          }

          RefreshRegistryPolicy 'ActivateClientSideExtension'
          {
             IsSingleInstance = 'Yes'
          }
}
