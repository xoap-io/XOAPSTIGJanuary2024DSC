configuration 'DoD_Office_2019-M365_Apps_v2r11'
{
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
    Import-DSCResource -ModuleName 'AuditPolicyDSC'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
          {
              ValueName = 'ActivationFilterOverride'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
          {
              ValueName = 'Compatibility Flags'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
          {
              ValueName = 'ActivationFilterOverride'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
          {
              ValueName = 'Compatibility Flags'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\Comment'
          {
              ValueName = 'Comment'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'software\microsoft\Office\Common\COM Compatibility'
              ValueData = 'Block all Flash activation'
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
          {
              ValueName = 'ActivationFilterOverride'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
          {
              ValueName = 'Compatibility Flags'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
          {
              ValueName = 'ActivationFilterOverride'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
          {
              ValueName = 'Compatibility Flags'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\enablesiphighsecuritymode'
          {
              ValueName = 'enablesiphighsecuritymode'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\policies\microsoft\office\16.0\lync'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\disablehttpconnect'
          {
              ValueName = 'disablehttpconnect'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\policies\microsoft\office\16.0\lync'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
          {
              ValueName = 'ActivationFilterOverride'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
          {
              ValueName = 'Compatibility Flags'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
          {
              ValueName = 'ActivationFilterOverride'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
          {
              ValueName = 'Compatibility Flags'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
          {
              ValueName = 'ActivationFilterOverride'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
          {
              ValueName = 'Compatibility Flags'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
          {
              ValueName = 'ActivationFilterOverride'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
          {
              ValueName = 'Compatibility Flags'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueData = 1024
          }

          <# RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\blockcontentexecutionfrominternet'
          {
              ValueName = 'blockcontentexecutionfrominternet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\notbpromptunsignedaddin'
          {
              ValueName = 'notbpromptunsignedaddin'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\vbawarnings'
          {
              ValueName = 'vbawarnings'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\trusted locations\allownetworklocations'
          {
              ValueName = 'allownetworklocations'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security\trusted locations'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\portal\linkpublishingdisabled'
          {
              ValueName = 'linkpublishingdisabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\portal'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\macroruntimescanscope'
          {
              ValueName = 'macroruntimescanscope'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\drmencryptproperty'
          {
              ValueName = 'drmencryptproperty'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\defaultencryption12'
          {
              ValueName = 'defaultencryption12'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\openxmlencryption'
          {
              ValueName = 'openxmlencryption'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations\allow user locations'
          {
              ValueName = 'allow user locations'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\access\noextensibilitycustomizationfromdocument'
          {
              ValueName = 'noextensibilitycustomizationfromdocument'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\access'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\excel\noextensibilitycustomizationfromdocument'
          {
              ValueName = 'noextensibilitycustomizationfromdocument'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\excel'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\infopath\noextensibilitycustomizationfromdocument'
          {
              ValueName = 'noextensibilitycustomizationfromdocument'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\infopath'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\outlook\noextensibilitycustomizationfromdocument'
          {
              ValueName = 'noextensibilitycustomizationfromdocument'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\outlook'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\powerpoint\noextensibilitycustomizationfromdocument'
          {
              ValueName = 'noextensibilitycustomizationfromdocument'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\powerpoint'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\project\noextensibilitycustomizationfromdocument'
          {
              ValueName = 'noextensibilitycustomizationfromdocument'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\project'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\publisher\noextensibilitycustomizationfromdocument'
          {
              ValueName = 'noextensibilitycustomizationfromdocument'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\publisher'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\visio\noextensibilitycustomizationfromdocument'
          {
              ValueName = 'noextensibilitycustomizationfromdocument'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\visio'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\word\noextensibilitycustomizationfromdocument'
          {
              ValueName = 'noextensibilitycustomizationfromdocument'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\word'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\trustcenter\trustbar'
          {
              ValueName = 'trustbar'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\trustcenter'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\internet\donotloadpictures'
          {
              ValueName = 'donotloadpictures'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\internet'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\extractdatadisableui'
          {
              ValueName = 'extractdatadisableui'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\disableautorepublish'
          {
              ValueName = 'disableautorepublish'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\disableautorepublishwarning'
          {
              ValueName = 'disableautorepublishwarning'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions\fupdateext_78_1'
          {
              ValueName = 'fupdateext_78_1'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\vbawarnings'
          {
              ValueName = 'vbawarnings'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\extensionhardening'
          {
              ValueName = 'extensionhardening'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\excelbypassencryptedmacroscan'
          {
              ValueName = 'excelbypassencryptedmacroscan'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\webservicefunctionwarnings'
          {
              ValueName = 'webservicefunctionwarnings'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\blockcontentexecutionfrominternet'
          {
              ValueName = 'blockcontentexecutionfrominternet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\notbpromptunsignedaddin'
          {
              ValueName = 'notbpromptunsignedaddin'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\external content\disableddeserverlaunch'
          {
              ValueName = 'disableddeserverlaunch'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\external content'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\external content\disableddeserverlookup'
          {
              ValueName = 'disableddeserverlookup'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\external content'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\external content\enableblockunsecurequeryfiles'
          {
              ValueName = 'enableblockunsecurequeryfiles'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\external content'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\dbasefiles'
          {
              ValueName = 'dbasefiles'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\difandsylkfiles'
          {
              ValueName = 'difandsylkfiles'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl2macros'
          {
              ValueName = 'xl2macros'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl2worksheets'
          {
              ValueName = 'xl2worksheets'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl3macros'
          {
              ValueName = 'xl3macros'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl3worksheets'
          {
              ValueName = 'xl3worksheets'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4macros'
          {
              ValueName = 'xl4macros'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4workbooks'
          {
              ValueName = 'xl4workbooks'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4worksheets'
          {
              ValueName = 'xl4worksheets'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl95workbooks'
          {
              ValueName = 'xl95workbooks'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl9597workbooksandtemplates'
          {
              ValueName = 'xl9597workbooksandtemplates'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\openinprotectedview'
          {
              ValueName = 'openinprotectedview'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\htmlandxmlssfiles'
          {
              ValueName = 'htmlandxmlssfiles'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\enableonload'
          {
              ValueName = 'enableonload'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\openinprotectedview'
          {
              ValueName = 'openinprotectedview'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\disableeditfrompv'
          {
              ValueName = 'disableeditfrompv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\enabledatabasefileprotectedview'
          {
              ValueName = 'enabledatabasefileprotectedview'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableinternetfilesinpv'
          {
              ValueName = 'disableinternetfilesinpv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableunsafelocationsinpv'
          {
              ValueName = 'disableunsafelocationsinpv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableattachmentsinpv'
          {
              ValueName = 'disableattachmentsinpv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations\allownetworklocations'
          {
              ValueName = 'allownetworklocations'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\notbpromptunsignedaddin'
          {
              ValueName = 'notbpromptunsignedaddin'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\vbawarnings'
          {
              ValueName = 'vbawarnings'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\trusted locations\allownetworklocations'
          {
              ValueName = 'allownetworklocations'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security\trusted locations'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\disallowattachmentcustomization'
          {
              ValueName = 'disallowattachmentcustomization'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\general\msgformat'
          {
              ValueName = 'msgformat'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\general'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\internet'
          {
              ValueName = 'internet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\junkmailenablelinks'
          {
              ValueName = 'junkmailenablelinks'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\rpc\enablerpcencryption'
          {
              ValueName = 'enablerpcencryption'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\rpc'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\authenticationservice'
          {
              ValueName = 'authenticationservice'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 16
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\publicfolderscript'
          {
              ValueName = 'publicfolderscript'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\sharedfolderscript'
          {
              ValueName = 'sharedfolderscript'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\allowactivexoneoffforms'
          {
              ValueName = 'allowactivexoneoffforms'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\publishtogaldisabled'
          {
              ValueName = 'publishtogaldisabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\minenckey'
          {
              ValueName = 'minenckey'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 168
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\warnaboutinvalid'
          {
              ValueName = 'warnaboutinvalid'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\usecrlchasing'
          {
              ValueName = 'usecrlchasing'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\adminsecuritymode'
          {
              ValueName = 'adminsecuritymode'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\allowuserstolowerattachments'
          {
              ValueName = 'allowuserstolowerattachments'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\showlevel1attach'
          {
              ValueName = 'showlevel1attach'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel1'
          {
              ValueName = 'fileextensionsremovelevel1'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = ''
          }

          RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel2'
          {
              ValueName = 'fileextensionsremovelevel2'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\enableoneoffformscripts'
          {
              ValueName = 'enableoneoffformscripts'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomcustomaction'
          {
              ValueName = 'promptoomcustomaction'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomaddressbookaccess'
          {
              ValueName = 'promptoomaddressbookaccess'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomformulaaccess'
          {
              ValueName = 'promptoomformulaaccess'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsaveas'
          {
              ValueName = 'promptoomsaveas'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomaddressinformationaccess'
          {
              ValueName = 'promptoomaddressinformationaccess'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoommeetingtaskrequestresponse'
          {
              ValueName = 'promptoommeetingtaskrequestresponse'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsend'
          {
              ValueName = 'promptoomsend'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\level'
          {
              ValueName = 'level'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\vbawarnings'
          {
              ValueName = 'vbawarnings'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\runprograms'
          {
              ValueName = 'runprograms'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\powerpointbypassencryptedmacroscan'
          {
              ValueName = 'powerpointbypassencryptedmacroscan'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\blockcontentexecutionfrominternet'
          {
              ValueName = 'blockcontentexecutionfrominternet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\notbpromptunsignedaddin'
          {
              ValueName = 'notbpromptunsignedaddin'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock\binaryfiles'
          {
              ValueName = 'binaryfiles'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock\openinprotectedview'
          {
              ValueName = 'openinprotectedview'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\enableonload'
          {
              ValueName = 'enableonload'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\openinprotectedview'
          {
              ValueName = 'openinprotectedview'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\disableeditfrompv'
          {
              ValueName = 'disableeditfrompv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableinternetfilesinpv'
          {
              ValueName = 'disableinternetfilesinpv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableattachmentsinpv'
          {
              ValueName = 'disableattachmentsinpv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableunsafelocationsinpv'
          {
              ValueName = 'disableunsafelocationsinpv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations\allownetworklocations'
          {
              ValueName = 'allownetworklocations'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\notbpromptunsignedaddin'
          {
              ValueName = 'notbpromptunsignedaddin'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\vbawarnings'
          {
              ValueName = 'vbawarnings'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\vbawarnings'
          {
              ValueName = 'vbawarnings'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\notbpromptunsignedaddin'
          {
              ValueName = 'notbpromptunsignedaddin'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\blockcontentexecutionfrominternet'
          {
              ValueName = 'blockcontentexecutionfrominternet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock\visio2000files'
          {
              ValueName = 'visio2000files'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock\visio2003files'
          {
              ValueName = 'visio2003files'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock\visio50andearlierfiles'
          {
              ValueName = 'visio50andearlierfiles'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\trusted locations\allownetworklocations'
          {
              ValueName = 'allownetworklocations'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\trusted locations'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\notbpromptunsignedaddin'
          {
              ValueName = 'notbpromptunsignedaddin'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\wordbypassencryptedmacroscan'
          {
              ValueName = 'wordbypassencryptedmacroscan'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\blockcontentexecutionfrominternet'
          {
              ValueName = 'blockcontentexecutionfrominternet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\vbawarnings'
          {
              ValueName = 'vbawarnings'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\openinprotectedview'
          {
              ValueName = 'openinprotectedview'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2files'
          {
              ValueName = 'word2files'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2000files'
          {
              ValueName = 'word2000files'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2003files'
          {
              ValueName = 'word2003files'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2007files'
          {
              ValueName = 'word2007files'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word60files'
          {
              ValueName = 'word60files'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word95files'
          {
              ValueName = 'word95files'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word97files'
          {
              ValueName = 'word97files'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\wordxpfiles'
          {
              ValueName = 'wordxpfiles'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\openinprotectedview'
          {
              ValueName = 'openinprotectedview'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\disableeditfrompv'
          {
              ValueName = 'disableeditfrompv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\enableonload'
          {
              ValueName = 'enableonload'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableinternetfilesinpv'
          {
              ValueName = 'disableinternetfilesinpv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableunsafelocationsinpv'
          {
              ValueName = 'disableunsafelocationsinpv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableattachmentsinpv'
          {
              ValueName = 'disableattachmentsinpv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations\allownetworklocations'
          {
              ValueName = 'allownetworklocations'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\uficontrols'
          {
              ValueName = 'uficontrols'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = 6
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecurity'
          {
              ValueName = 'automationsecurity'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecuritypublisher'
          {
              ValueName = 'automationsecuritypublisher'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\smart tag\neverloadmanifests'
          {
              ValueName = 'neverloadmanifests'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\smart tag'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\vba\security\loadcontrolsinforms'
          {
              ValueName = 'loadcontrolsinforms'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\vba\security'
              ValueData = 1
          } #>

          RefreshRegistryPolicy 'ActivateClientSideExtension'
          {
             IsSingleInstance = 'Yes'
          }
}
