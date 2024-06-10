configuration 'DoD_Office_System_2016_and_Components'
{
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
    Import-DSCResource -ModuleName 'AuditPolicyDSC'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'

          <#     RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\defaultformat'
          {
              ValueName = 'defaultformat'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueData = 51
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\extractdatadisableui'
          {
              ValueName = 'extractdatadisableui'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions\fglobalsheet_37_1'
          {
              ValueName = 'fglobalsheet_37_1'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\requireaddinsig'
          {
              ValueName = 'requireaddinsig'
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

          RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\excel\security\excelbypassencryptedmacroscan'
          {
              ValueName = 'excelbypassencryptedmacroscan'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\accessvbom'
          {
              ValueName = 'accessvbom'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\vbawarnings'
          {
              ValueName = 'vbawarnings'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 2
          }

          RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\excel\security\webservicefunctionwarnings'
          {
              ValueName = 'webservicefunctionwarnings'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\blockcontentexecutionfrominternet'
          {
              ValueName = 'blockcontentexecutionfrominternet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueData = 1
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
              ValueData = 5
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl9597workbooksandtemplates'
          {
              ValueName = 'xl9597workbooksandtemplates'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 5
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\openinprotectedview'
          {
              ValueName = 'openinprotectedview'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 0
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

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\htmlandxmlssfiles'
          {
              ValueName = 'htmlandxmlssfiles'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\dbasefiles'
          {
              ValueName = 'dbasefiles'
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

          RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\openinprotectedview'
          {
              ValueName = 'openinprotectedview'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\disableeditfrompv'
          {
              ValueName = 'disableeditfrompv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableattachmentsinpv'
          {
              ValueName = 'disableattachmentsinpv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableintranetcheck'
          {
              ValueName = 'disableintranetcheck'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations\alllocationsdisabled'
          {
              ValueName = 'alllocationsdisabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations\allownetworklocations'
          {
              ValueName = 'allownetworklocations'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\OneDrive\AllowTenantList\1111-2222-3333-4444'
          {
              ValueName = '1111-2222-3333-4444'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\OneDrive\AllowTenantList'
              ValueData = '1111-2222-3333-4444'
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\meetings\profile\serverui'
          {
              ValueName = 'serverui'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\meetings\profile'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\disallowattachmentcustomization'
          {
              ValueName = 'disallowattachmentcustomization'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\autoformat\pgrfafo_25_1'
          {
              ValueName = 'pgrfafo_25_1'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\autoformat'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\blockextcontent'
          {
              ValueName = 'blockextcontent'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\unblockspecificsenders'
          {
              ValueName = 'unblockspecificsenders'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\unblocksafezone'
          {
              ValueName = 'unblocksafezone'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\trustedzone'
          {
              ValueName = 'trustedzone'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
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

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\intranet'
          {
              ValueName = 'intranet'
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

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\readasplain'
          {
              ValueName = 'readasplain'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\readsignedasplain'
          {
              ValueName = 'readsignedasplain'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\editorpreference'
          {
              ValueName = 'editorpreference'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 65536
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\message rtf format'
          {
              ValueName = 'message rtf format'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\disableofficeonline'
          {
              ValueName = 'disableofficeonline'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\disabledav'
          {
              ValueName = 'disabledav'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\publishcalendardetailspolicy'
          {
              ValueName = 'publishcalendardetailspolicy'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
              ValueData = 16384
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\restrictedaccessonly'
          {
              ValueName = 'restrictedaccessonly'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss\enablefulltexthtml'
          {
              ValueName = 'enablefulltexthtml'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss\enableattachments'
          {
              ValueName = 'enableattachments'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal\enableattachments'
          {
              ValueName = 'enableattachments'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal\disable'
          {
              ValueName = 'disable'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\rpc\enablerpcencryption'
          {
              ValueName = 'enablerpcencryption'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\rpc'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\sharedfolderscript'
          {
              ValueName = 'sharedfolderscript'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\publicfolderscript'
          {
              ValueName = 'publicfolderscript'
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

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\addintrust'
          {
              ValueName = 'addintrust'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\enablerememberpwd'
          {
              ValueName = 'enablerememberpwd'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\adminsecuritymode'
          {
              ValueName = 'adminsecuritymode'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 3
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

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsend'
          {
              ValueName = 'promptoomsend'
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

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoommeetingtaskrequestresponse'
          {
              ValueName = 'promptoommeetingtaskrequestresponse'
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

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomformulaaccess'
          {
              ValueName = 'promptoomformulaaccess'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\externalsmime'
          {
              ValueName = 'externalsmime'
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

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\msgformats'
          {
              ValueName = 'msgformats'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\fipsmode'
          {
              ValueName = 'fipsmode'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\clearsign'
          {
              ValueName = 'clearsign'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\respondtoreceiptrequests'
          {
              ValueName = 'respondtoreceiptrequests'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\usecrlchasing'
          {
              ValueName = 'usecrlchasing'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\level'
          {
              ValueName = 'level'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\authenticationservice'
          {
              ValueName = 'authenticationservice'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 16
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\forcedefaultprofile'
          {
              ValueName = 'forcedefaultprofile'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\minenckey'
          {
              ValueName = 'minenckey'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 168
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\nocheckonsessionsecurity'
          {
              ValueName = 'nocheckonsessionsecurity'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\supressnamechecks'
          {
              ValueName = 'supressnamechecks'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueData = 1
          }

          RegistryPolicyFile 'DELVALS_CU:\software\policies\microsoft\office\16.0\outlook\security\trustedaddins'
          {
              ValueName = ''
              TargetType = 'ComputerConfiguration'

              Ensure = 'Present'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security\trustedaddins'
              ValueData = ''
          } #>

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
          {
              ValueName = 'groove.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
          {
              ValueName = 'excel.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
          {
              ValueName = 'mspub.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
          {
              ValueName = 'powerpnt.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
          {
              ValueName = 'pptview.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
          {
              ValueName = 'visio.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
          {
              ValueName = 'winproj.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
          {
              ValueName = 'winword.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
          {
              ValueName = 'outlook.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
          {
              ValueName = 'spdesign.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
          {
              ValueName = 'exprwd.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
          {
              ValueName = 'msaccess.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
          {
              ValueName = 'onenote.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
          {
              ValueName = 'mse7.exe'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Policies\Microsoft\OneDrive\DisablePersonalSync'
          {
              ValueName = 'DisablePersonalSync'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\SOFTWARE\Policies\Microsoft\OneDrive'
              ValueData = 1
          }

          <# RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\requireaddinsig'
          {
              ValueName = 'requireaddinsig'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\notbpromptunsignedaddin'
          {
              ValueName = 'notbpromptunsignedaddin'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\trustwss'
          {
              ValueName = 'trustwss'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\vbawarnings'
          {
              ValueName = 'vbawarnings'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\OneDrive\AllowTenantList\1111-2222-3333-4444'
          {
              ValueName = '1111-2222-3333-4444'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'HKLM:\Software\Policies\Microsoft\OneDrive\AllowTenantList'
              ValueData = '1111-2222-3333-4444'
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\requireaddinsig'
          {
              ValueName = 'requireaddinsig'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\notbpromptunsignedaddin'
          {
              ValueName = 'notbpromptunsignedaddin'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\vbawarnings'
          {
              ValueName = 'vbawarnings'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueData = 2
          }

          RegistryPolicyFile 'DEL_CU:\keycupoliciesmsvbasecurity\loadcontrolsinforms'
          {
              ValueName = 'loadcontrolsinforms'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'HKCU:\keycupoliciesmsvbasecurity'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\sendcustomerdata'
          {
              ValueName = 'sendcustomerdata'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\broadcast\disabledefaultservice'
          {
              ValueName = 'disabledefaultservice'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\broadcast'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\broadcast\disableprogrammaticaccess'
          {
              ValueName = 'disableprogrammaticaccess'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\broadcast'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\drm\requireconnection'
          {
              ValueName = 'requireconnection'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\drm'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\feedback\includescreenshot'
          {
              ValueName = 'includescreenshot'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\feedback'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\fixedformat\disablefixedformatdocproperties'
          {
              ValueName = 'disablefixedformatdocproperties'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\fixedformat'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\ptwatson\ptwoptin'
          {
              ValueName = 'ptwoptin'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\ptwatson'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\drmencryptproperty'
          {
              ValueName = 'drmencryptproperty'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\openxmlencryptproperty'
          {
              ValueName = 'openxmlencryptproperty'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\openxmlencryption'
          {
              ValueName = 'openxmlencryption'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\defaultencryption12'
          {
              ValueName = 'defaultencryption12'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\encryptdocprops'
          {
              ValueName = 'encryptdocprops'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations\allow user locations'
          {
              ValueName = 'allow user locations'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\trustcenter\trustbar'
          {
              ValueName = 'trustbar'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\trustcenter'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\osm\enablefileobfuscation'
          {
              ValueName = 'enablefileobfuscation'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\osm'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\wef\trustedcatalogs\requireserververification'
          {
              ValueName = 'requireserververification'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\wef\trustedcatalogs'
              ValueData = 1
          }

          RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\common\security\uficontrols'
          {
              ValueName = 'uficontrols'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecurity'
          {
              ValueName = 'automationsecurity'
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
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Policies\Microsoft\OneDrive\DisablePersonalSync'
          {
              ValueName = 'DisablePersonalSync'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\SOFTWARE\Policies\Microsoft\OneDrive'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\promptforbadfiles'
          {
              ValueName = 'promptforbadfiles'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\requireaddinsig'
          {
              ValueName = 'requireaddinsig'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
              ValueData = 1
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
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecuritypublisher'
          {
              ValueName = 'automationsecuritypublisher'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueData = 3
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\internet\donotunderlinehyperlinks'
          {
              ValueName = 'donotunderlinehyperlinks'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\internet'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\requireaddinsig'
          {
              ValueName = 'requireaddinsig'
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

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\modaltrustdecisiononly'
          {
              ValueName = 'modaltrustdecisiononly'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\vbawarnings'
          {
              ValueName = 'vbawarnings'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\settings\default file format'
          {
              ValueName = 'default file format'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\settings'
              ValueData = 12
          } #>

          RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\savepassword'
          {
              ValueName = 'savepassword'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\enablesiphighsecuritymode'
          {
              ValueName = 'enablesiphighsecuritymode'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\disablehttpconnect'
          {
              ValueName = 'disablehttpconnect'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
              ValueData = 1
          }

          <# RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\research\translation\useonline'
          {
              ValueName = 'useonline'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\research\translation'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\options\defaultformat'
          {
              ValueName = 'defaultformat'
              TargetType = 'ComputerConfiguration'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\options'
              ValueData = '
          '
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\options\dontupdatelinks'
          {
              ValueName = 'dontupdatelinks'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\options'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\requireaddinsig'
          {
              ValueName = 'requireaddinsig'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\notbpromptunsignedaddin'
          {
              ValueName = 'notbpromptunsignedaddin'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 1
          }

          RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\word\security\wordbypassencryptedmacroscan'
          {
              ValueName = 'wordbypassencryptedmacroscan'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\accessvbom'
          {
              ValueName = 'accessvbom'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\vbawarnings'
          {
              ValueName = 'vbawarnings'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\blockcontentexecutionfrominternet'
          {
              ValueName = 'blockcontentexecutionfrominternet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueData = 1
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
              ValueData = 5
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
              ValueData = 5
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word97files'
          {
              ValueName = 'word97files'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 5
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\wordxpfiles'
          {
              ValueName = 'wordxpfiles'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueData = 5
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\enableonload'
          {
              ValueName = 'enableonload'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueData = 1
          }

          RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\word\security\filevalidation\openinprotectedview'
          {
              ValueName = 'openinprotectedview'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\disableeditfrompv'
          {
              ValueName = 'disableeditfrompv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableattachmentsinpv'
          {
              ValueName = 'disableattachmentsinpv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableintranetcheck'
          {
              ValueName = 'disableintranetcheck'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations\alllocationsdisabled'
          {
              ValueName = 'alllocationsdisabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations\allownetworklocations'
          {
              ValueName = 'allownetworklocations'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\options\defaultformat'
          {
              ValueName = 'defaultformat'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\options'
              ValueData = 27
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\requireaddinsig'
          {
              ValueName = 'requireaddinsig'
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

          RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\powerpointbypassencryptedmacroscan'
          {
              ValueName = 'powerpointbypassencryptedmacroscan'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\accessvbom'
          {
              ValueName = 'accessvbom'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 0
          }

          RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\runprograms'
          {
              ValueName = 'runprograms'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\vbawarnings'
          {
              ValueName = 'vbawarnings'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 2
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\blockcontentexecutionfrominternet'
          {
              ValueName = 'blockcontentexecutionfrominternet'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueData = 1
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

          RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\openinprotectedview'
          {
              ValueName = 'openinprotectedview'
              TargetType = 'ComputerConfiguration'
              Ensure = 'Absent'
              ValueType = 'String'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueData = ''
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\disableeditfrompv'
          {
              ValueName = 'disableeditfrompv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableattachmentsinpv'
          {
              ValueName = 'disableattachmentsinpv'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableintranetcheck'
          {
              ValueName = 'disableintranetcheck'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueData = 0
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations\alllocationsdisabled'
          {
              ValueName = 'alllocationsdisabled'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations'
              ValueData = 1
          }

          RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations\allownetworklocations'
          {
              ValueName = 'allownetworklocations'
              TargetType = 'ComputerConfiguration'
              ValueType = 'Dword'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations'
              ValueData = 0
          } #>

          RefreshRegistryPolicy 'ActivateClientSideExtension'
          {
             IsSingleInstance = 'Yes'
          }
}
