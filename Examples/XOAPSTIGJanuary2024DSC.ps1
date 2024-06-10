Configuration 'XOAPSTIGJanuary2024DSC'
{
    Import-DSCResource -Module 'XOAPSTIGJanuary2024DSC' -Name 'DoD_Adobe_Acrobat_Reader_DC_Continuous_V2R1' -ModuleVersion '0.0.1'

    param
        (
        )

    Node 'XOAPSTIGAugust2024DSC'
    {
        DoD_Adobe_Acrobat_Reader_DC_Continuous_V2R1 'Example'
        {
        }

    }
}
XOAPSTIGJanuary2024DSC -OutputPath 'C:\XOAPSTIGJanuary2024DSC'
