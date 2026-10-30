#Requires -Version 5.1

$Root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $Root 'HardeningKitty.psd1') -Force

InModuleScope HardeningKitty.SecurityAudit {
    Describe 'Baseline report normalization' {
        BeforeEach {
            $Finding = [PSCustomObject]@{
                ID = 'T-01'; Category = 'Registry policy'; Name = '테스트 보안 설정'; Method = 'Registry'
                RegistryPath = 'HKLM:\Software\Fixture'; RegistryItem = 'Enabled'; MethodArgument = ''
                RecommendedValue = '1'; Operator = '='; Severity = 'High'; DefaultValue = '0'; Description = ''
            }
            $Definition = [PSCustomObject]@{ Path = 'C:\fixture\machine.csv'; Name = 'machine.csv'; Findings = @($Finding) }
            $EngineRow = [PSCustomObject]@{ ID = 'T-01'; Result = '1'; Recommended = '1'; TestResult = 'Passed'; DefaultValue = 'False' }
            $Run = [PSCustomObject]@{ Rows = @($EngineRow); Completed = $true; Error = ''; Diagnostics = ''; HasErrors = $false }
            $Catalog = @{ 'Machine:T-01' = [PSCustomObject]@{ Scope = 'Machine'; ID = 'T-01'; Name = $Finding.Name; Description = '레지스트리의 보안 정책이 실제로 활성화되어 있는지 확인하여 허용되지 않은 접근 위험을 줄입니다.' } }
            $CheckedAt = [DateTimeOffset]'2026-10-29T10:01:02+09:00'
            $Arguments = @{ Definition = $Definition; Run = $Run; Scope = 'Machine'; Target = 'fixture-host'; Catalog = $Catalog; CheckedAt = $CheckedAt }
            Mock Invoke-HardeningKitty { Throw 'Live baseline collection is forbidden in these tests.' }
        }
        It 'retains every expected ID in definition order when report rows are missing or out of order' {
            $Second = $Finding.PSObject.Copy()
            $Second.ID = 'T-02'
            $Third = $Finding.PSObject.Copy()
            $Third.ID = 'T-03'
            $Definition.Findings = @($Finding, $Second, $Third)
            $ThirdRow = $EngineRow.PSObject.Copy()
            $ThirdRow.ID = 'T-03'
            $Run.Rows = @($ThirdRow, $EngineRow)
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            (($Rows | Where-Object Scope -eq Machine).ID -join ',') | Should Be 'T-01,T-02,T-03'
            ($Rows | Where-Object ID -eq T-02).TestResult | Should Be 'Error'
            ($null -eq ($Rows | Where-Object ID -eq T-02).Result) | Should Be $true
            ($null -eq ($Rows | Where-Object ID -eq T-02).UsedDefault) | Should Be $true
            ($Rows | Where-Object ID -eq T-02).ValueOrigin | Should Be 'Unavailable'
            ($Rows | Where-Object ID -eq T-02).ReasonCode | Should Be 'MissingResult'
            ($Rows | Where-Object ID -eq T-01).TestResult | Should Be 'Passed'
            ($Rows | Where-Object ID -eq T-03).TestResult | Should Be 'Passed'
            ($Rows | Where-Object ID -eq ENGINE-Machine).TestResult | Should Be 'Error'
            ($Rows | Where-Object ID -eq ENGINE-Machine).Details | Should Match '누락 1'
        }
        It 'retains all 418 machine and 56 user definitions even when the engine returns no rows' {
            $ModuleRoot = (Get-Module HardeningKitty.SecurityAudit -All).ModuleBase
            ForEach ($Scope in @('Machine', 'User')) {
                $Definition = Import-SecurityAuditList -Path (Join-Path $ModuleRoot "lists\finding_list_0x6d69636b_$($Scope.ToLowerInvariant()).csv")
                $Run.Rows = @()
                $Rows = @(ConvertFrom-SecurityAuditEngineReport -Definition $Definition -Run $Run -Scope $Scope -Target 'fixture' -Catalog @{} -CheckedAt $CheckedAt)
                $ExpectedCount = 418
                If ($Scope -eq 'User') { $ExpectedCount = 56 }
                $Definition.Findings.Count | Should Be $ExpectedCount
                @($Rows | Where-Object Scope -eq $Scope).Count | Should Be $ExpectedCount
                (($Rows | Where-Object Scope -eq $Scope).ID -join ',') | Should Be ($Definition.Findings.ID -join ',')
                @($Rows | Where-Object TestResult -ne Error).Count | Should Be 0
            }
            Assert-MockCalled Invoke-HardeningKitty -Times 0 -Exactly -Scope It
        }
        It 'downgrades explicit default substitutions regardless of the original pass or failure' {
            ForEach ($Status in @('Passed', 'Failed')) {
                $EngineRow.TestResult = $Status
                $EngineRow.DefaultValue = 'True'
                $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
                $Rows[0].TestResult | Should Be 'Unknown'
                $Rows[0].EngineTestResult | Should Be $Status
                ($Rows[0].UsedDefault -is [Boolean]) | Should Be $true
                $Rows[0].UsedDefault | Should Be $true
                $Rows[0].Result | Should Be '1'
                $Rows[0].ValueOrigin | Should Be 'Default'
                $Rows[0].ReasonCode | Should Be 'DefaultSubstitution'
                $Rows[1].Details | Should Match '기본값 대체 1'
            }
        }
        It 'parses false as a Boolean false instead of PowerShell truthiness and preserves real zero' {
            $Finding.RecommendedValue = '0'
            $EngineRow.Result = 0
            ForEach ($Flag in @('False', 'false', $false)) {
                $EngineRow.DefaultValue = $Flag
                $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
                $Rows[0].TestResult | Should Be 'Passed'
                ($Rows[0].UsedDefault -is [Boolean]) | Should Be $true
                $Rows[0].UsedDefault | Should Be $false
                $Rows[0].Result | Should Be 0
                $Rows[0].ValueOrigin | Should Be 'Observed'
                $Rows[0].ReasonCode | Should Be 'Compared'
                $Rows[1].Details | Should Match '기본값 대체 0'
            }
        }
        It 'keeps missing, null and invalid default flags unresolved rather than guessing false' {
            ForEach ($Flag in @($null, '', ' ', '0', '1', 'unknown')) {
                $EngineRow.DefaultValue = $Flag
                $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
                $Rows[0].TestResult | Should Be 'Unknown'
                ($null -eq $Rows[0].UsedDefault) | Should Be $true
                $Rows[0].EngineTestResult | Should Be 'Passed'
                $Rows[0].ValueOrigin | Should Be 'Unverified'
                $Rows[0].ReasonCode | Should Be 'UnknownDefaultFlag'
            }
            $Run.Rows = @([PSCustomObject]@{ ID = 'T-01'; Result = '1'; Recommended = '1'; TestResult = 'Passed' })
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            $Rows[0].TestResult | Should Be 'Unknown'
            ($null -eq $Rows[0].UsedDefault) | Should Be $true
            $Rows[0].ValueOrigin | Should Be 'Unverified'
            $Rows[0].ReasonCode | Should Be 'UnknownDefaultFlag'
        }
        It 'does not interpret absent, whitespace, fractional, overflowing or nonnumeric results as zero' {
            ForEach ($Operator in @('=', '!=', '<=', '<=!0', '>=')) {
                $Finding.Operator = $Operator
                $Finding.RecommendedValue = '0'
                ForEach ($Value in @($null, '', '  ', "`t`r`n", 'invalid', '1.5', '9223372036854775808')) {
                    $EngineRow.Result = $Value
                    $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
                    $Rows[0].TestResult | Should Be 'Unknown'
                    $Rows[0].EngineTestResult | Should Be 'Passed'
                    $Rows[0].UsedDefault | Should Be $false
                    $Rows[0].ValueOrigin | Should Be 'Unverified'
                    $Rows[0].ReasonCode | Should Be 'InvalidNumericEvidence'
                }
            }
        }
        It 'accepts surrounding whitespace and signed integer values without rewriting the raw result' {
            $Finding.Operator = '>='
            ForEach ($Value in @(' 1 ', "`t14`r`n", '-1', '9223372036854775807')) {
                $EngineRow.Result = $Value
                $EngineRow.TestResult = 'Failed'
                $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
                $Rows[0].TestResult | Should Be 'Failed'
                $Rows[0].Result | Should Be $Value
                $Rows[0].EngineTestResult | Should Be 'Failed'
            }
        }
        It 'never treats an empty USER_RIGHTS export as an observed pass or failure' {
            $Finding.Operator = 'notcontains'
            $Finding.RecommendedValue = 'untrusted-account'
            $Finding.Method = 'accesschk'
            ForEach ($HasErrors in @($false, $true)) {
                $Run.HasErrors = $HasErrors
                ForEach ($Status in @('Passed', 'Failed')) {
                    $EngineRow.TestResult = $Status
                    ForEach ($Value in @('', $null, ' ', "`t`r`n")) {
                        $EngineRow.Result = $Value
                        $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
                        $Rows[0].TestResult | Should Be 'Unknown'
                        $Rows[0].EngineTestResult | Should Be $Status
                        $Rows[0].UsedDefault | Should Be $false
                        $Rows[0].ValueOrigin | Should Be 'Unverified'
                        $Rows[0].ReasonCode | Should Be 'UnverifiedEmptyExport'
                    }
                }
            }
        }
        It 'preserves clean empty Defender exclusions and nonempty user-right observations' {
            $Finding.Operator = 'notcontains'
            $Finding.RecommendedValue = 'untrusted-account'
            $Finding.Method = 'MpPreferenceExclusion'
            ForEach ($Value in @('', $null)) {
                $EngineRow.Result = $Value
                $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
                $Rows[0].TestResult | Should Be 'Passed'
                $Rows[0].UsedDefault | Should Be $false
                $Rows[0].ValueOrigin | Should Be 'Observed'
                $Rows[0].ReasonCode | Should Be 'Compared'
            }
            $Finding.Method = 'accesschk'
            $EngineRow.Result = 'BUILTIN\Administrators'
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            $Rows[0].TestResult | Should Be 'Passed'
            $Rows[0].ValueOrigin | Should Be 'Observed'
            $Rows[0].ReasonCode | Should Be 'Compared'
        }
        It 'does not pass an empty Defender exclusion result after a run-level collection error' {
            $Finding.Method = 'MpPreferenceExclusion'
            $Finding.MethodArgument = 'ExclusionPath'
            $Finding.Operator = '='
            $Finding.RecommendedValue = ''
            ForEach ($Value in @('', $null)) {
                $EngineRow.Result = $Value
                $Run.HasErrors = $false
                $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
                $Rows[0].TestResult | Should Be 'Passed'
                $Rows[1].TestResult | Should Be 'Info'
                $Run.HasErrors = $true
                $Run.Diagnostics = 'Get-MpPreference: fixture access denied'
                $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
                $Rows[0].TestResult | Should Be 'Unknown'
                $Rows[0].EngineTestResult | Should Be 'Passed'
                $Rows[0].UsedDefault | Should Be $false
                $Rows[0].ValueOrigin | Should Be 'Unverified'
                $Rows[0].ReasonCode | Should Be 'CollectionError'
                $Rows[1].TestResult | Should Be 'Error'
                $Rows[1].Details | Should Match 'Get-MpPreference'
            }
        }
        It 'treats an absent Result column as an error, not as a legitimate empty exclusion list' {
            $Finding.Method = 'MpPreferenceExclusion'
            $Finding.Operator = '='
            $Finding.RecommendedValue = ''
            $Run.Rows = @([PSCustomObject]@{ ID = 'T-01'; Recommended = ''; TestResult = 'Passed'; DefaultValue = 'False' })
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            $Rows[0].TestResult | Should Be 'Error'
            $Rows[0].EngineTestResult | Should Be 'Passed'
            $Rows[0].UsedDefault | Should Be $false
            $Rows[0].ValueOrigin | Should Be 'Unavailable'
            $Rows[0].ReasonCode | Should Be 'MissingResultColumn'
            $Rows[0].Details | Should Match 'Result'
            $Run.Rows = @([PSCustomObject]@{ ID = 'T-01'; Result = ''; Recommended = ''; TestResult = 'Passed'; DefaultValue = 'False' })
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            $Rows[0].TestResult | Should Be 'Passed'
        }
        It 'distinguishes allowed empty equality from missing nonempty text results' {
            $Finding.RecommendedValue = ''
            $EngineRow.Result = ''
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            $Rows[0].TestResult | Should Be 'Passed'
            $Rows[0].ValueOrigin | Should Be 'Observed'
            $Rows[0].ReasonCode | Should Be 'Compared'
            $Finding.Operator = '=|0'
            $Finding.RecommendedValue = 'Administrators'
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            $Rows[0].TestResult | Should Be 'Passed'
            $Rows[0].ValueOrigin | Should Be 'Observed'
            $Rows[0].ReasonCode | Should Be 'Compared'
            $Finding.Operator = '='
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            $Rows[0].TestResult | Should Be 'Unknown'
            $Rows[0].ValueOrigin | Should Be 'Unavailable'
            $Rows[0].ReasonCode | Should Be 'EmptyValue'
        }
        It 'never calls unsupported, unavailable, sentinel or manual-check values observed passes' {
            $Finding.RecommendedValue = 'Enabled'
            ForEach ($Value in @('-NODATA-', 'NotSupported', 'NotConfigured', 'PathNotExists', 'WinningProviderNotExists', 'Not available', 'Manual check required')) {
                $EngineRow.Result = $Value
                $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
                $Rows[0].TestResult | Should Be 'Unknown'
                $Rows[0].Result | Should Be $Value
                $Rows[0].EngineTestResult | Should Be 'Passed'
                $Rows[0].ValueOrigin | Should Be 'Unavailable'
                $Rows[0].ReasonCode | Should Be 'CollectorMarker'
            }
        }
        It 'marks unflagged ASR default results uncertain but retains nondefault ASR evidence' {
            $Finding.Method = 'MpPreferenceAsr'
            $Finding.DefaultValue = '0'
            $Finding.MethodArgument = 'fixture-rule-guid'
            $EngineRow.Result = '0'
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            $Rows[0].TestResult | Should Be 'Unknown'
            $Rows[0].UsedDefault | Should Be $false
            $Rows[0].ValueOrigin | Should Be 'Unverified'
            $Rows[0].ReasonCode | Should Be 'UnverifiedAsrDefault'
            $Rows[0].Details | Should Match 'ASR'
            $EngineRow.Result = '1'
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            $Rows[0].TestResult | Should Be 'Passed'
            $Rows[0].ValueOrigin | Should Be 'Observed'
            $Rows[0].ReasonCode | Should Be 'Compared'
        }
        It 'does not choose an arbitrary result for duplicate IDs or turn unexpected IDs into findings' {
            $Conflict = $EngineRow.PSObject.Copy()
            $Conflict.TestResult = 'Failed'
            $Conflict.Result = '0'
            $Unexpected = $EngineRow.PSObject.Copy()
            $Unexpected.ID = 'OUTSIDE-LIST'
            $BlankID = $EngineRow.PSObject.Copy()
            $BlankID.ID = ''
            $Run.Rows = @($EngineRow, $Conflict, $Unexpected, $BlankID)
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            $Rows.Count | Should Be 2
            $Rows[0].ID | Should Be 'T-01'
            $Rows[0].TestResult | Should Be 'Error'
            ($null -eq $Rows[0].Result) | Should Be $true
            ($null -eq $Rows[0].UsedDefault) | Should Be $true
            $Rows[0].ValueOrigin | Should Be 'Unavailable'
            $Rows[0].ReasonCode | Should Be 'DuplicateResult'
            $Rows[1].TestResult | Should Be 'Error'
            $Rows[1].Details | Should Match '중복 ID 1'
            $Rows[1].Details | Should Match '예상하지 않은 ID 2'
            $Rows[1].Details | Should Match 'OUTSIDE-LIST'
        }
        It 'does not label partial or failed execution as a completed compliance result' {
            $Run.Completed = $false
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            @($Rows | Where-Object TestResult -ne Error).Count | Should Be 0
            $Rows[0].EngineTestResult | Should Be 'Passed'
            $Rows[0].Result | Should Be '1'
            $Rows[0].ValueOrigin | Should Be 'Unverified'
            $Rows[0].ReasonCode | Should Be 'ExecutionIncomplete'
            $Run.Completed = $true
            $Run.Error = 'report read failed'
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            @($Rows | Where-Object TestResult -ne Error).Count | Should Be 0
            $Rows[0].ValueOrigin | Should Be 'Unverified'
            $Rows[0].ReasonCode | Should Be 'ExecutionError'
            $Rows[0].Details | Should Match 'report read failed'
            $Rows[1].Details | Should Match 'report read failed'
        }
        It 'rejects missing or unknown engine status while preserving the original status as evidence' {
            ForEach ($Status in @('', $null, 'Unknown', 'Info', 'NotApplicable', 'Passed" onclick="alert(1)')) {
                $EngineRow.TestResult = $Status
                $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
                $Rows[0].TestResult | Should Be 'Error'
                $Rows[0].EngineTestResult | Should Be ([String]$Status)
                $Rows[0].ValueOrigin | Should Be 'Unverified'
                $Rows[0].ReasonCode | Should Be 'InvalidEngineVerdict'
            }
        }
        It 'preserves authoritative list metadata, operator, query source, status and checked instant' {
            $Finding.Operator = '<=!0'
            $Finding.RecommendedValue = '90'
            $Finding.Method = 'secedit'
            $Finding.MethodArgument = 'MaximumPasswordAge'
            $EngineRow.Recommended = 'engine recommendation retained separately'
            $EngineRow.TestResult = 'Failed'
            $EngineRow.Result = '0'
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            $Row = $Rows[0]
            $Row.Scope | Should Be 'Machine'
            $Row.List | Should Be 'machine.csv'
            $Row.Category | Should Be $Finding.Category
            $Row.Name | Should Be $Finding.Name
            $Row.Description | Should Be $Catalog['Machine:T-01'].Description
            $Row.Severity | Should Be 'High'
            $Row.Target | Should Be 'fixture-host'
            $Row.TestResult | Should Be 'Failed'
            $Row.EngineTestResult | Should Be 'Failed'
            $Row.ValueOrigin | Should Be 'Observed'
            $Row.ReasonCode | Should Be 'Compared'
            $Columns = @($Row.PSObject.Properties.Name)
            ($Columns[($Columns.Count - 8)..($Columns.Count - 1)] -join ',') | Should Be 'UsedDefault,ValueOrigin,ReasonCode,CheckedAt,Importance,ImportanceReason,RemediationPriority,PriorityReason'
            $Row.Source | Should Be 'secedit /export SECURITYPOLICY: MaximumPasswordAge'
            $Row.Recommended | Should Match ([Regex]::Escape('<=!0'))
            $Row.Recommended | Should Match '90'
            $Row.Details | Should Match 'engine recommendation retained separately'
            $Row.CheckedAt | Should Be $CheckedAt.ToString('o')
            $Rows[1].Scope | Should Be 'Execution'
            $Rows[1].Source | Should Be $Definition.Path
            $Rows[1].TestResult | Should Be 'Info'
            $Rows[1].ValueOrigin | Should Be 'Reference'
        }
        It 'retains limited service and firewall collector meanings in the evidence' {
            $Finding.Method = 'service'
            $Finding.MethodArgument = 'RemoteRegistry'
            $Finding.RecommendedValue = 'Disabled'
            $EngineRow.Result = 'Disabled'
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            $Rows[0].Source | Should Match 'Get-Service.*RemoteRegistry.*StartType'
            $Rows[0].Details | Should Match '시작 유형'
            $Finding.Method = 'FirewallRule'
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            $Rows[0].Source | Should Match 'Get-NetFirewallRule.*ActiveStore.*Enabled'
            $Rows[0].Details | Should Match '포트'
        }
        It 'identifies the real bcdedit search operand rather than an empty method argument' {
            $Finding.Method = 'bcdedit'
            $Finding.MethodArgument = ''
            $Finding.RecommendedValue = 'nx AlwaysOn'
            Get-SecurityAuditQuery -Finding $Finding | Should Match 'nx AlwaysOn'
        }
        It 'marks otherwise comparable passes and failures eligible for isolated collection' {
            $Run.HasErrors = $true
            $Run.Diagnostics = '[!] fixture collector unavailable'
            ForEach ($Status in @('Passed', 'Failed')) {
                $EngineRow.TestResult = $Status
                $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
                $Rows[0].TestResult | Should Be 'Unknown'
                $Rows[0].EngineTestResult | Should Be $Status
                $Rows[0].Result | Should Be '1'
                $Rows[0].ValueOrigin | Should Be 'Unverified'
                $Rows[0].ReasonCode | Should Be 'CollectionError'
                $Rows[1].TestResult | Should Be 'Error'
                $Rows[1].Details | Should Match 'fixture collector unavailable'
            }
        }
        It 'does not make defaults eligible for recheck or weaken a fatal execution error' {
            $Run.HasErrors = $true
            $EngineRow.TestResult = 'Failed'
            $EngineRow.Result = '0'
            $EngineRow.DefaultValue = 'True'
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            $Rows[0].TestResult | Should Be 'Unknown'
            $Rows[0].EngineTestResult | Should Be 'Failed'
            $Rows[0].Result | Should Be '0'
            $Rows[0].ValueOrigin | Should Be 'Default'
            $Rows[0].ReasonCode | Should Be 'DefaultSubstitution'
            $Rows[1].TestResult | Should Be 'Error'
            $Run.Error = 'fatal fixture failure'
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            @($Rows | Where-Object TestResult -ne Error).Count | Should Be 0
            $Rows[0].ValueOrigin | Should Be 'Default'
            $Rows[0].ReasonCode | Should Be 'ExecutionError'
        }
        It 'retains diagnostics and reconciliation counts in the execution row' {
            $Run.Diagnostics = '[?] Finding list is custom; fixture warning'
            $Rows = @(ConvertFrom-SecurityAuditEngineReport @Arguments)
            $Rows[1].ID | Should Be 'ENGINE-Machine'
            $Rows[1].Result | Should Be '1 / 1'
            $Rows[1].Details | Should Match '예정 1개; 원본 행 1개'
            $Rows[1].Details | Should Match 'fixture warning'
            $Rows[1].Description.Length | Should BeGreaterThan 30
        }
        It 'turns a thrown engine invocation into a complete expected-ID error report' {
            Mock Invoke-SecurityAuditEngine { Throw 'fixture engine denied' }
            $Rows = @(Invoke-SecurityAuditBaseline -Definition $Definition -Scope User -Target 'fixture-user' -Catalog @{})
            $Rows.Count | Should Be 2
            $Rows[0].ID | Should Be 'T-01'
            $Rows[0].Scope | Should Be 'User'
            $Rows[0].TestResult | Should Be 'Error'
            $Rows[0].Details | Should Match 'fixture engine denied'
            $Rows[1].ID | Should Be 'ENGINE-User'
            $Rows[1].TestResult | Should Be 'Error'
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 1 -Exactly -Scope It -ParameterFilter { $ListPath -eq $Definition.Path }
            Assert-MockCalled Invoke-HardeningKitty -Times 0 -Exactly -Scope It
        }
        It 'normalizes a successful mocked engine receipt with the requested scope and target' {
            $script:BaselineReceipt = $Run
            Mock Invoke-SecurityAuditEngine { $script:BaselineReceipt }
            $Rows = @(Invoke-SecurityAuditBaseline -Definition $Definition -Scope Machine -Target 'fixture-host' -Catalog $Catalog)
            $Rows.Count | Should Be 2
            $Rows[0].ID | Should Be 'T-01'
            $Rows[0].Scope | Should Be 'Machine'
            $Rows[0].Target | Should Be 'fixture-host'
            $Rows[0].Description | Should Be $Catalog['Machine:T-01'].Description
            $Rows[0].TestResult | Should Be 'Passed'
            $Rows[0].CheckedAt | Should Match '[+-]\d{2}:\d{2}$'
            $Rows[1].CheckedAt | Should Be $Rows[0].CheckedAt
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 1 -Exactly -Scope It -ParameterFilter { $ListPath -eq $Definition.Path }
            Assert-MockCalled Invoke-HardeningKitty -Times 0 -Exactly -Scope It
        }
    }

    Describe 'Isolated baseline collection after broad-run errors' {
        BeforeEach {
            $Finding = [PSCustomObject]@{
                ID = 'T-01'; Category = 'Registry policy'; Name = '격리 조회 항목'; Method = 'Registry'
                RegistryPath = 'HKLM:\Software\Fixture'; RegistryItem = 'Enabled'; MethodArgument = ''
                RecommendedValue = '1'; Operator = '='; Severity = 'High'; DefaultValue = '0'; Description = ''
            }
            $Definition = [PSCustomObject]@{ Path = 'C:\fixture\isolated.csv'; Name = 'isolated.csv'; Findings = @($Finding) }
            $EngineRow = [PSCustomObject]@{ ID = 'T-01'; Result = '1'; Recommended = 'old recommendation'; TestResult = 'Passed'; DefaultValue = 'False' }
            $script:BroadReceipt = [PSCustomObject]@{
                Rows = @($EngineRow); Completed = $true; Error = ''
                Diagnostics = '[!] 최초 수집 오류 <script>alert("fixture")</script>'; HasErrors = $true
            }
            $FreshRow = $EngineRow.PSObject.Copy()
            $FreshRow.Recommended = 'fresh recommendation'
            $script:IsolatedReceipts = @{
                'T-01' = [PSCustomObject]@{ Rows = @($FreshRow); Completed = $true; Error = ''; Diagnostics = ''; HasErrors = $false }
            }
            $script:BaselineCalls = New-Object 'System.Collections.Generic.List[object]'
            $script:ThrowIsolatedID = ''
            $script:DelayBroadReceipt = $false
            Mock Invoke-HardeningKitty { Throw 'Live baseline collection is forbidden in these tests.' } -ParameterFilter { $true }
            Mock Invoke-SecurityAuditEngine {
                $script:BaselineCalls.Add([PSCustomObject]@{ ListPath = $ListPath; FindingID = [String]$FindingID })
                If ([String]::IsNullOrEmpty($FindingID)) {
                    # Separate the broad and isolated collection instants even on a coarse clock.
                    If ($script:DelayBroadReceipt) { Start-Sleep -Milliseconds 30 }
                    Return $script:BroadReceipt
                }
                If ($FindingID -ceq $script:ThrowIsolatedID) { Throw 'fixture isolated exception' }
                If (-not $script:IsolatedReceipts.ContainsKey($FindingID)) { Throw "Unexpected isolated ID: $FindingID" }
                Return $script:IsolatedReceipts[$FindingID]
            } -ParameterFilter { $true }
        }
        It 'rechecks each comparable ID once without letting a bad item poison clean passes or failures in either scope' {
            $Bad = $Finding.PSObject.Copy()
            $Bad.ID = 'BAD'
            $GoodPass = $Finding.PSObject.Copy()
            $GoodPass.ID = 'GOOD-PASS'
            $GoodFail = $Finding.PSObject.Copy()
            $GoodFail.ID = 'GOOD-FAIL'
            $Definition.Findings = @($Bad, $GoodPass, $GoodFail)
            $OldBad = $EngineRow.PSObject.Copy()
            $OldBad.ID = 'BAD'
            $OldPass = $EngineRow.PSObject.Copy()
            $OldPass.ID = 'GOOD-PASS'
            $OldPass.Result = '0'
            $OldPass.TestResult = 'Failed'
            $OldFail = $EngineRow.PSObject.Copy()
            $OldFail.ID = 'GOOD-FAIL'
            $script:BroadReceipt.Rows = @($OldFail, $OldPass, $OldBad)
            $NewBad = $OldBad.PSObject.Copy()
            $NewBad.Result = '9'
            $NewBad.TestResult = 'Failed'
            $NewBad.Recommended = 'fresh bad recommendation'
            $NewPass = $OldPass.PSObject.Copy()
            $NewPass.Result = '1'
            $NewPass.TestResult = 'Passed'
            $NewPass.Recommended = 'fresh pass recommendation'
            $NewFail = $OldFail.PSObject.Copy()
            $NewFail.Result = '0'
            $NewFail.TestResult = 'Failed'
            $NewFail.Recommended = 'fresh failure recommendation'
            $script:IsolatedReceipts = @{
                'BAD' = [PSCustomObject]@{ Rows = @($NewBad); Completed = $true; Error = 'fixture isolated denied'; Diagnostics = '[!] isolated bad collector'; HasErrors = $true }
                'GOOD-PASS' = [PSCustomObject]@{ Rows = @($NewPass); Completed = $true; Error = ''; Diagnostics = ''; HasErrors = $false }
                'GOOD-FAIL' = [PSCustomObject]@{ Rows = @($NewFail); Completed = $true; Error = ''; Diagnostics = ''; HasErrors = $false }
            }
            $script:DelayBroadReceipt = $true
            ForEach ($Scope in @('Machine', 'User')) {
                $script:BaselineCalls.Clear()
                $Rows = @(Invoke-SecurityAuditBaseline -Definition $Definition -Scope $Scope -Target '격리 대상' -Catalog @{})
                $Rows.Count | Should Be 4
                ($Rows.ID -join ',') | Should Be "BAD,GOOD-PASS,GOOD-FAIL,ENGINE-$Scope"
                ($Rows.Scope -join ',') | Should Be "$Scope,$Scope,$Scope,Execution"
                ($Rows.TestResult -join ',') | Should Be 'Error,Passed,Failed,Error'
                ($Rows[0..2].EngineTestResult -join ',') | Should Be 'Failed,Passed,Failed'
                ($Rows[0..2].Result -join ',') | Should Be '9,1,0'
                ($Rows[0..2].ValueOrigin -join ',') | Should Be 'Unverified,Observed,Observed'
                ($Rows[0..2].ReasonCode -join ',') | Should Be 'ExecutionError,Compared,Compared'
                $Rows[0].Details | Should Match 'fixture isolated denied'
                $Rows[0].Details | Should Match 'isolated bad collector'
                $Rows[1].Details | Should Match 'fresh pass recommendation'
                $Rows[2].Details | Should Match 'fresh failure recommendation'
                ForEach ($Row in $Rows[0..2]) {
                    $Row.List | Should Be 'isolated.csv'
                    $Row.Target | Should Be '격리 대상'
                    $Row.UsedDefault | Should Be $false
                    $Row.Details | Should Match '개별 재조회'
                    $Row.Details | Should Not Match 'old recommendation'
                    ([DateTimeOffset]$Row.CheckedAt -gt [DateTimeOffset]$Rows[3].CheckedAt) | Should Be $true
                }
                $Rows[1].Details | Should Not Match 'isolated bad collector'
                $Rows[2].Details | Should Not Match 'isolated bad collector'
                $Rows[3].ValueOrigin | Should Be 'Reference'
                $Rows[3].Result | Should Be '3 / 3'
                $Rows[3].Details | Should Match '예정 3개; 원본 행 3개; 누락 0; 중복 ID 0'
                $Rows[3].Details | Should Match ([Regex]::Escape($script:BroadReceipt.Diagnostics))
                $Rows[3].Details | Should Match '개별 재조회: 3; 정상 비교 가능: 2; 미확인 또는 오류: 1'
                $script:BaselineCalls.Count | Should Be 4
                ($script:BaselineCalls.FindingID -join ',') | Should Be ',BAD,GOOD-PASS,GOOD-FAIL'
                @($script:BaselineCalls | Where-Object ListPath -ne $Definition.Path).Count | Should Be 0
            }
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 8 -Exactly -Scope It
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 2 -Exactly -Scope It -ParameterFilter { [String]::IsNullOrEmpty($FindingID) }
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 2 -Exactly -Scope It -ParameterFilter { $FindingID -ceq 'BAD' }
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 2 -Exactly -Scope It -ParameterFilter { $FindingID -ceq 'GOOD-PASS' }
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 2 -Exactly -Scope It -ParameterFilter { $FindingID -ceq 'GOOD-FAIL' }
            Assert-MockCalled Invoke-HardeningKitty -Times 0 -Exactly -Scope It
        }
        It 'does not recheck a clean broad run with both passed and failed observations' {
            $Second = $Finding.PSObject.Copy()
            $Second.ID = 'T-02'
            $FailedRow = $EngineRow.PSObject.Copy()
            $FailedRow.ID = 'T-02'
            $FailedRow.Result = '0'
            $FailedRow.TestResult = 'Failed'
            $Definition.Findings = @($Finding, $Second)
            $script:BroadReceipt.Rows = @($FailedRow, $EngineRow)
            $script:BroadReceipt.HasErrors = $false
            $script:BroadReceipt.Diagnostics = '[?] clean fixture warning'
            $Rows = @(Invoke-SecurityAuditBaseline -Definition $Definition -Scope User -Target 'fixture-user' -Catalog @{})
            $Rows.Count | Should Be 3
            ($Rows.ID -join ',') | Should Be 'T-01,T-02,ENGINE-User'
            ($Rows.TestResult -join ',') | Should Be 'Passed,Failed,Info'
            ($Rows[0..1].ValueOrigin -join ',') | Should Be 'Observed,Observed'
            $Rows[0].CheckedAt | Should Be $Rows[2].CheckedAt
            $Rows[1].CheckedAt | Should Be $Rows[2].CheckedAt
            $Rows[2].Details | Should Match 'clean fixture warning'
            $Rows[2].Details | Should Not Match '개별 재조회'
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 1 -Exactly -Scope It
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 0 -Exactly -Scope It -ParameterFilter { -not [String]::IsNullOrEmpty($FindingID) }
        }
        It 'keeps failed, incomplete and invalid-cardinality isolated receipts Error without recursion' {
            ForEach ($Case in @('Failure', 'Exception', 'Partial', 'Missing', 'Duplicate', 'Wrong', 'WrongCase', 'Extra', 'MissingResultColumn', 'InvalidVerdict')) {
                $script:BaselineCalls.Clear()
                $script:ThrowIsolatedID = ''
                $Fresh = $EngineRow.PSObject.Copy()
                $Fresh.Result = '0'
                $Fresh.TestResult = 'Failed'
                $ItemRun = [PSCustomObject]@{ Rows = @($Fresh); Completed = $true; Error = ''; Diagnostics = 'isolated receipt diagnostic'; HasErrors = $false }
                Switch ($Case) {
                    'Failure' { $ItemRun.Error = 'isolated export failed' }
                    'Exception' { $script:ThrowIsolatedID = 'T-01' }
                    'Partial' { $ItemRun.Completed = $false }
                    'Missing' { $ItemRun.Rows = @() }
                    'Duplicate' { $ItemRun.Rows = @($Fresh, $Fresh.PSObject.Copy()) }
                    'Wrong' { $Fresh.ID = 'OTHER-ID' }
                    'WrongCase' { $Fresh.ID = 't-01' }
                    'Extra' {
                        $Extra = $Fresh.PSObject.Copy()
                        $Extra.ID = 'OTHER-ID'
                        $ItemRun.Rows = @($Fresh, $Extra)
                    }
                    'MissingResultColumn' { $Fresh.PSObject.Properties.Remove('Result') }
                    'InvalidVerdict' { $Fresh.TestResult = 'Info' }
                }
                $script:IsolatedReceipts['T-01'] = $ItemRun
                $Rows = @(Invoke-SecurityAuditBaseline -Definition $Definition -Scope Machine -Target 'fixture-host' -Catalog @{})
                $Rows.Count | Should Be 2
                ($Rows.ID -join ',') | Should Be 'T-01,ENGINE-Machine'
                ($Rows.Scope -join ',') | Should Be 'Machine,Execution'
                ($Rows.TestResult -join ',') | Should Be 'Error,Error'
                ($Rows[0].ValueOrigin -in @('Unverified', 'Unavailable')) | Should Be $true
                $Rows[0].Details | Should Match '개별 재조회'
                $Rows[1].Details | Should Match ([Regex]::Escape($script:BroadReceipt.Diagnostics))
                $Rows[1].Details | Should Match '개별 재조회: 1; 정상 비교 가능: 0; 미확인 또는 오류: 1'
                $script:BaselineCalls.Count | Should Be 2
                ($script:BaselineCalls.FindingID -join ',') | Should Be ',T-01'
                If ($Case -eq 'Exception') { $Rows[0].Details | Should Match 'fixture isolated exception' }
                If ($Case -eq 'Failure') { $Rows[0].Details | Should Match 'isolated export failed' }
                If ($Case -in @('Missing', 'Duplicate', 'Wrong', 'WrongCase', 'Extra')) {
                    $Rows[0].ReasonCode | Should Be 'ExecutionError'
                    $Rows[0].Details | Should Match '단일 결과'
                }
            }
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 20 -Exactly -Scope It
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 10 -Exactly -Scope It -ParameterFilter { $FindingID -ceq 'T-01' }
        }
        It 'does not recursively retry an isolated run that still has collection errors' {
            $script:IsolatedReceipts['T-01'].HasErrors = $true
            $script:IsolatedReceipts['T-01'].Diagnostics = '[!] isolated collector still unavailable'
            $Rows = @(Invoke-SecurityAuditBaseline -Definition $Definition -Scope Machine -Target 'fixture-host' -Catalog @{})
            $Rows.Count | Should Be 2
            $Rows[0].TestResult | Should Be 'Unknown'
            $Rows[0].ValueOrigin | Should Be 'Unverified'
            $Rows[0].ReasonCode | Should Be 'CollectionError'
            $Rows[0].Details | Should Match 'isolated collector still unavailable'
            $Rows[1].Details | Should Match '개별 재조회: 1; 정상 비교 가능: 0'
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 2 -Exactly -Scope It
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 1 -Exactly -Scope It -ParameterFilter { $FindingID -ceq 'T-01' }
        }
        It 'preserves warning-only isolated diagnostics without changing a clean comparison verdict' {
            $Warning = '[?] 개별 조회 경고 <script>진단 데이터</script>'
            $script:IsolatedReceipts['T-01'].Diagnostics = $Warning
            $Rows = @(Invoke-SecurityAuditBaseline -Definition $Definition -Scope Machine -Target 'fixture-host' -Catalog @{})
            $Rows.Count | Should Be 2
            $Rows[0].TestResult | Should Be 'Passed'
            $Rows[0].EngineTestResult | Should Be 'Passed'
            $Rows[0].ValueOrigin | Should Be 'Observed'
            $Rows[0].ReasonCode | Should Be 'Compared'
            $Rows[0].Details | Should Match ([Regex]::Escape($Warning))
            $Rows[1].TestResult | Should Be 'Error'
            $Rows[1].Details | Should Match ([Regex]::Escape($script:BroadReceipt.Diagnostics))
            $Rows[1].Details | Should Match '개별 재조회: 1; 정상 비교 가능: 1'
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 2 -Exactly -Scope It
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 1 -Exactly -Scope It -ParameterFilter { $FindingID -ceq 'T-01' }
        }
        It 'replaces old evidence with an isolated default without presenting it as an observation' {
            $script:DelayBroadReceipt = $true
            $Fresh = $script:IsolatedReceipts['T-01'].Rows[0]
            $Fresh.Result = '0'
            $Fresh.TestResult = 'Failed'
            $Fresh.DefaultValue = 'True'
            $Rows = @(Invoke-SecurityAuditBaseline -Definition $Definition -Scope Machine -Target 'fixture-host' -Catalog @{})
            $Rows[0].Result | Should Be '0'
            $Rows[0].TestResult | Should Be 'Unknown'
            $Rows[0].EngineTestResult | Should Be 'Failed'
            $Rows[0].UsedDefault | Should Be $true
            $Rows[0].ValueOrigin | Should Be 'Default'
            $Rows[0].ReasonCode | Should Be 'DefaultSubstitution'
            $Rows[0].Details | Should Match 'fresh recommendation'
            $Rows[0].Details | Should Not Match 'old recommendation'
            ([DateTimeOffset]$Rows[0].CheckedAt -gt [DateTimeOffset]$Rows[1].CheckedAt) | Should Be $true
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 2 -Exactly -Scope It
        }
        It 'never promotes or rechecks noncomparable evidence alongside an eligible observation' {
            $Cases = @(
                @{ ID = 'DEFAULT'; Status = 'Unknown'; Origin = 'Default'; Reason = 'DefaultSubstitution' }
                @{ ID = 'NUMERIC'; Status = 'Unknown'; Origin = 'Unverified'; Reason = 'InvalidNumericEvidence' }
                @{ ID = 'MARKER'; Status = 'Unknown'; Origin = 'Unavailable'; Reason = 'CollectorMarker' }
                @{ ID = 'ASR'; Status = 'Unknown'; Origin = 'Unverified'; Reason = 'UnverifiedAsrDefault' }
                @{ ID = 'MISSING'; Status = 'Error'; Origin = 'Unavailable'; Reason = 'MissingResult' }
                @{ ID = 'DUPLICATE'; Status = 'Error'; Origin = 'Unavailable'; Reason = 'DuplicateResult' }
                @{ ID = 'ACCESSCHK'; Status = 'Unknown'; Origin = 'Unverified'; Reason = 'UnverifiedEmptyExport' }
                @{ ID = 'FLAG'; Status = 'Unknown'; Origin = 'Unverified'; Reason = 'UnknownDefaultFlag' }
                @{ ID = 'COLUMN'; Status = 'Error'; Origin = 'Unavailable'; Reason = 'MissingResultColumn' }
                @{ ID = 'EMPTY'; Status = 'Unknown'; Origin = 'Unavailable'; Reason = 'EmptyValue' }
                @{ ID = 'VERDICT'; Status = 'Error'; Origin = 'Unverified'; Reason = 'InvalidEngineVerdict' }
            )
            ForEach ($Case in $Cases) {
                $Item = $Finding.PSObject.Copy()
                $Item.ID = $Case.ID
                $Raw = $EngineRow.PSObject.Copy()
                $Raw.ID = $Case.ID
                Switch ($Case.ID) {
                    'DEFAULT' { $Raw.DefaultValue = 'True' }
                    'NUMERIC' { $Raw.Result = 'not a number' }
                    'MARKER' { $Raw.Result = '-NODATA-' }
                    'ASR' { $Item.Method = 'MpPreferenceAsr'; $Raw.Result = '0' }
                    'ACCESSCHK' { $Item.Method = 'accesschk'; $Raw.Result = ''; $Item.RecommendedValue = '' }
                    'FLAG' { $Raw.DefaultValue = 'unknown' }
                    'COLUMN' { $Raw.PSObject.Properties.Remove('Result') }
                    'EMPTY' { $Raw.Result = ''; $Item.RecommendedValue = 'Enabled' }
                    'VERDICT' { $Raw.TestResult = 'Info' }
                }
                $Definition.Findings += $Item
                If ($Case.ID -ne 'MISSING') { $script:BroadReceipt.Rows += $Raw }
                If ($Case.ID -eq 'DUPLICATE') { $script:BroadReceipt.Rows += $Raw.PSObject.Copy() }
            }
            $Rows = @(Invoke-SecurityAuditBaseline -Definition $Definition -Scope User -Target 'fixture-user' -Catalog @{})
            $Rows.Count | Should Be 13
            ($Rows.ID -join ',') | Should Be (($Definition.Findings.ID -join ',') + ',ENGINE-User')
            @($Rows | Where-Object Scope -eq User).Count | Should Be 12
            $Rows[0].TestResult | Should Be 'Passed'
            $Rows[0].ReasonCode | Should Be 'Compared'
            ForEach ($Case in $Cases) {
                $Row = $Rows | Where-Object ID -eq $Case.ID
                $Row.TestResult | Should Be $Case.Status
                $Row.ValueOrigin | Should Be $Case.Origin
                $Row.ReasonCode | Should Be $Case.Reason
                $Row.CheckedAt | Should Be $Rows[12].CheckedAt
                $Row.Details | Should Not Match '개별 재조회'
            }
            $Rows[12].TestResult | Should Be 'Error'
            $Rows[12].Details | Should Match '누락 1; 중복 ID 1'
            $Rows[12].Details | Should Match '개별 재조회: 1; 정상 비교 가능: 1'
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 2 -Exactly -Scope It
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 1 -Exactly -Scope It -ParameterFilter { $FindingID -ceq 'T-01' }
            Assert-MockCalled Invoke-SecurityAuditEngine -Times 0 -Exactly -Scope It -ParameterFilter {
                -not [String]::IsNullOrEmpty($FindingID) -and $FindingID -cne 'T-01'
            }
        }
    }

    Describe 'Finding CSV definition validation' {
        BeforeEach {
            $Path = Join-Path $TestDrive '보안 기준 [fixture].csv'
            $Finding = [PSCustomObject][ordered]@{
                ID = '001'; Category = '보안 설정'; Name = '한글 항목, 쉼표'; Method = 'Registry'
                RecommendedValue = ''; Operator = '='; Severity = 'High'; Description = '명시적인 빈 값이 허용된 설정을 확인하는 항목입니다.'
            }
        }
        It 'imports literal UTF-8 paths, leading-zero IDs and legitimate empty recommendations' {
            $Finding | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
            $Definition = Import-SecurityAuditList -Path $Path
            $Definition.Path | Should Be (Resolve-Path -LiteralPath $Path).ProviderPath
            $Definition.Name | Should Be '보안 기준 [fixture].csv'
            $Definition.Findings.Count | Should Be 1
            $Definition.Findings[0].ID | Should Be '001'
            $Definition.Findings[0].Name | Should Be '한글 항목, 쉼표'
            $Definition.Findings[0].RecommendedValue | Should Be ''
            $Definition.Findings[0].Description | Should Be $Finding.Description
        }
        It 'rejects empty and header-only definition files' {
            Set-Content -LiteralPath $Path -Value '' -Encoding UTF8
            { Import-SecurityAuditList -Path $Path } | Should Throw 'empty'
            Set-Content -LiteralPath $Path -Value 'ID,Category,Name,Method,RecommendedValue,Operator,Severity' -Encoding UTF8
            { Import-SecurityAuditList -Path $Path } | Should Throw 'empty'
        }
        It 'rejects every missing required column instead of interpreting incomplete definitions' {
            ForEach ($Column in @('ID', 'Category', 'Name', 'Method', 'RecommendedValue', 'Operator', 'Severity')) {
                $Finding | Select-Object -Property ($Finding.PSObject.Properties.Name | Where-Object { $_ -ne $Column }) |
                    Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
                { Import-SecurityAuditList -Path $Path } | Should Throw "missing column $Column"
            }
        }
        It 'rejects duplicate and blank IDs' {
            @($Finding, $Finding) | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
            { Import-SecurityAuditList -Path $Path } | Should Throw 'duplicate finding ID'
            ForEach ($ID in @('', '  ')) {
                $Finding.ID = $ID
                $Finding | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
                { Import-SecurityAuditList -Path $Path } | Should Throw 'Missing or duplicate finding ID'
            }
        }
        It 'rejects missing names and methods and refuses missing files' {
            ForEach ($Property in @('Name', 'Method')) {
                $Broken = $Finding.PSObject.Copy()
                $Broken.$Property = ' '
                $Broken | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
                { Import-SecurityAuditList -Path $Path } | Should Throw 'Missing finding name or method'
            }
            { Import-SecurityAuditList -Path (Join-Path $TestDrive 'absent.csv') } | Should Throw
        }
    }

    Describe 'Baseline explanation catalog' {
        It 'matches all 418 machine and 56 user definitions by exact scope, ID and name' {
            $ModuleRoot = (Get-Module HardeningKitty.SecurityAudit -All).ModuleBase
            $Catalog = Get-SecurityAuditCatalog
            $Catalog.Count | Should Be 474
            ForEach ($Scope in @('Machine', 'User')) {
                $Definition = Import-SecurityAuditList -Path (Join-Path $ModuleRoot "lists\finding_list_0x6d69636b_$($Scope.ToLowerInvariant()).csv")
                $Count = 418
                If ($Scope -eq 'User') { $Count = 56 }
                $Definition.Findings.Count | Should Be $Count
                @($Catalog.Values | Where-Object Scope -eq $Scope).Count | Should Be $Count
                ForEach ($Finding in $Definition.Findings) {
                    $Key = "$Scope`:$($Finding.ID)"
                    $Catalog.ContainsKey($Key) | Should Be $true
                    $Entry = $Catalog[$Key]
                    ($Entry.Scope -ceq $Scope) | Should Be $true
                    ($Entry.ID -ceq $Finding.ID) | Should Be $true
                    ($Entry.Name -ceq $Finding.Name) | Should Be $true
                    $Entry.Description.Length | Should BeGreaterThan 30
                    $Entry.Description | Should Match '[가-힣]'
                    $Entry.Description | Should Not Be $Entry.Name
                    $Entry.Description | Should Not Match 'TODO|설명 없음|추후 작성'
                    Get-SecurityAuditDescription -Finding $Finding -Scope $Scope -Catalog $Catalog | Should Be $Entry.Description
                }
            }
        }
        It 'reads each JSON catalog explicitly as UTF-8 and keeps scope-qualified IDs distinct' {
            Mock Get-Content { '[{"Scope":"Machine","ID":"001","Name":"머신 항목","Description":"머신 설정을 확인하는 한글 설명입니다."}]' } -ParameterFilter { $LiteralPath -like '*descriptions-machine-core.json' }
            Mock Get-Content { '[{"Scope":"User","ID":"001","Name":"사용자 항목","Description":"사용자 설정을 확인하는 한글 설명입니다."}]' } -ParameterFilter { $LiteralPath -like '*descriptions-apps-user.json' }
            Mock Get-Content { '[]' } -ParameterFilter { $LiteralPath -like '*descriptions-machine-platform.json' }
            $Catalog = Get-SecurityAuditCatalog
            $Catalog.Count | Should Be 2
            $Catalog['Machine:001'].Name | Should Be '머신 항목'
            $Catalog['User:001'].Name | Should Be '사용자 항목'
            Assert-MockCalled Get-Content -Times 3 -Exactly -Scope It -ParameterFilter { $Encoding -eq 'UTF8' -and $Raw }
        }
        It 'rejects duplicate or incomplete catalog entries' {
            Mock Get-Content { $script:InvalidCatalog } -ParameterFilter { $true }
            $script:InvalidCatalog = '[{"Scope":"Machine","ID":"1","Name":"a","Description":"description"},{"Scope":"Machine","ID":"1","Name":"b","Description":"other"}]'
            { Get-SecurityAuditCatalog } | Should Throw 'duplicate description entry'
            ForEach ($Json in @(
                '[{"Scope":"Other","ID":"1","Name":"a","Description":"description"}]',
                '[{"Scope":"Machine","ID":"","Name":"a","Description":"description"}]',
                '[{"Scope":"Machine","ID":"1","Name":"","Description":"description"}]',
                '[{"Scope":"Machine","ID":"1","Name":"a","Description":""}]'
            )) {
                $script:InvalidCatalog = $Json
                { Get-SecurityAuditCatalog } | Should Throw 'Invalid or duplicate description entry'
            }
        }
        It 'prefers authored custom descriptions and never borrows catalog text for a different name or scope' {
            $Finding = [PSCustomObject]@{ ID = '1'; Name = 'Original'; Description = '사용자 정의 목록 작성자가 제공한 고유한 보안 설명입니다.'; Method = 'Registry'; RegistryPath = 'HKCU:\Fixture'; RegistryItem = 'Value'; Operator = '='; RecommendedValue = '1' }
            $Catalog = @{ 'Machine:1' = [PSCustomObject]@{ Name = 'Original'; Description = '원본 카탈로그 설명' } }
            Get-SecurityAuditDescription -Finding $Finding -Scope Machine -Catalog $Catalog | Should Be $Finding.Description
            $Finding.Description = ''
            Get-SecurityAuditDescription -Finding $Finding -Scope Machine -Catalog $Catalog | Should Be '원본 카탈로그 설명'
            Get-SecurityAuditDescription -Finding $Finding -Scope User -Catalog $Catalog | Should Match '사용자 정의'
            $Finding.Name = 'Renamed custom item'
            $Description = Get-SecurityAuditDescription -Finding $Finding -Scope Machine -Catalog $Catalog
            $Description | Should Match '사용자 정의'
            $Description | Should Not Match '원본 카탈로그 설명'
            $Description | Should Match 'HKCU:'
        }
    }

    Describe 'Read-only original engine invocation and temporary lifecycle' {
        BeforeEach {
            $script:BaselineTestRoot = $TestDrive
            $script:SimulateCleanupFailure = $false
            $script:SimulateImportFailure = $false
            $script:IgnoreEngineFilter = $false
            $script:EngineProtocolMessages = @()
            $script:EngineNonterminatingError = ''
            $script:EngineCalls = New-Object 'System.Collections.Generic.List[object]'
            $script:EngineDirectories = New-Object 'System.Collections.Generic.List[string]'
            $script:EngineFixture = [PSCustomObject]@{
                ID = 'T-01'; Name = '한글 보안 설정'; Severity = 'High'; Result = '한글 계정, "관리자"'
                Recommended = "첫째 줄`n둘째 줄"; TestResult = 'Passed'; DefaultValue = 'False'
            }
            $OriginalTemp = $env:TEMP
            $OriginalTmp = $env:TMP
            Mock New-SecurityAuditDirectory {
                $Directory = New-Item -Path (Join-Path $script:BaselineTestRoot ([Guid]::NewGuid().ToString('N'))) -ItemType Directory -ErrorAction Stop
                $script:EngineDirectories.Add($Directory.FullName)
                $Directory.FullName
            }
            Mock Invoke-HardeningKitty {
                $script:EngineCalls.Add([PSCustomObject]@{
                    Mode = $Mode; Source = $Source; List = $FileFindingList; Report = [Boolean]$Report; Path = $ReportFile
                    Temp = $env:TEMP; Tmp = $env:TMP; Existed = (Test-Path -LiteralPath $ReportFile)
                    SkipMachine = [Boolean]$SkipMachineInformation; SkipUser = [Boolean]$SkipUserInformation
                    Filter = $Filter
                })
                $Selected = @($script:EngineFixture)
                If ($null -ne $Filter -and -not $script:IgnoreEngineFilter) {
                    $Selected = @($Selected | Where-Object -FilterScript $Filter)
                }
                $Selected | Export-Csv -LiteralPath $ReportFile -NoTypeInformation -Encoding UTF8
                ForEach ($Message in $script:EngineProtocolMessages) { Write-Host $Message }
                If ($script:EngineNonterminatingError) { Write-Error $script:EngineNonterminatingError -ErrorAction Continue }
                'original success-stream chatter must not escape'
            } -ParameterFilter { $true }
            # Return an invokable FunctionInfo whose ScriptBlock owns a real module.
            # Its only delegate is the already-installed Pester proxy, never the native engine.
            $MockCommand = $ExecutionContext.InvokeCommand.GetCommand('Invoke-HardeningKitty', [System.Management.Automation.CommandTypes]::Function)
            $script:EngineCommandModule = New-Module -Name HardeningKitty.EngineMockAdapter -ArgumentList $MockCommand -ScriptBlock {
                Param ($MockCommand)
                $script:MockCommand = $MockCommand
                $script:InvocationCount = 0
                Function Invoke-FixtureEngine {
                    [CmdletBinding()]
                    Param ([String] $Mode, [String] $Source, [String] $FileFindingList, [Switch] $Report,
                        [String] $ReportFile, [Switch] $SkipMachineInformation, [Switch] $SkipUserInformation,
                        [ScriptBlock] $Filter)
                    $script:InvocationCount++
                    & $script:MockCommand @PSBoundParameters
                }
                Export-ModuleMember -Function Invoke-FixtureEngine
            }
            $script:EngineFixtureCommand = $script:EngineCommandModule.ExportedFunctions['Invoke-FixtureEngine']
            Mock Get-Command {
                $script:EngineFixtureCommand
            } -ParameterFilter { $Name -eq 'Invoke-HardeningKitty' -and $CommandType -eq 'Function' }
        }
        AfterEach {
            $script:SimulateCleanupFailure = $false
            $script:SimulateImportFailure = $false
            $script:IgnoreEngineFilter = $false
            $script:EngineProtocolMessages = @()
            $script:EngineNonterminatingError = ''
            $env:TEMP = $OriginalTemp
            $env:TMP = $OriginalTmp
            Remove-Module -ModuleInfo $script:EngineCommandModule -ErrorAction Ignore
            $script:EngineFixtureCommand = $null
            $script:EngineCommandModule = $null
        }
        It 'uses only Audit and GPO with explicit fresh report paths for sequential scopes' {
            $First = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
            $Second = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\user.csv'
            $First.Completed | Should Be $true
            $Second.Completed | Should Be $true
            $First.Error | Should Be ''
            $Second.Error | Should Be ''
            $script:EngineCalls.Count | Should Be 2
            ($script:EngineFixtureCommand -is [System.Management.Automation.FunctionInfo]) | Should Be $true
            $script:EngineFixtureCommand.ScriptBlock.Module.Name | Should Be 'HardeningKitty.EngineMockAdapter'
            $script:EngineFixtureCommand.ScriptBlock.Module.SessionState.PSVariable.GetValue('script:InvocationCount') | Should Be 2
            $script:EngineCalls[0].Path | Should Not Be $script:EngineCalls[1].Path
            ForEach ($Call in $script:EngineCalls) {
                $Call.Mode | Should Be 'Audit'
                $Call.Source | Should Be 'GPO'
                $Call.Report | Should Be $true
                $Call.Existed | Should Be $false
                $Call.SkipMachine | Should Be $true
                $Call.SkipUser | Should Be $true
                ($null -eq $Call.Filter) | Should Be $true
                $Call.Temp | Should Be (Split-Path -Parent $Call.Path)
                $Call.Tmp | Should Be $Call.Temp
                Test-Path -LiteralPath $Call.Temp | Should Be $false
            }
            $env:TEMP | Should Be $OriginalTemp
            $env:TMP | Should Be $OriginalTmp
            Assert-MockCalled Invoke-HardeningKitty -Times 2 -Exactly -Scope It -ParameterFilter {
                $Mode -eq 'Audit' -and $Source -eq 'GPO' -and $Report -and $SkipMachineInformation -and $SkipUserInformation -and
                -not $Log -and -not $Backup -and -not $AllowCustomList
            }
            Assert-MockCalled Invoke-HardeningKitty -Times 1 -Exactly -Scope It -ParameterFilter { $FileFindingList -eq 'C:\fixture\machine.csv' }
            Assert-MockCalled Invoke-HardeningKitty -Times 1 -Exactly -Scope It -ParameterFilter { $FileFindingList -eq 'C:\fixture\user.csv' }
        }
        It 'filters exactly one case-sensitive string ID and treats quotes and wildcard syntax as data' {
            $HostileID = 'q''"; throw "fixture injection"; # [*?] $(throw "fixture expansion")'
            $Cases = @(
                @{ ID = '001'; Others = @(1, '01', '0001', '001suffix') }
                @{ ID = 'AbC'; Others = @('abc', 'ABC', 'AbCsuffix', 'T-01') }
                @{ ID = $HostileID; Others = @('q-anything', 'q"; throw "fixture injection"; # [x]', 'OTHER') }
            )
            $Template = $script:EngineFixture.PSObject.Copy()
            ForEach ($Case in $Cases) {
                $Requested = $Template.PSObject.Copy()
                $Requested.ID = $Case.ID
                $Candidates = @($Requested)
                ForEach ($OtherID in $Case.Others) {
                    $Other = $Template.PSObject.Copy()
                    $Other.ID = $OtherID
                    $Candidates += $Other
                }
                $script:EngineFixture = $Candidates
                $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\선택 목록.csv' -FindingID $Case.ID
                $Run.Completed | Should Be $true
                $Run.Error | Should Be ''
                $Run.HasErrors | Should Be $false
                $Run.Rows.Count | Should Be 1
                ($Run.Rows[0].ID -ceq $Case.ID) | Should Be $true
                $Run.Rows[0].Result | Should Be $Template.Result
            }
            $script:EngineCalls.Count | Should Be 3
            @($script:EngineCalls.Path | Select-Object -Unique).Count | Should Be 3
            # Reevaluate the saved closures after the engine invocation and later selections end.
            $SelectedID = 'caller shadow must not replace the captured ID'
            $FindingID = 'caller shadow must not replace the captured ID'
            $Probe = @($Cases | ForEach-Object { [PSCustomObject]@{ ID = $_.ID } })
            For ($Index = 0; $Index -lt $Cases.Count; $Index++) {
                $Call = $script:EngineCalls[$Index]
                ($Call.Filter -is [ScriptBlock]) | Should Be $true
                $Selected = @($Probe | Where-Object -FilterScript $Call.Filter)
                $Selected.Count | Should Be 1
                ($Selected[0].ID -ceq $Cases[$Index].ID) | Should Be $true
                $Call.Mode | Should Be 'Audit'
                $Call.Source | Should Be 'GPO'
                $Call.List | Should Be 'C:\fixture\선택 목록.csv'
                $Call.Report | Should Be $true
                $Call.Existed | Should Be $false
                $Call.SkipMachine | Should Be $true
                $Call.SkipUser | Should Be $true
                $Call.Temp | Should Be (Split-Path -Parent $Call.Path)
                $Call.Tmp | Should Be $Call.Temp
                Test-Path -LiteralPath $Call.Temp | Should Be $false
            }
            $env:TEMP | Should Be $OriginalTemp
            $env:TMP | Should Be $OriginalTmp
            Assert-MockCalled Invoke-HardeningKitty -Times 3 -Exactly -Scope It -ParameterFilter {
                $Filter -is [ScriptBlock] -and $Mode -eq 'Audit' -and $Source -eq 'GPO' -and
                $Report -and $SkipMachineInformation -and $SkipUserInformation -and
                -not $Log -and -not $Backup -and -not $AllowCustomList
            }
        }
        It 'rejects empty, duplicate, wrong, case-mismatched, numeric-alias and extra isolated output IDs' {
            $Template = $script:EngineFixture.PSObject.Copy()
            $script:IgnoreEngineFilter = $true
            ForEach ($Case in @('Empty', 'Duplicate', 'Wrong', 'WrongCase', 'NumericAlias', 'Extra')) {
                $RequestedID = 'T-01'
                $First = $Template.PSObject.Copy()
                $First.ID = $RequestedID
                $OutputRows = @($First)
                Switch ($Case) {
                    'Empty' { $OutputRows = @() }
                    'Duplicate' { $OutputRows = @($First, $First.PSObject.Copy()) }
                    'Wrong' { $First.ID = 'OTHER' }
                    'WrongCase' { $First.ID = 't-01' }
                    'NumericAlias' { $RequestedID = '001'; $First.ID = '1' }
                    'Extra' {
                        $Extra = $First.PSObject.Copy()
                        $Extra.ID = 'OTHER'
                        $OutputRows += $Extra
                    }
                }
                $script:EngineFixture = $OutputRows
                $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv' -FindingID $RequestedID
                $Run.Completed | Should Be $true
                $Run.Error | Should Match '단일 행'
                $Run.Error | Should Match ([Regex]::Escape($RequestedID))
                $Run.Rows.Count | Should Be $OutputRows.Count
                $env:TEMP | Should Be $OriginalTemp
                $env:TMP | Should Be $OriginalTmp
            }
            ForEach ($Directory in $script:EngineDirectories) { Test-Path -LiteralPath $Directory | Should Be $false }
            Assert-MockCalled Invoke-HardeningKitty -Times 6 -Exactly -Scope It -ParameterFilter { $Filter -is [ScriptBlock] }
        }
        It 'rejects explicitly empty or null FindingID before invoking the engine or creating exports' {
            { Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv' -FindingID '' } | Should Throw
            { Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv' -FindingID $null } | Should Throw
            $script:EngineDirectories.Count | Should Be 0
            Assert-MockCalled Invoke-HardeningKitty -Times 0 -Exactly -Scope It
        }
        It 'round-trips non-ASCII, quotes, commas and multiline CSV without leaking engine pipeline output' {
            $Receipts = @(Invoke-SecurityAuditEngine -ListPath 'C:\fixture\한글 목록.csv')
            $Receipts.Count | Should Be 1
            $Receipts[0].Rows.Count | Should Be 1
            $Receipts[0].Rows[0].Result | Should Be $script:EngineFixture.Result
            $Receipts[0].Rows[0].Recommended | Should Be $script:EngineFixture.Recommended
            $Receipts[0].Rows[0].DefaultValue | Should Be 'False'
            $Receipts[0].HasErrors | Should Be $false
        }
        It 'does not mutate caller encoding preferences or unrelated parameter defaults' {
            $SavedDefaults = $PSDefaultParameterValues
            Try {
                $PSDefaultParameterValues = @{ 'Export-Csv:Encoding' = 'ASCII'; 'Get-Content:Encoding' = 'Unicode' }
                $CallerDefaults = $PSDefaultParameterValues
                $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
                $Run.Rows[0].Result | Should Be $script:EngineFixture.Result
                [Object]::ReferenceEquals($CallerDefaults, $PSDefaultParameterValues) | Should Be $true
                $PSDefaultParameterValues.Count | Should Be 2
                $PSDefaultParameterValues['Export-Csv:Encoding'] | Should Be 'ASCII'
                $PSDefaultParameterValues['Get-Content:Encoding'] | Should Be 'Unicode'
            } Finally {
                $PSDefaultParameterValues = $SavedDefaults
            }
        }
        It 'recognizes a complete corroborated High failure including the raw Name field as a verdict rather than an error' {
            $script:EngineFixture.Name = '정책, "이름" <script>fixture</script>'
            $script:EngineFixture.TestResult = 'Failed'
            $script:EngineFixture.Result = '0'
            $script:EngineFixture.Recommended = '1'
            $Verdict = "[!] ID T-01, $($script:EngineFixture.Name), Result=0, Recommended=1, Severity=High"
            $script:EngineProtocolMessages = @($Verdict, $Verdict, '[?] 한글 진단은 유지')
            $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
            $Run.Completed | Should Be $true
            $Run.Error | Should Be ''
            $Run.HasErrors | Should Be $false
            $Run.Rows[0].Name | Should Be $script:EngineFixture.Name
            $Run.Rows[0].TestResult | Should Be 'Failed'
            $Run.Diagnostics | Should Not Match ([Regex]::Escape($Verdict))
            $Run.Diagnostics | Should Match '한글 진단은 유지'
            $Finding = [PSCustomObject]@{
                ID = 'T-01'; Name = $script:EngineFixture.Name; Category = 'Fixture'; Method = 'Registry'
                RegistryPath = 'HKLM:\Fixture'; RegistryItem = 'Value'; Operator = '='; RecommendedValue = '1'
                Severity = 'High'; DefaultValue = '0'; Description = '작성된 보안 설명'
            }
            $Definition = [PSCustomObject]@{ Path = 'C:\fixture\machine.csv'; Name = 'machine.csv'; Findings = @($Finding) }
            $Rows = @(ConvertFrom-SecurityAuditEngineReport -Definition $Definition -Run $Run -Scope Machine -Target 'fixture' -Catalog @{} -CheckedAt ([DateTimeOffset]::Now))
            ($Rows.TestResult -join ',') | Should Be 'Failed,Info'
            $Rows[0].ValueOrigin | Should Be 'Observed'
            $Rows[0].ReasonCode | Should Be 'Compared'
        }
        It 'recognizes the native engine negated recommendation spelling for a genuine High inequality failure' {
            $script:EngineFixture.TestResult = 'Failed'
            $script:EngineFixture.Result = '1'
            $script:EngineFixture.Recommended = '1'
            $script:EngineProtocolMessages = @("[!] ID T-01, $($script:EngineFixture.Name), Result=1, Recommended=Not 1, Severity=High")
            $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
            $Run.Error | Should Be ''
            $Run.HasErrors | Should Be $false
            $Run.Rows[0].Recommended | Should Be '1'
            $Run.Diagnostics | Should Be ''
            $script:EngineProtocolMessages += '[!] unrelated inequality collector error'
            $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
            $Run.Error | Should Be ''
            $Run.HasErrors | Should Be $true
            $Run.Diagnostics | Should Be '[!] unrelated inequality collector error'
        }
        It 'retains mismatched and incomplete High-looking messages instead of parsing them as trusted verdicts' {
            $script:EngineFixture.Name = '검증된 항목'
            $script:EngineFixture.TestResult = 'Failed'
            $script:EngineFixture.Result = '0'
            $script:EngineFixture.Recommended = '1'
            $Verdict = '[!] ID T-01, 검증된 항목, Result=0, Recommended=1, Severity=High'
            $Messages = @(
                '[!] ID OTHER, 검증된 항목, Result=0, Recommended=1, Severity=High'
                '[!] ID T-01, 다른 이름, Result=0, Recommended=1, Severity=High'
                '[!] ID T-01, 검증된 항목, Result=9, Recommended=1, Severity=High'
                '[!] ID T-01, 검증된 항목, Result=0, Recommended=2, Severity=High'
                '[!] ID T-01, 검증된 항목, Result=0, Recommended=Not 2, Severity=High'
                '[!] ID T-01, 검증된 항목, Result=0, Recommended=1, Severity=Low'
                '[!] ID T-01, Result=0, Recommended=1, Severity=High'
                '[!] ID t-01, 검증된 항목, Result=0, Recommended=1, Severity=High'
                '[!] ID T-01, 검증된 항목, Result=0, Recommended=1, Severity=high'
                '[!] ID T-01, 검증된 항목, Result=0, Recommended=1, Severity=High; <script>오류</script>'
            )
            ForEach ($Message in $Messages) {
                $script:EngineProtocolMessages = @($Verdict, $Message)
                $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
                $Run.Completed | Should Be $true
                $Run.Error | Should Be ''
                $Run.HasErrors | Should Be $true
                ($Run.Diagnostics -ceq $Message) | Should Be $true
            }
        }
        It 'requires an actual Failed High CSV row before ignoring a matching-looking verdict message' {
            $script:EngineFixture.Name = '검증된 항목'
            $script:EngineFixture.Result = '0'
            $script:EngineFixture.Recommended = '1'
            $script:EngineProtocolMessages = @('[!] ID T-01, 검증된 항목, Result=0, Recommended=1, Severity=High')
            ForEach ($Case in @('Passed', 'Medium', 'NoSeverity', 'NoName')) {
                $Raw = $script:EngineFixture.PSObject.Copy()
                $Raw.TestResult = 'Failed'
                $Raw.Severity = 'High'
                Switch ($Case) {
                    'Passed' { $Raw.TestResult = 'Passed' }
                    'Medium' { $Raw.Severity = 'Medium' }
                    'NoSeverity' { $Raw.PSObject.Properties.Remove('Severity') }
                    'NoName' { $Raw.PSObject.Properties.Remove('Name') }
                }
                $Saved = $script:EngineFixture
                $script:EngineFixture = $Raw
                $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
                $script:EngineFixture = $Saved
                $Run.Error | Should Be ''
                $Run.HasErrors | Should Be $true
                $Run.Diagnostics | Should Be $script:EngineProtocolMessages[0]
            }
        }
        It 'never suppresses a real ErrorRecord even when a corroborated High verdict is also present' {
            $script:EngineFixture.TestResult = 'Failed'
            $script:EngineFixture.Result = '0'
            $script:EngineFixture.Recommended = '1'
            $Verdict = "[!] ID T-01, $($script:EngineFixture.Name), Result=0, Recommended=1, Severity=High"
            $script:EngineProtocolMessages = @($Verdict)
            ForEach ($Message in @('fixture 실제 수집 오류 <script>진단 데이터</script>', $Verdict)) {
                $script:EngineNonterminatingError = $Message
                $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
                $Run.Completed | Should Be $true
                $Run.Error | Should Be ''
                $Run.Rows.Count | Should Be 1
                $Run.HasErrors | Should Be $true
                $Run.Diagnostics | Should Match ([Regex]::Escape($Message))
            }
        }
        It 'captures warning, host-error and nonterminating-error diagnostics and deduplicates messages' {
            Mock Invoke-HardeningKitty {
                $script:EngineFixture | Export-Csv -LiteralPath $ReportFile -NoTypeInformation -Encoding UTF8
                Write-Information '[?] Finding list is custom: fixture' -InformationAction Continue
                Write-Information '[!] collector host failure' -InformationAction Continue
                Write-Information '[i] irrelevant successful finding' -InformationAction Continue
                Write-Warning 'duplicate fixture warning'
                Write-Warning 'duplicate fixture warning'
                Write-Error 'fixture nonterminating failure' -ErrorAction Continue
            } -ParameterFilter { $true }
            $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
            $Run.Completed | Should Be $true
            $Run.Error | Should Be ''
            $Run.HasErrors | Should Be $true
            $Run.Rows.Count | Should Be 1
            $Run.Diagnostics | Should Match 'Finding list is custom'
            $Run.Diagnostics | Should Match 'collector host failure'
            $Run.Diagnostics | Should Match 'fixture nonterminating failure'
            $Run.Diagnostics | Should Not Match 'irrelevant successful finding'
            [Regex]::Matches($Run.Diagnostics, 'duplicate fixture warning').Count | Should Be 1
        }
        It 'treats an Error-level host message alone as an execution error' {
            Mock Invoke-HardeningKitty {
                $script:EngineFixture | Export-Csv -LiteralPath $ReportFile -NoTypeInformation -Encoding UTF8
                Write-Host '[!] host-only failure'
            } -ParameterFilter { $true }
            $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
            $Run.HasErrors | Should Be $true
            $Run.Diagnostics | Should Match 'host-only failure'
        }
        It 'records a nonterminating error without requiring an Error-level host message' {
            Mock Invoke-HardeningKitty {
                $script:EngineFixture | Export-Csv -LiteralPath $ReportFile -NoTypeInformation -Encoding UTF8
                Write-Error 'fixture standalone error' -ErrorAction Continue
            } -ParameterFilter { $true }
            $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
            $Run.Completed | Should Be $true
            $Run.Rows.Count | Should Be 1
            $Run.HasErrors | Should Be $true
            $Run.Diagnostics | Should Match 'fixture standalone error'
        }
        It 'bounds verbose diagnostics while retaining an explicit truncation notice' {
            Mock Invoke-HardeningKitty {
                $script:EngineFixture | Export-Csv -LiteralPath $ReportFile -NoTypeInformation -Encoding UTF8
                Write-Warning ('fixture start ' + ('x' * 9000) + ' omitted ending')
            } -ParameterFilter { $true }
            $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
            $Run.Diagnostics.Length | Should BeLessThan 8100
            $Run.Diagnostics | Should Match '^fixture start '
            $Run.Diagnostics | Should Match '추가 진단 메시지 생략'
            $Run.Diagnostics | Should Not Match 'omitted ending'
            $Run.HasErrors | Should Be $false
        }
        It 'removes temporary files and restores TEMP and TMP after a terminating engine failure' {
            Mock Invoke-HardeningKitty {
                Set-Content -LiteralPath (Join-Path $env:TEMP 'security-policy.inf') -Value 'private fixture'
                Throw 'fixture terminating failure'
            } -ParameterFilter { $true }
            $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
            $Run.Completed | Should Be $false
            $Run.Error | Should Match 'fixture terminating failure'
            $Run.Rows.Count | Should Be 0
            $script:EngineDirectories.Count | Should Be 1
            Test-Path -LiteralPath $script:EngineDirectories[0] | Should Be $false
            $env:TEMP | Should Be $OriginalTemp
            $env:TMP | Should Be $OriginalTmp
        }
        It 'reports a missing output CSV and still removes the temporary directory' {
            Mock Invoke-HardeningKitty {} -ParameterFilter { $true }
            $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
            $Run.Completed | Should Be $true
            $Run.Error | Should Match 'CSV'
            $Run.Rows.Count | Should Be 0
            Test-Path -LiteralPath $script:EngineDirectories[0] | Should Be $false
            $env:TEMP | Should Be $OriginalTemp
            $env:TMP | Should Be $OriginalTmp
        }
        It 'cleans up after CSV import failures and restores absent TEMP and TMP variables' {
            $script:SimulateImportFailure = $true
            Mock Import-Csv { Throw 'fixture CSV unreadable' } -ParameterFilter { $script:SimulateImportFailure }
            $env:TEMP = $null
            $env:TMP = $null
            $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
            $Run.Error | Should Match 'fixture CSV unreadable'
            Test-Path -LiteralPath $script:EngineDirectories[0] | Should Be $false
            ($null -eq $env:TEMP) | Should Be $true
            ($null -eq $env:TMP) | Should Be $true
            Assert-MockCalled Import-Csv -Times 1 -Exactly -Scope It -ParameterFilter { $Encoding -eq 'UTF8' }
        }
        It 'reports cleanup failure rather than claiming private exports were removed' {
            $script:SimulateCleanupFailure = $true
            Mock Remove-Item { Throw 'fixture cleanup denied' } -ParameterFilter {
                $script:SimulateCleanupFailure -and $LiteralPath -in $script:EngineDirectories
            }
            $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
            $Run.Error | Should Match '임시 디렉터리 정리 실패'
            $Run.Error | Should Match 'fixture cleanup denied'
            $Run.Error | Should Match ([Regex]::Escape($script:EngineDirectories[0]))
            $env:TEMP | Should Be $OriginalTemp
            $env:TMP | Should Be $OriginalTmp
            # TestDrive owns the fixture directory and removes it after mocks are restored.
        }
        It 'does not invoke the original command if secure temporary-directory creation fails' {
            Mock New-SecurityAuditDirectory { Throw 'fixture directory denied' }
            { Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv' } | Should Throw 'fixture directory denied'
            Assert-MockCalled Invoke-HardeningKitty -Times 0 -Exactly -Scope It
            $env:TEMP | Should Be $OriginalTemp
            $env:TMP | Should Be $OriginalTmp
        }
        It 'refuses a non-module-backed original command and still cleans up without invoking it' {
            $UnboundPipeline = [System.Management.Automation.PowerShell]::Create()
            Try {
                $script:UnboundEngineCommand = @($UnboundPipeline.AddScript(@'
Function Invoke-UnboundEngineFixture { Throw 'The unbound fixture must not execute.' }
Get-Command Invoke-UnboundEngineFixture -CommandType Function
'@).Invoke())[0]
                ($script:UnboundEngineCommand -is [System.Management.Automation.FunctionInfo]) | Should Be $true
                ($null -eq $script:UnboundEngineCommand.ScriptBlock.Module) | Should Be $true
                Mock Get-Command { $script:UnboundEngineCommand } -ParameterFilter {
                    $Name -eq 'Invoke-HardeningKitty' -and $CommandType -eq 'Function'
                }
                $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
                $Run.Completed | Should Be $false
                $Run.Error | Should Match 'Import HardeningKitty.psd1'
                Test-Path -LiteralPath $script:EngineDirectories[0] | Should Be $false
                Assert-MockCalled Invoke-HardeningKitty -Times 0 -Exactly -Scope It
                $env:TEMP | Should Be $OriginalTemp
                $env:TMP | Should Be $OriginalTmp
            } Finally {
                $UnboundPipeline.Dispose()
                $script:UnboundEngineCommand = $null
            }
        }
        It 'keeps caller encoding preferences unchanged on failures as well as successful runs' {
            Mock Invoke-HardeningKitty { Throw 'fixture engine failure' } -ParameterFilter { $true }
            $SavedDefaults = $PSDefaultParameterValues
            Try {
                $PSDefaultParameterValues = @{ 'Export-Csv:Encoding' = 'Unicode' }
                $CallerDefaults = $PSDefaultParameterValues
                $Run = Invoke-SecurityAuditEngine -ListPath 'C:\fixture\machine.csv'
                $Run.Error | Should Match 'fixture engine failure'
                [Object]::ReferenceEquals($CallerDefaults, $PSDefaultParameterValues) | Should Be $true
                $PSDefaultParameterValues['Export-Csv:Encoding'] | Should Be 'Unicode'
                $PSDefaultParameterValues.Count | Should Be 1
            } Finally {
                $PSDefaultParameterValues = $SavedDefaults
            }
        }
    }
}

Describe 'Original module boundary in an isolated runspace' {
    BeforeEach {
        # Module-backed doubles exercise PowerShell's real preference scope rules.
        # A separate runspace also prevents Break/Continue from escaping into Pester.
        $Harness = @'
Param ($Manifest, $FixtureRoot, $Control, $InitialState)
$ErrorActionPreference = 'Stop'
Import-Module $Manifest -Force
$Fake = New-Module -Name HardeningKitty.TestEngine -ArgumentList $Control, $InitialState -ScriptBlock {
    Param ($Control, $InitialState)
    $script:FixtureControl = $Control
    $script:FixtureEngineCalled = $false
    $script:ObservedEncoding = ''
    $script:ObservedUnrelated = ''
    $script:DefaultsWereCloned = $false
    $script:InitialDefaults = $null
    If ($InitialState -eq 'Present') {
        $script:PSDefaultParameterValues = @{ 'Export-Csv:Encoding' = 'ASCII'; 'Get-Content:Encoding' = 'Unicode' }
        $script:InitialDefaults = $script:PSDefaultParameterValues
    } ElseIf (Get-Variable -Name PSDefaultParameterValues -Scope Script -ErrorAction Ignore) {
        Remove-Variable -Name PSDefaultParameterValues -Scope Script
    }
    Function Invoke-HardeningKitty {
        [CmdletBinding()]
        Param ([String] $Mode, [String] $Source, [String] $FileFindingList, [Switch] $Report,
            [String] $ReportFile, [Switch] $SkipMachineInformation, [Switch] $SkipUserInformation,
            [ScriptBlock] $Filter)
        $script:FixtureEngineCalled = $true
        $script:FilterReceived = $null -ne $Filter
        If ($Mode -ne 'Audit' -or $Source -ne 'GPO') { Throw 'Unsafe mode in fixture.' }
        $script:ObservedEncoding = $PSDefaultParameterValues['Export-Csv:Encoding']
        $script:ObservedUnrelated = $PSDefaultParameterValues['Get-Content:Encoding']
        $script:DefaultsWereCloned = -not [Object]::ReferenceEquals($script:InitialDefaults, $PSDefaultParameterValues)
        $FixtureRows = @([PSCustomObject]@{
            ID = 'T-01'; Result = '한글 계정, "관리자"'; Recommended = "첫째 줄`n둘째 줄"; TestResult = 'Passed'; DefaultValue = 'False'
        })
        If ($script:FixtureControl -eq 'Filter') {
            ForEach ($ID in @('t-01', 'T-02')) {
                $Other = $FixtureRows[0].PSObject.Copy()
                $Other.ID = $ID
                $FixtureRows += $Other
            }
        }
        If ($null -ne $Filter) { $FixtureRows = @($FixtureRows | Where-Object -FilterScript $Filter) }
        $FixtureRows | Export-Csv -LiteralPath $ReportFile -NoTypeInformation
        If ($script:FixtureControl -eq 'Throw') { Throw 'fixture module failure' }
        If ($script:FixtureControl -eq 'Break') { Break }
        If ($script:FixtureControl -eq 'Continue') { Continue }
    }
    Export-ModuleMember -Function Invoke-HardeningKitty
}
$AuditModule = Get-Module HardeningKitty.SecurityAudit -All
& $AuditModule {
    Param ($FixtureRoot, $Fake)
    $BeforeTemp = $env:TEMP
    $BeforeTmp = $env:TMP
    $PSDefaultParameterValues = @{ 'Export-Csv:Encoding' = 'Unicode'; 'Get-Content:Encoding' = 'ASCII' }
    $CallerDefaults = $PSDefaultParameterValues
    $script:FixtureDirectory = Join-Path $FixtureRoot ([Guid]::NewGuid().ToString('N'))
    Function script:New-SecurityAuditDirectory {
        (New-Item -Path $script:FixtureDirectory -ItemType Directory -ErrorAction Stop).FullName
    }
    Set-Item -Path Function:\script:Invoke-HardeningKitty -Value $Fake.ExportedFunctions['Invoke-HardeningKitty'].ScriptBlock -Force
    $Resolved = Get-Command Invoke-HardeningKitty -CommandType Function
    If ($Resolved -isnot [System.Management.Automation.FunctionInfo] -or
        $Resolved.ScriptBlock.Module.Name -ne 'HardeningKitty.TestEngine') {
        Throw 'The safe fixture command was not installed with its fake module binding.'
    }
    $EngineSession = $Resolved.ScriptBlock.Module.SessionState
    $Selection = @{}
    If ($EngineSession.PSVariable.GetValue('script:FixtureControl') -eq 'Filter') { $Selection.FindingID = 'T-01' }
    $Run = Invoke-SecurityAuditEngine -ListPath 'mock-only.csv' @Selection
    $After = $EngineSession.PSVariable.Get('script:PSDefaultParameterValues')
    $Initial = $EngineSession.PSVariable.GetValue('script:InitialDefaults')
    $SameDefaults = $false
    If ($null -ne $After) { $SameDefaults = [Object]::ReferenceEquals($Initial, $After.Value) }
    $InitialEncoding = ''
    $InitialCount = 0
    If ($null -ne $Initial) {
        $InitialEncoding = $Initial['Export-Csv:Encoding']
        $InitialCount = $Initial.Count
    }
    [PSCustomObject]@{
        Resumed = $true
        EngineCalled = $EngineSession.PSVariable.GetValue('script:FixtureEngineCalled')
        FilterReceived = $EngineSession.PSVariable.GetValue('script:FilterReceived')
        ObservedEncoding = $EngineSession.PSVariable.GetValue('script:ObservedEncoding')
        ObservedUnrelated = $EngineSession.PSVariable.GetValue('script:ObservedUnrelated')
        DefaultsWereCloned = $EngineSession.PSVariable.GetValue('script:DefaultsWereCloned')
        ScriptDefaultsExist = $null -ne $After
        SameDefaults = $SameDefaults
        OriginalEncoding = $InitialEncoding
        OriginalCount = $InitialCount
        CallerSameDefaults = [Object]::ReferenceEquals($CallerDefaults, $PSDefaultParameterValues)
        CallerEncoding = $PSDefaultParameterValues['Export-Csv:Encoding']
        CallerUnrelated = $PSDefaultParameterValues['Get-Content:Encoding']
        Completed = $Run.Completed
        Failure = $Run.Error
        Rows = @($Run.Rows).Count
        Value = ($Run.Rows | Select-Object -First 1).Result
        Recommendation = ($Run.Rows | Select-Object -First 1).Recommended
        DirectoryRemoved = -not (Test-Path -LiteralPath $script:FixtureDirectory)
        TempRestored = $env:TEMP -eq $BeforeTemp
        TmpRestored = $env:TMP -eq $BeforeTmp
    }
} $FixtureRoot $Fake
'@
        Function Invoke-EngineModuleFixture {
            Param ([String] $Control, [String] $InitialState = 'Present')
            $OriginalTemp = $env:TEMP
            $OriginalTmp = $env:TMP
            $Pipeline = [System.Management.Automation.PowerShell]::Create()
            Try {
                [void]$Pipeline.AddScript($Harness).AddArgument((Join-Path $Root 'HardeningKitty.psd1')).AddArgument($TestDrive).AddArgument($Control).AddArgument($InitialState)
                $Pending = $Pipeline.BeginInvoke()
                If (-not $Pending.AsyncWaitHandle.WaitOne(15000)) {
                    $Pipeline.Stop()
                    Throw "The $Control fixture did not return within the runspace safety limit."
                }
                $Receipts = @($Pipeline.EndInvoke($Pending))
                $Pipeline.Streams.Error.Count | Should Be 0
                $Receipts.Count | Should Be 1
                $Receipts[0].Resumed | Should Be $true
                $Receipts[0].EngineCalled | Should Be $true
                $Receipts[0].DirectoryRemoved | Should Be $true
                $Receipts[0].TempRestored | Should Be $true
                $Receipts[0].TmpRestored | Should Be $true
                $Receipts[0].CallerSameDefaults | Should Be $true
                $Receipts[0].CallerEncoding | Should Be 'Unicode'
                $Receipts[0].CallerUnrelated | Should Be 'ASCII'
                $Receipts[0]
            } Finally {
                $Pipeline.Dispose()
                $env:TEMP = $OriginalTemp
                $env:TMP = $OriginalTmp
            }
        }
    }
    It 'round-trips UTF-8 from a different module and restores its exact existing preference object' {
        $Receipt = Invoke-EngineModuleFixture -Control Success
        $Receipt.Completed | Should Be $true
        $Receipt.Failure | Should Be ''
        $Receipt.Rows | Should Be 1
        $Receipt.Value | Should Be '한글 계정, "관리자"'
        $Receipt.Recommendation | Should Be "첫째 줄`n둘째 줄"
        $Receipt.ObservedEncoding | Should Be 'UTF8'
        $Receipt.ObservedUnrelated | Should Be 'Unicode'
        $Receipt.DefaultsWereCloned | Should Be $true
        $Receipt.ScriptDefaultsExist | Should Be $true
        $Receipt.SameDefaults | Should Be $true
        $Receipt.OriginalEncoding | Should Be 'ASCII'
        $Receipt.OriginalCount | Should Be 2
    }
    It 'evaluates the isolated ID closure inside a different module without leaking encoding preferences' {
        $Receipt = Invoke-EngineModuleFixture -Control Filter
        $Receipt.Completed | Should Be $true
        $Receipt.Failure | Should Be ''
        $Receipt.FilterReceived | Should Be $true
        $Receipt.Rows | Should Be 1
        $Receipt.Value | Should Be '한글 계정, "관리자"'
        $Receipt.ObservedEncoding | Should Be 'UTF8'
        $Receipt.ObservedUnrelated | Should Be 'Unicode'
        $Receipt.SameDefaults | Should Be $true
        $Receipt.OriginalEncoding | Should Be 'ASCII'
        $Receipt.OriginalCount | Should Be 2
    }
    It 'removes a newly introduced module preference variable after a successful UTF-8 export' {
        $Receipt = Invoke-EngineModuleFixture -Control Success -InitialState Absent
        $Receipt.Completed | Should Be $true
        $Receipt.Failure | Should Be ''
        $Receipt.Value | Should Be '한글 계정, "관리자"'
        $Receipt.ObservedEncoding | Should Be 'UTF8'
        $Receipt.ScriptDefaultsExist | Should Be $false
    }
    It 'restores existing and absent module preference states after terminating failures' {
        ForEach ($State in @('Present', 'Absent')) {
            $Receipt = Invoke-EngineModuleFixture -Control Throw -InitialState $State
            $Receipt.Completed | Should Be $false
            $Receipt.Failure | Should Match 'fixture module failure'
            $Receipt.ObservedEncoding | Should Be 'UTF8'
            If ($State -eq 'Present') {
                $Receipt.SameDefaults | Should Be $true
                $Receipt.OriginalEncoding | Should Be 'ASCII'
                $Receipt.OriginalCount | Should Be 2
            } Else {
                $Receipt.ScriptDefaultsExist | Should Be $false
            }
        }
    }
    It 'contains unlabeled Break and Continue without escaping the audit boundary or skipping cleanup' {
        ForEach ($Control in @('Break', 'Continue')) {
            $Receipt = Invoke-EngineModuleFixture -Control $Control
            $Receipt.Completed | Should Be $false
            $Receipt.Failure | Should Match '정상 반환'
            $Receipt.Rows | Should Be 1
            $Receipt.SameDefaults | Should Be $true
            $Receipt.OriginalEncoding | Should Be 'ASCII'
        }
    }
}
