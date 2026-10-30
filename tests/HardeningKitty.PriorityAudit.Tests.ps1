#Requires -Version 5.1

$Root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $Root 'HardeningKitty.psd1') -Force

Describe 'Priority helpers remain private' {
    It 'does not export classification helpers from either module' {
        ForEach ($Name in @('HardeningKitty', 'HardeningKitty.SecurityAudit')) {
            $Module = Get-Module $Name -All | Select-Object -First 1
            ForEach ($Private in @('Get-SecurityAuditPriorityReference', 'Set-SecurityAuditPriority')) {
                ($Module.ExportedFunctions.Keys -contains $Private) | Should Be $false
            }
        }
    }
}

InModuleScope HardeningKitty.SecurityAudit {
    Describe 'Priority reference loading' {
        It 'reads each bundled list once and keeps identical IDs in distinct exact scope keys' {
            Mock Import-Csv {
                [PSCustomObject]@{
                    ID = '1421'; Name = 'Fixture log capacity'; Method = 'Registry'
                    RegistryPath = 'HKLM:\Software\Fixture'; RegistryItem = 'Capacity'
                    RecommendedValue = '16384'; Operator = '>='
                }
            }
            $Reference = Get-SecurityAuditPriorityReference
            ($Reference -is [Hashtable]) | Should Be $true
            $Reference.Count | Should Be 2
            $Reference.ContainsKey('Machine:1421') | Should Be $true
            $Reference.ContainsKey('User:1421') | Should Be $true
            $Reference.ContainsKey('machine:1421') | Should Be $false
            ForEach ($Scope in @('Machine', 'User')) {
                $Entry = $Reference["$($Scope):1421"]
                $Entry.Scope | Should Be $Scope
                $Entry.ID | Should Be '1421'
                $Entry.List | Should Be "finding_list_0x6d69636b_$($Scope.ToLowerInvariant()).csv"
                $Entry.Name | Should Be 'Fixture log capacity'
                $Entry.Source | Should Be '레지스트리 값: HKLM:\Software\Fixture\Capacity'
                $Entry.Recommended | Should Be '이상 (>=): 16384'
                $Entry.Method | Should Be 'Registry'
                $Row = [PSCustomObject]@{
                    Scope = $Entry.Scope; ID = $Entry.ID; List = $Entry.List; Name = $Entry.Name
                    Source = $Entry.Source; Recommended = $Entry.Recommended; Severity = 'Medium'
                    TestResult = 'Failed'; ValueOrigin = 'Observed'; UsedDefault = $false; Result = '4096'
                }
                $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                $Expected = 'Review'
                If ($Scope -eq 'Machine') { $Expected = 'P1' }
                $Row.RemediationPriority | Should Be $Expected
            }
            Assert-MockCalled Import-Csv -Times 2 -Exactly -Scope It
            Assert-MockCalled Import-Csv -Times 1 -Exactly -Scope It -ParameterFilter {
                [IO.Path]::GetFileName($LiteralPath) -ceq 'finding_list_0x6d69636b_machine.csv' -and $Encoding -eq 'UTF8'
            }
            Assert-MockCalled Import-Csv -Times 1 -Exactly -Scope It -ParameterFilter {
                [IO.Path]::GetFileName($LiteralPath) -ceq 'finding_list_0x6d69636b_user.csv' -and $Encoding -eq 'UTF8'
            }
        }
        It 'surfaces a reference read failure rather than fabricating definitions' {
            Mock Import-Csv { Throw 'fixture reference read failed' }
            { Get-SecurityAuditPriorityReference } | Should Throw 'fixture reference read failed'
        }
    }

    Describe 'Security importance and remediation priority' {
        BeforeEach {
            $script:BlockPriorityReferenceReads = $false
            $ModuleRoot = (Get-Module HardeningKitty.SecurityAudit -All).ModuleBase
            $Reference = Get-SecurityAuditPriorityReference
            $Definitions = @{}
            ForEach ($Scope in @('Machine', 'User')) {
                $Path = Join-Path $ModuleRoot "lists\finding_list_0x6d69636b_$($Scope.ToLowerInvariant()).csv"
                ForEach ($Definition in @(Import-Csv -LiteralPath $Path -Encoding UTF8)) {
                    $Definitions["$($Scope):$($Definition.ID)"] = $Definition
                }
            }
            $NewBaseline = {
                Param ([String] $ID, [String] $Scope = 'Machine')
                $Definition = $Definitions["$($Scope):$ID"]
                If ($null -eq $Definition) { Throw "Missing bundled fixture definition: $($Scope):$ID" }
                $Row = New-SecurityAuditFinding -ID $Definition.ID -Scope $Scope `
                    -List "finding_list_0x6d69636b_$($Scope.ToLowerInvariant()).csv" `
                    -Category $Definition.Category -Name $Definition.Name -Target 'fixture-host' `
                    -Result 'fixture-observed-failure' -Recommended (Get-SecurityAuditCriterion -Finding $Definition) `
                    -TestResult Failed -Source (Get-SecurityAuditQuery -Finding $Definition) `
                    -Details '실측 증거는 분류 과정에서 변경하지 않습니다.' -Severity $Definition.Severity -ValueOrigin Observed
                $Row.EngineTestResult = 'Failed'
                $Row.UsedDefault = $false
                $Row.CheckedAt = '2026-10-29T10:01:02.1234567+09:00'
                Return $Row
            }
            Mock Invoke-HardeningKitty { Throw 'Live collection is forbidden in priority tests.' }
        }

        It 'keeps constructors and setters without a reference conservative and performs no implicit list read' {
            Mock Import-Csv { Throw 'The setter must not load a reference.' } -ParameterFilter { $script:BlockPriorityReferenceReads }
            $script:BlockPriorityReferenceReads = $true
            Try {
                $Row = & $NewBaseline '1421'
                $Row.Importance | Should Be 'Medium'
                $Row.RemediationPriority | Should Be 'Review'
                $null = Set-SecurityAuditPriority -Finding $Row
                $Row.RemediationPriority | Should Be 'Review'
                $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                $Row.RemediationPriority | Should Be 'P1'
                Assert-MockCalled Import-Csv -Times 0 -Exactly -Scope It -ParameterFilter { $script:BlockPriorityReferenceReads }
                Assert-MockCalled Invoke-HardeningKitty -Times 0 -Exactly -Scope It
            } Finally {
                $script:BlockPriorityReferenceReads = $false
            }
        }

        It 'separates security importance from implementation impact and order' {
            $Encryption = & $NewBaseline '1708'
            $Tips = & $NewBaseline '4501' 'User'
            $null = Set-SecurityAuditPriority -Finding $Encryption -Reference $Reference
            $null = Set-SecurityAuditPriority -Finding $Tips -Reference $Reference
            $Encryption.Importance | Should Be 'High'
            $Encryption.RemediationPriority | Should Be 'P3'
            $Encryption.ImportanceReason | Should Match '접근 통제·자격 증명·데이터 보호'
            $Encryption.PriorityReason | Should Match '낮은 보안 중요도가 아니라'
            $Tips.Importance | Should Be 'Low'
            $Tips.RemediationPriority | Should Be 'P1'
            $Tips.ImportanceReason | Should Match '편의 기능 또는 노출 감소'
            $Tips.PriorityReason | Should Match '무위험 변경 승인이 아닙니다'
            $Encryption.ImportanceReason | Should Match '기준 목록 작성자의 판단'
            $Tips.ImportanceReason | Should Match '관측된 호스트 위험 수준'
        }

        It 'requires exact source severity spelling while preserving the raw value and independent priority' {
            $Cases = @(
                @{ Severity = 'High'; Importance = 'High' }
                @{ Severity = 'Medium'; Importance = 'Medium' }
                @{ Severity = 'Low'; Importance = 'Low' }
                @{ Severity = 'HIGH'; Importance = 'Unrated' }
                @{ Severity = 'medium'; Importance = 'Unrated' }
                @{ Severity = 'low'; Importance = 'Unrated' }
                @{ Severity = 'Critical'; Importance = 'Unrated' }
                @{ Severity = ''; Importance = 'Unrated' }
                @{ Severity = ' High '; Importance = 'Unrated' }
                @{ Severity = $null; Importance = 'Unrated' }
            )
            ForEach ($Scope in @('Machine', 'User')) {
                $ID = '1421'
                If ($Scope -eq 'User') { $ID = '4501' }
                ForEach ($Case in $Cases) {
                    $Row = & $NewBaseline $ID $Scope
                    $Row.Severity = $Case.Severity
                    $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                    ($Row.Importance -ceq $Case.Importance) | Should Be $true
                    ($Row.Severity -ceq $Case.Severity) | Should Be $true
                    $Row.RemediationPriority | Should Be 'P1'
                    If ($Case.Importance -eq 'Medium') { $Row.ImportanceReason | Should Match '방어·탐지·정책 이행' }
                    If ($Case.Importance -eq 'Unrated') { $Row.ImportanceReason | Should Match '원문은 보존' }
                }
            }
        }

        It 'uses explicit supplemental purposes rather than category or supplied severity' {
            $Cases = @(
                @{ IDs = @('SS-02', 'SS-03', 'PP-01', 'PP-02'); Importance = 'High'; Priority = 'P2' }
                @{ IDs = @('PP-06', 'LA-05'); Importance = 'High'; Priority = 'P3' }
                @{ IDs = @('SS-01', 'SS-04', 'PP-04', 'PP-05'); Importance = 'Medium'; Priority = 'P2' }
                @{ IDs = @('PP-03', 'LA-02', 'LA-03', 'LA-04'); Importance = 'Medium'; Priority = 'P3' }
                @{ IDs = @('LA-01'); Importance = 'Reference'; Priority = 'Review' }
                @{ IDs = @('LA-00', 'SS-05', 'PP-99', 'unknown'); Importance = 'Unrated'; Priority = 'Review' }
            )
            ForEach ($Case in $Cases) {
                ForEach ($ID in $Case.IDs) {
                    $Row = New-SecurityAuditFinding -ID $ID -Scope Supplemental -Category 'arbitrary' `
                        -Severity Low -Result 0 -TestResult Failed -ValueOrigin Observed
                    $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                    $Row.Importance | Should Be $Case.Importance
                    $Row.RemediationPriority | Should Be $Case.Priority
                    $Row.Severity | Should Be 'Low'
                    If ($ID -eq 'LA-01') { $Row.ImportanceReason | Should Match '날짜 메타데이터' }
                }
            }
        }

        It 'reproduces the 75 failing-row distribution using definitions, not a report snapshot' {
            $MachineIDs = @(
                '1303', '1305', '1307', '1308', '1310', '1311', '1315', '1316', '1320', '1322', '1323', '1328',
                '1421', '1422', '1423', '1427', '1428', '1429', '1433', '1434', '1435',
                '1500', '1502', '1503', '1504', '1505', '1506', '1507', '1509', '1511', '1512', '1513', '1514',
                '1515', '1516', '1519', '1520', '1521', '1524', '1708', '1762', '1774', '1826',
                '1950', '1951', '1954', '1956', '1958', '1960', '1961', '1963',
                '2400', '2401', '2402', '2403', '2404', '2405', '2406', '2407', '2408', '2409', '2410', '2412', '2413'
            )
            $Rows = @(
                ForEach ($ID in $MachineIDs) { & $NewBaseline $ID }
                ForEach ($ID in @('4303', '4501', '4502', '4505')) { & $NewBaseline $ID 'User' }
                $Index = 0
                ForEach ($ID in @('PP-02', 'PP-04', 'PP-05', 'LA-04', 'LA-04', 'LA-04', 'LA-05')) {
                    New-SecurityAuditFinding -ID $ID -Scope Supplemental -Target "fixture-account-$Index" `
                        -Result 0 -TestResult Failed -ValueOrigin Observed
                    $Index++
                }
            )
            ForEach ($Row in $Rows) { $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference }
            $Rows.Count | Should Be 75
            @($Rows | Where-Object TestResult -ne Failed).Count | Should Be 0
            @($Rows | Where-Object RemediationPriority -eq P1).Count | Should Be 14
            @($Rows | Where-Object RemediationPriority -eq P2).Count | Should Be 35
            @($Rows | Where-Object RemediationPriority -eq P3).Count | Should Be 16
            @($Rows | Where-Object RemediationPriority -eq Review).Count | Should Be 10
            @($Rows | Where-Object RemediationPriority -eq None).Count | Should Be 0
            Assert-MockCalled Invoke-HardeningKitty -Times 0 -Exactly -Scope It
        }

        It 'excludes the ambiguous AutoPlay recommendation instead of calling zero a disable action' {
            $Row = & $NewBaseline '4505' 'User'
            $Row.Result = 1
            $Before = $Row | Select-Object ID, Scope, Source, Recommended, Result, TestResult, EngineTestResult, CheckedAt | ConvertTo-Json -Compress
            $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
            $Row.RemediationPriority | Should Be 'Review'
            $Row.PriorityReason | Should Match 'DisableAutoplay = 0'
            $Row.PriorityReason | Should Match '방향을 반대로'
            ($Row | Select-Object ID, Scope, Source, Recommended, Result, TestResult, EngineTestResult, CheckedAt | ConvertTo-Json -Compress) | Should Be $Before
        }

        It 'rejects custom list collisions and every changed identity field' {
            ForEach ($Property in @('Scope', 'ID', 'List', 'Name', 'Source', 'Recommended')) {
                ForEach ($Replacement in @('', 'different definition', $null)) {
                    $Row = & $NewBaseline '1421'
                    $Row.$Property = $Replacement
                    $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                    $Row.RemediationPriority | Should Be 'Review'
                }
            }
            ForEach ($Property in @('Scope', 'List', 'Name', 'Source', 'Recommended')) {
                $Row = & $NewBaseline '4303' 'User'
                $Original = $Row.$Property
                $Row.$Property = $Original.ToUpperInvariant()
                ($Row.$Property -cne $Original) | Should Be $true
                $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                $Row.RemediationPriority | Should Be 'Review'
            }
            $Custom = & $NewBaseline '1421'
            $Custom.List = 'custom.csv'
            $Custom.Category = 'Windows Firewall'
            $Custom.Severity = 'High'
            $null = Set-SecurityAuditPriority -Finding $Custom -Reference $Reference
            $Custom.Importance | Should Be 'High'
            $Custom.RemediationPriority | Should Be 'Review'
            $Custom.PriorityReason | Should Match '사용자 정의 목록'
            $Custom.List = 'C:\somewhere\finding_list_0x6d69636b_machine.csv'
            $null = Set-SecurityAuditPriority -Finding $Custom -Reference $Reference
            $Custom.RemediationPriority | Should Be 'Review'
        }

        It 'checks scope and ID inside records even when a caller supplies a case-insensitive table' {
            $Row = & $NewBaseline '1421'
            $Entry = $Reference['Machine:1421'].PSObject.Copy()
            $Entry.Scope = 'machine'
            $CaseInsensitive = @{ 'Machine:1421' = $Entry }
            $null = Set-SecurityAuditPriority -Finding $Row -Reference $CaseInsensitive
            $Row.RemediationPriority | Should Be 'Review'
            $Entry.Scope = 'Machine'
            $Entry.ID = 'different-id'
            $null = Set-SecurityAuditPriority -Finding $Row -Reference $CaseInsensitive
            $Row.RemediationPriority | Should Be 'Review'
        }

        It 'does not promote unmapped definitions from their category, severity or nearby ID' {
            ForEach ($ID in @('1000', '1775', '2411')) {
                $Row = & $NewBaseline $ID
                $Row.Category = 'Advanced Audit Policy Configuration'
                $Row.Severity = 'High'
                $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                $Row.Importance | Should Be 'High'
                $Row.RemediationPriority | Should Be 'Review'
            }
            $Row = & $NewBaseline '1508'
            $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
            $Row.RemediationPriority | Should Be 'P2'
            $Row.PriorityReason | Should Match '로그 양'
            $Row.List = 'other-audit-list.csv'
            $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
            $Row.RemediationPriority | Should Be 'Review'
        }

        It 'always keeps Unknown and Error in Review even for observed P1 candidates' {
            ForEach ($Status in @('Unknown', 'Error')) {
                $Rows = @(
                    & $NewBaseline '1421'
                    New-SecurityAuditFinding -ID 'SS-02' -TestResult Failed -Result 0 -ValueOrigin Observed
                )
                ForEach ($Row in $Rows) {
                    $Row.TestResult = $Status
                    $Row.UsedDefault = $false
                    $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                    $Row.RemediationPriority | Should Be 'Review'
                    $Row.TestResult | Should Be $Status
                    $Row.ValueOrigin | Should Be 'Observed'
                    $Row.PriorityReason | Should Match '수집 오류·증거·적용 가능성 확인'
                }
            }
        }

        It 'requests no change for Passed, Info or NotApplicable without converting them to compliance' {
            ForEach ($Status in @('Passed', 'Info', 'NotApplicable')) {
                ForEach ($Scope in @('Machine', 'Supplemental', 'Context', 'Execution')) {
                    $Row = & $NewBaseline '1421'
                    $Row.Scope = $Scope
                    $Row.TestResult = $Status
                    $Row.ValueOrigin = 'Default'
                    $Row.UsedDefault = $true
                    $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                    $Row.RemediationPriority | Should Be 'None'
                    $Row.TestResult | Should Be $Status
                    $Row.UsedDefault | Should Be $true
                    If ($Status -ne 'Passed') { $Row.PriorityReason | Should Match '자동 준수나 보안 통제의 합격을 뜻하지' }
                }
            }
        }

        It 'requires observed failure and rejects default substitution without treating false strings as true' {
            ForEach ($Origin in @('Default', 'Unverified', 'Unavailable', 'Reference', '', $null)) {
                $Row = & $NewBaseline '1421'
                $Row.ValueOrigin = $Origin
                $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                $Row.RemediationPriority | Should Be 'Review'
                $Row.TestResult | Should Be 'Failed'
            }
            $Cases = @(
                @{ Flag = $true; Priority = 'Review' }
                @{ Flag = 'True'; Priority = 'Review' }
                @{ Flag = 'true'; Priority = 'Review' }
                @{ Flag = $false; Priority = 'P1' }
                @{ Flag = 'False'; Priority = 'P1' }
                @{ Flag = $null; Priority = 'P1' }
            )
            ForEach ($Case in $Cases) {
                $Row = & $NewBaseline '1421'
                $Row.UsedDefault = $Case.Flag
                $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                $Row.RemediationPriority | Should Be $Case.Priority
                ($Row.UsedDefault -ceq $Case.Flag) | Should Be $true
                $Row.TestResult | Should Be 'Failed'
            }
            ForEach ($Value in @(0, $false)) {
                $Row = & $NewBaseline '1421'
                $Row.Result = $Value
                $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                $Row.RemediationPriority | Should Be 'P1'
                $Row.Result | Should Be $Value
                ($Row.Result.GetType() -eq $Value.GetType()) | Should Be $true
            }
        }

        It 'never turns context or execution failures into remediation candidates' {
            ForEach ($Scope in @('Context', 'Execution')) {
                ForEach ($Status in @('Failed', 'Unknown', 'Error')) {
                    $Row = & $NewBaseline '1421'
                    $Row.Scope = $Scope
                    $Row.TestResult = $Status
                    $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                    $Row.Importance | Should Be 'Reference'
                    $Row.RemediationPriority | Should Be 'Review'
                }
            }
        }

        It 'preserves object identity, all original evidence, property order and individual timestamps on refresh' {
            $Fields = @('Importance', 'ImportanceReason', 'RemediationPriority', 'PriorityReason')
            $Rows = @(& $NewBaseline '1421'; & $NewBaseline '4501' 'User')
            $Rows[1].CheckedAt = '2026-10-29T02:03:04.7654321+00:00'
            ForEach ($Row in $Rows) {
                ForEach ($Field in $Fields) { $Row.PSObject.Properties.Remove($Field) }
                $OriginalNames = @($Row.PSObject.Properties.Name)
                $Before = $Row | ConvertTo-Json -Depth 8 -Compress
                $Returned = @(Set-SecurityAuditPriority -Finding $Row -Reference $Reference)
                $Returned.Count | Should Be 1
                [Object]::ReferenceEquals($Row, $Returned[0]) | Should Be $true
                ($Row.PSObject.Properties.Name -join ',') | Should Be (($OriginalNames + $Fields) -join ',')
                ForEach ($Field in $Fields) {
                    $Row.PSObject.Properties[$Field].MemberType | Should Be 'NoteProperty'
                    ($Row.$Field -is [String]) | Should Be $true
                }
                $After = $Row | Select-Object -Property $OriginalNames | ConvertTo-Json -Depth 8 -Compress
                ($After -ceq $Before) | Should Be $true
                $null = Set-SecurityAuditPriority -Finding $Row
                $Row.RemediationPriority | Should Be 'Review'
                $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                $Row.RemediationPriority | Should Be 'P1'
                ($Row.PSObject.Properties.Name -join ',') | Should Be (($OriginalNames + $Fields) -join ',')
                $After = $Row | Select-Object -Property $OriginalNames | ConvertTo-Json -Depth 8 -Compress
                ($After -ceq $Before) | Should Be $true
            }
            $Rows[0].CheckedAt | Should Be '2026-10-29T10:01:02.1234567+09:00'
            $Rows[1].CheckedAt | Should Be '2026-10-29T02:03:04.7654321+00:00'
        }

        It 'explains NOTSET as Windows-default uncertainty rather than a disabled protection' {
            ForEach ($ID in @('1950', '1951', '1954', '1956', '1958', '1960', '1961', '1963')) {
                $Row = & $NewBaseline $ID
                $Row.Result = 'NOTSET'
                $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                $Row.RemediationPriority | Should Be 'Review'
                $Row.PriorityReason | Should Match 'Windows 기본 동작'
                $Row.PriorityReason | Should Match '보호 기능이 꺼짐을 뜻하지'
                $Row.Result | Should Be 'NOTSET'
                $Row.TestResult | Should Be 'Failed'
                $Row.Result = 'OFF'
                $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                $Row.RemediationPriority | Should Be 'Review'
                $Row.PriorityReason | Should Match '애플리케이션 호환성'
            }
        }

        It 'requires current antivirus applicability evidence and never assumes a third-party product or NA' {
            $Row = & $NewBaseline '1826'
            $Row.Result = $false
            $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
            $Row.RemediationPriority | Should Be 'Review'
            $Row.PriorityReason | Should Match '현재 활성 백신'
            $Row.PriorityReason | Should Match '타사 백신 사용을 가정하지'
            $Row.PriorityReason | Should Match '이 값만으로 NotApplicable'
            $Row.TestResult | Should Be 'Failed'
            $Row.Result | Should Be $false
        }

        It 'retains effect-specific prerequisites instead of treating priority as permission' {
            $Cases = @(
                @{ ID = '1421'; Scope = 'Machine'; Priority = 'P1'; Reason = '디스크 여유' }
                @{ ID = '1506'; Scope = 'Machine'; Priority = 'P1'; Reason = '기존 성공 감사를 제거하지' }
                @{ ID = '1422'; Scope = 'Machine'; Priority = 'P1'; Reason = '허용·차단 규칙을 바꾸지' }
                @{ ID = '4501'; Scope = 'User'; Priority = 'P1'; Reason = 'Windows 팁·추천' }
                @{ ID = '1423'; Scope = 'Machine'; Priority = 'P2'; Reason = '로그 양' }
                @{ ID = '1303'; Scope = 'Machine'; Priority = 'P2'; Reason = '자격 증명' }
                @{ ID = '1320'; Scope = 'Machine'; Priority = 'P2'; Reason = '로그인 전 종료 제한' }
                @{ ID = '1328'; Scope = 'Machine'; Priority = 'P2'; Reason = '관리자 승인·자격 증명 입력' }
                @{ ID = '2413'; Scope = 'Machine'; Priority = 'P2'; Reason = 'Stopped는 현재 실행 상태일 뿐 미사용의 증거가 아니며' }
                @{ ID = '2400'; Scope = 'Machine'; Priority = 'P2'; Reason = '미사용임을 확인한 경우에만' }
                @{ ID = '4502'; Scope = 'User'; Priority = 'P2'; Reason = '실제로 사용하지 않는 경우에만' }
                @{ ID = '1305'; Scope = 'Machine'; Priority = 'P3'; Reason = 'NAS·파일 공유' }
                @{ ID = '1311'; Scope = 'Machine'; Priority = 'P3'; Reason = '저장된 자격 증명 의존성' }
                @{ ID = '2401'; Scope = 'Machine'; Priority = 'P3'; Reason = '인쇄 의존성' }
                @{ ID = '1708'; Scope = 'Machine'; Priority = 'P3'; Reason = '복구 키' }
                @{ ID = '1762'; Scope = 'Machine'; Priority = 'P3'; Reason = '실제 볼륨 암호화' }
                @{ ID = '4303'; Scope = 'User'; Priority = 'P3'; Reason = '애플리케이션 제어 정책' }
            )
            ForEach ($Case in $Cases) {
                $Row = & $NewBaseline $Case.ID $Case.Scope
                If ($Case.ID -eq '2413') { $Row.Result = 'Stopped' }
                $null = Set-SecurityAuditPriority -Finding $Row -Reference $Reference
                $Row.RemediationPriority | Should Be $Case.Priority
                $Row.PriorityReason | Should Match $Case.Reason
                $Row.PriorityReason | Should Match '정적 안내'
                If ($Case.Priority -eq 'P3') { $Row.PriorityReason | Should Match '변경·롤백·복구 계획' }
            }
        }
    }
}
