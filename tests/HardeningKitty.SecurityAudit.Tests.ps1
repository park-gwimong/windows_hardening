#Requires -Version 5.1

$Root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $Root 'HardeningKitty.psd1') -Force

Describe 'Security audit manifest integration' {
    It 'exports both audit commands without exposing private helpers' {
        $Module = Get-Module HardeningKitty | Where-Object ModuleType -eq Manifest
        $Exports = $Module.ExportedFunctions.Keys
        $Exports.Count | Should Be 2
        ($Exports -contains 'Invoke-HardeningKitty') | Should Be $true
        ($Exports -contains 'Invoke-HardeningKittySecurityAudit') | Should Be $true
        ForEach ($Private in @('Invoke-HardeningKittyAccountAudit', 'Get-AccountAuditPolicy', 'Get-AccountAuditFinding',
            'New-SecurityAuditFinding', 'ConvertTo-SecurityAuditHtml', 'Invoke-SecurityAuditBaseline',
            'Invoke-SecurityAuditEngine', 'ConvertFrom-SecurityAuditEngineReport', 'Get-SecurityAuditCatalog',
            'Set-SecurityAuditPriority', 'Get-SecurityAuditPriorityReference')) {
            ($Exports -contains $Private) | Should Be $false
        }
        $Module.ExportedAliases.Count | Should Be 0
        $Module.ExportedCmdlets.Count | Should Be 0
        $Module.ExportedVariables.Count | Should Be 0
        @($Module.NestedModules | Where-Object Name -eq 'HardeningKitty.AccountAudit').Count | Should Be 0
        Test-Path -LiteralPath (Join-Path $Root 'HardeningKitty.AccountAudit.psm1') | Should Be $false
    }
}

InModuleScope HardeningKitty.SecurityAudit {
    Describe 'Security finding schema' {
        It 'preserves supplied evidence and distinguishes false, zero and absent engine metadata' {
            $Row = New-SecurityAuditFinding -ID 'fixture' -Scope Machine -List '목록.csv' -Category 'System' `
                -Name '설정 이름' -Description '보안 정책의 적용 상태와 변경이 필요한 이유를 설명하는 테스트 항목입니다.' `
                -Target 'host' -Result $false -Recommended '0' -TestResult Failed -Source 'registry path' `
                -Details 'observed evidence' -Severity High
            ($Row.PSObject.Properties.Name -join ',') | Should Be 'ID,Scope,List,Category,Name,Description,Target,Result,Recommended,TestResult,Source,Details,Severity,EngineTestResult,UsedDefault,ValueOrigin,ReasonCode,CheckedAt,Importance,ImportanceReason,RemediationPriority,PriorityReason'
            $Row.Scope | Should Be 'Machine'
            $Row.List | Should Be '목록.csv'
            $Row.Description | Should Match '변경이 필요한 이유'
            $Row.Severity | Should Be 'High'
            $Row.Source | Should Be 'registry path'
            $Row.Details | Should Be 'observed evidence'
            ($Row.Result -is [Boolean]) | Should Be $true
            $Row.Result | Should Be $false
            $Row.Recommended | Should Be '0'
            ($null -eq $Row.EngineTestResult) | Should Be $true
            ($null -eq $Row.UsedDefault) | Should Be $true
            $Row.ValueOrigin | Should Be 'Observed'
        }
        It 'derives provenance from evidence without treating zero or false as missing' {
            $Cases = @(
                @{ Result = 0; Status = 'Passed'; Origin = 'Observed' }
                @{ Result = $false; Status = 'Failed'; Origin = 'Observed' }
                @{ Result = 'timestamp'; Status = 'Info'; Origin = 'Observed' }
                @{ Result = 'disabled account'; Status = 'NotApplicable'; Origin = 'Observed' }
                @{ Result = ' '; Status = 'Passed'; Origin = 'Observed' }
                @{ Result = 0; Status = 'Unknown'; Origin = 'Unverified' }
                @{ Result = $false; Status = 'Error'; Origin = 'Unverified' }
                @{ Result = $null; Status = 'Unknown'; Origin = 'Unavailable' }
                @{ Result = ''; Status = 'Failed'; Origin = 'Unavailable' }
                @{ Result = $null; Status = 'Error'; Origin = 'Unavailable' }
                @{ Result = ''; Status = 'Unknown'; Origin = 'Unavailable' }
            )
            ForEach ($Case in $Cases) {
                $Row = New-SecurityAuditFinding -ID 'evidence' -Result $Case.Result -TestResult $Case.Status
                $Row.ValueOrigin | Should Be $Case.Origin
                $Row.Result | Should Be $Case.Result
            }
        }
        It 'marks context and execution information as reference even when empty or unresolved' {
            ForEach ($Scope in @('Context', 'Execution')) {
                ForEach ($Value in @($null, '', 0, $false, 'host')) {
                    $Row = New-SecurityAuditFinding -ID 'reference' -Scope $Scope -Result $Value -TestResult Unknown
                    $Row.ValueOrigin | Should Be 'Reference'
                    $Row.Result | Should Be $Value
                }
            }
        }
        It 'retains explicit collection origins and reasons without rewriting raw values or verdicts' {
            $Default = New-SecurityAuditFinding -ID 'default' -Result 0 -TestResult Unknown `
                -ValueOrigin Default -ReasonCode DefaultSubstitution
            $Default.ValueOrigin | Should Be 'Default'
            $Default.ReasonCode | Should Be 'DefaultSubstitution'
            $Default.Result | Should Be 0
            $Default.TestResult | Should Be 'Unknown'
            $EmptyObserved = New-SecurityAuditFinding -ID 'empty' -Result '' -TestResult Passed -ValueOrigin Observed
            $EmptyObserved.ValueOrigin | Should Be 'Observed'
            ($EmptyObserved.Result -is [String]) | Should Be $true
            $EmptyObserved.Result.Length | Should Be 0
        }
        It 'does not fabricate reason codes for supplemental or context evidence' {
            ForEach ($Scope in @('Supplemental', 'Context')) {
                $Row = New-SecurityAuditFinding -ID 'no-reason' -Scope $Scope -Result 'host' -TestResult Info
                $Row.ReasonCode | Should Be ''
            }
        }
        It 'rejects unsupported or malicious explicitly supplied origins' {
            ForEach ($Origin in @('', $null, 'Guessed', 'Observed" onclick="alert(1)', '<script>alert(1)</script>')) {
                { New-SecurityAuditFinding -ID 'invalid' -Result 1 -TestResult Passed -ValueOrigin $Origin } | Should Throw
            }
        }
    }

    Describe 'Numeric audit boundaries' {
        It 'rejects disabled, negative and excessive timeouts' {
            ForEach ($Value in @('0', '-1', '901')) {
                Test-AccountAuditNumber -Value $Value -Minimum 1 -Maximum 900 | Should Be 'Failed'
            }
        }
        It 'accepts both inclusive policy limits' {
            Test-AccountAuditNumber -Value '1' -Minimum 1 -Maximum 900 | Should Be 'Passed'
            Test-AccountAuditNumber -Value '900' -Minimum 1 -Maximum 900 | Should Be 'Passed'
        }
        It 'never treats missing, malformed or overflowing data as zero' {
            ForEach ($Value in @($null, '', 'invalid', '99999999999999999999', '1.5')) {
                Test-AccountAuditNumber -Value $Value -Minimum 0 -Maximum 0 | Should Be 'Unknown'
            }
        }
    }

    Describe 'Security policy parsing' {
        It 'reads only System Access and preserves explicit zero' {
            $Policy = ConvertFrom-AccountAuditPolicy -Lines @(
                '[Other]', 'PasswordComplexity = 9', ' [System Access] ',
                ' PasswordComplexity = 1 ', 'ClearTextPassword = 0',
                '; comment = ignored', '[Version]', 'PasswordComplexity = 8'
            )
            $Policy.PasswordComplexity | Should Be '1'
            $Policy.ClearTextPassword | Should Be '0'
            $Policy.Count | Should Be 2
        }
        It 'does not synthesize missing policy values' {
            $Policy = ConvertFrom-AccountAuditPolicy -Lines @('[System Access]', 'EnableGuestAccount = 0')
            $Policy.ContainsKey('PasswordComplexity') | Should Be $false
        }
        It 'converts SAM seconds to days and retains zero minimums' {
            $Policy = ConvertFrom-AccountAuditModalsPolicy -Policy ([PSCustomObject]@{
                MinimumPasswordLength = 0; MaximumPasswordAgeSeconds = 3628800
                MinimumPasswordAgeSeconds = 86400; PasswordHistoryLength = 24
            })
            $Policy.MaximumPasswordAge | Should Be 42
            $Policy.MinimumPasswordAge | Should Be 1
            $Policy.MinimumPasswordLength | Should Be 0
            $Policy.PasswordHistorySize | Should Be 24
        }
        It 'recognizes the native unlimited-age sentinel' {
            $Policy = ConvertFrom-AccountAuditModalsPolicy -Policy ([PSCustomObject]@{
                MinimumPasswordLength = 14; MaximumPasswordAgeSeconds = [UInt32]::MaxValue
                MinimumPasswordAgeSeconds = 0; PasswordHistoryLength = 0
            })
            $Policy.MaximumPasswordAge | Should Be 0
            Test-AccountAuditNumber -Value $Policy.MaximumPasswordAge -Minimum 1 -Maximum 365 | Should Be 'Failed'
        }
    }

    Describe 'Screen saver registry precedence' {
        It 'does not replace an explicit disabled policy with enabled preferences' {
            Mock Get-ItemProperty {
                If ($LiteralPath -like '*Policies*') { Return [PSCustomObject]@{ ScreenSaveActive = '0' } }
                Return [PSCustomObject]@{ ScreenSaveActive = '1' }
            }
            $Setting = Get-AccountAuditScreenSaverValue -Name ScreenSaveActive
            $Setting.Value | Should Be '0'
            $Setting.Source | Should Match 'Policies'
            Assert-MockCalled Get-ItemProperty -Times 1 -Exactly -Scope It
        }
        It 'does not replace an explicitly empty policy value' {
            Mock Get-ItemProperty { [PSCustomObject]@{ 'SCRNSAVE.EXE' = '' } }
            $Setting = Get-AccountAuditScreenSaverValue -Name 'SCRNSAVE.EXE'
            $Setting.Found | Should Be $true
            $Setting.Value | Should Be ''
            Assert-MockCalled Get-ItemProperty -Times 1 -Exactly -Scope It
        }
        It 'resolves each value independently when only some policy values exist' {
            Mock Get-ItemProperty {
                If ($LiteralPath -like '*Policies*') { Return [PSCustomObject]@{ ScreenSaveActive = '0' } }
                Return [PSCustomObject]@{ ScreenSaveTimeOut = '600' }
            }
            $Setting = Get-AccountAuditScreenSaverValue -Name ScreenSaveTimeOut
            $Setting.Value | Should Be '600'
            $Setting.Source | Should Not Match 'Policies'
        }
        It 'reports absent registry keys without inventing a Windows default' {
            Mock Get-ItemProperty { Throw [System.Management.Automation.ItemNotFoundException]::new('missing key') }
            $Setting = Get-AccountAuditScreenSaverValue -Name ScreenSaverIsSecure
            $Setting.Found | Should Be $false
            $Setting.Error | Should Be ''
            ($null -eq $Setting.Value) | Should Be $true
            Assert-MockCalled Get-ItemProperty -Times 2 -Exactly -Scope It
        }
        It 'does not use preferences when policy access is denied' {
            Mock Get-ItemProperty { Throw [UnauthorizedAccessException]::new('denied') }
            $Setting = Get-AccountAuditScreenSaverValue -Name ScreenSaveActive
            $Setting.Error | Should Match 'denied'
            $Setting.Found | Should Be $false
            Assert-MockCalled Get-ItemProperty -Times 1 -Exactly -Scope It
        }
    }

    Describe 'Screen saver file checks' {
        BeforeEach { Mock Test-Path { $true } }
        It 'checks a local scr file without executing it' {
            (Test-AccountAuditScreenSaverFile -Value "$env:SystemRoot\System32\scrnsave.scr").Status | Should Be 'Passed'
            Assert-MockCalled Test-Path -Times 1 -Exactly -Scope It -ParameterFilter { $PathType -eq 'Leaf' }
        }
        It 'rejects an empty or non-scr executable' {
            (Test-AccountAuditScreenSaverFile -Value '').Status | Should Be 'Failed'
            (Test-AccountAuditScreenSaverFile -Value "$env:SystemRoot\System32\cmd.exe").Status | Should Be 'Failed'
            Assert-MockCalled Test-Path -Times 0 -Exactly -Scope It
        }
        It 'does not probe UNC paths or ambiguous relative paths' {
            ForEach ($Path in @('\\server\share\saver.scr', '//server/share/saver.scr', '..\saver.scr')) {
                (Test-AccountAuditScreenSaverFile -Value $Path).Status | Should Be 'Unknown'
            }
            Assert-MockCalled Test-Path -Times 0 -Exactly -Scope It
        }
        It 'reports a missing configured executable' {
            Mock Test-Path { $false }
            (Test-AccountAuditScreenSaverFile -Value "$env:SystemRoot\System32\missing.scr").Status | Should Be 'Failed'
        }
    }

    Describe 'Local account date and flag assessment' {
        BeforeEach {
            $Now = [DateTimeOffset]'2026-10-01T12:00:00+09:00'
            $User = [PSCustomObject]@{
                Name = 'test,account'; SID = 'S-1-5-21-1-2-3-1001'; Enabled = $true
                PrincipalSource = 'Local'; PasswordLastSet = $Now.AddDays(-5).UtcDateTime
                PasswordExpires = $Now.AddDays(85).UtcDateTime; PasswordRequired = $true
            }
            $Flags = [PSCustomObject]@{ PasswordExpires = $true }
        }
        It 'preserves the change instant with an explicit timezone offset' {
            $Rows = @(Get-AccountAuditUserFinding -User $User -AccountFlags $Flags -Now $Now -MaximumPasswordAgeDays 90)
            $LastSet = $Rows | Where-Object ID -eq LA-01
            $LastSet.TestResult | Should Be 'Info'
            $LastSet.Result | Should Match '[+-]\d{2}:\d{2}$'
            ([DateTimeOffset]$LastSet.Result).UtcDateTime | Should Be $User.PasswordLastSet
            ($Rows | Where-Object ID -eq LA-02).Result | Should Be 5
            ($Rows | Where-Object ID -eq LA-02).TestResult | Should Be 'Passed'
        }
        It 'fails at the exact age limit and does not round fractional ages upward' {
            $User.PasswordLastSet = $Now.AddDays(-90).UtcDateTime
            $Rows = @(Get-AccountAuditUserFinding -User $User -AccountFlags $Flags -Now $Now -MaximumPasswordAgeDays 90)
            ($Rows | Where-Object ID -eq LA-02).TestResult | Should Be 'Failed'
            $User.PasswordLastSet = $Now.AddDays(-90).AddSeconds(1).UtcDateTime
            $Rows = @(Get-AccountAuditUserFinding -User $User -AccountFlags $Flags -Now $Now -MaximumPasswordAgeDays 90)
            ($Rows | Where-Object ID -eq LA-02).TestResult | Should Be 'Passed'
        }
        It 'reports unavailable and future last-set timestamps as unknown' {
            ForEach ($Date in @($null, $Now.AddMinutes(1).UtcDateTime)) {
                $User.PasswordLastSet = $Date
                $Rows = @(Get-AccountAuditUserFinding -User $User -AccountFlags $Flags -Now $Now -MaximumPasswordAgeDays 90)
                ($Rows | Where-Object ID -eq LA-01).TestResult | Should Be 'Unknown'
                ($Rows | Where-Object ID -eq LA-02).TestResult | Should Be 'Unknown'
            }
        }
        It 'fails when the returned expiry instant has been reached' {
            $User.PasswordExpires = $Now.UtcDateTime
            $Rows = @(Get-AccountAuditUserFinding -User $User -AccountFlags $Flags -Now $Now -MaximumPasswordAgeDays 90)
            ($Rows | Where-Object ID -eq LA-03).TestResult | Should Be 'Failed'
        }
        It 'does not infer a never-expire flag from a missing expiry date' {
            $User.PasswordExpires = $null
            $Rows = @(Get-AccountAuditUserFinding -User $User -AccountFlags $null -Now $Now -MaximumPasswordAgeDays 90)
            ($Rows | Where-Object ID -eq LA-04).TestResult | Should Be 'Unknown'
            ($null -eq ($Rows | Where-Object ID -eq LA-04).Result) | Should Be $true
        }
        It 'detects never-expire and password-not-required flags independently' {
            $Flags.PasswordExpires = $false
            $User.PasswordRequired = $false
            $Rows = @(Get-AccountAuditUserFinding -User $User -AccountFlags $Flags -Now $Now -MaximumPasswordAgeDays 90)
            ($Rows | Where-Object ID -eq LA-04).Result | Should Be $true
            ($Rows | Where-Object ID -eq LA-04).TestResult | Should Be 'Failed'
            ($Rows | Where-Object ID -eq LA-05).TestResult | Should Be 'Failed'
        }
        It 'retains disabled account metadata without reporting compliance failures' {
            $User.Enabled = $false
            $User.PasswordRequired = $false
            $Rows = @(Get-AccountAuditUserFinding -User $User -AccountFlags $Flags -Now $Now -MaximumPasswordAgeDays 1)
            @($Rows | Where-Object TestResult -ne NotApplicable).Count | Should Be 0
            ($Rows | Where-Object ID -eq LA-01).Result | Should Not BeNullOrEmpty
        }
        It 'does not mistake cloud or unknown-source records for authoritative dates' {
            ForEach ($Source in @('MicrosoftAccount', 'AzureAD', 'ActiveDirectory', $null)) {
                $User.PrincipalSource = $Source
                $Rows = @(Get-AccountAuditUserFinding -User $User -AccountFlags $Flags -Now $Now -MaximumPasswordAgeDays 1)
                @($Rows | Where-Object TestResult -ne Unknown).Count | Should Be 0
                ($Rows | Where-Object ID -eq LA-01).Details | Should Match 'not authoritative'
            }
        }
    }

    Describe 'Private policy export lifecycle' {
        It 'restricts temporary policy data and removes it after success' {
            Mock Export-AccountAuditPolicy {
                $script:ExportDirectory = Split-Path -Parent $Path
                $script:ExportAcl = Get-Acl -LiteralPath $script:ExportDirectory
                Set-Content -LiteralPath $Path -Value @('[System Access]', 'PasswordComplexity = 1') -Encoding Unicode
            }
            $Policy = Get-AccountAuditPolicy
            $Policy.PasswordComplexity | Should Be '1'
            $script:ExportAcl.AreAccessRulesProtected | Should Be $true
            $Rules = @($script:ExportAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
            @($Rules | Where-Object { $_.IdentityReference.Value -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }).Count | Should Be 0
            Test-Path -LiteralPath $script:ExportDirectory | Should Be $false
        }
        It 'removes the private directory when the export fails' {
            Mock Export-AccountAuditPolicy {
                $script:ExportDirectory = Split-Path -Parent $Path
                Throw 'export failed'
            }
            { Get-AccountAuditPolicy } | Should Throw 'export failed'
            Test-Path -LiteralPath $script:ExportDirectory | Should Be $false
        }
    }

    Describe 'Self-contained HTML report rendering' {
        BeforeEach {
            $Rows = @(
                New-SecurityAuditFinding -ID 'SS-01' -Category 'Screen Saver' -Name 'Screen saver enabled' -Target 'host\user' -Result 1 -Recommended 1 -TestResult Passed -Source 'registry' -Details 'Enabled'
                New-SecurityAuditFinding -ID 'PP-02' -Category 'Password Policy' -Name 'Minimum length' -Target 'host' -Result 8 -Recommended 14 -TestResult Failed -Source 'SAM' -Details 'Too short'
                New-SecurityAuditFinding -ID 'PP-01' -Category 'Password Policy' -Name 'Complexity' -Target 'host' -Result $null -Recommended 1 -TestResult Unknown -Source 'secedit' -Details 'Not returned'
                New-SecurityAuditFinding -ID 'LA-00' -Category 'Local Accounts' -Name 'Enumeration' -Target 'host' -Result $null -Recommended 'Available' -TestResult Error -Source 'Get-LocalUser' -Details 'Access denied'
                New-SecurityAuditFinding -ID 'CTX-01' -Scope Context -Category 'Scope' -Name 'Audit scope' -Description (Get-SupplementalAuditDescription -ID 'CTX-01') -Target 'host\user' -Result 'host' -Recommended '' -TestResult Info -Source 'identity' -Details 'Current user only'
                New-SecurityAuditFinding -ID 'LA-01' -Category 'Local Accounts' -Name 'Disabled account' -Target 'host\disabled' -Result $null -Recommended '' -TestResult NotApplicable -Source 'SAM' -Details 'Excluded'
            )
            ForEach ($Row in $Rows) { $Row.CheckedAt = '2026-10-29T12:00:00+09:00' }
        }
        It 'renders every finding with accurate separate status counts and snapshot metadata' {
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Rows)
            $Document.DocumentElement.Name | Should Be 'html'
            $Document.DocumentElement.lang | Should Be 'ko'
            $Document.SelectSingleNode('//h1').InnerText | Should Be '시스템 보안 점검 보고서'
            $Document.SelectSingleNode('//*[@id="finding-total"]').InnerText | Should Be '6'
            $Document.SelectNodes('//details[@class="finding"]').Count | Should Be 6
            $Document.SelectNodes('//details[@class="finding"]//*[@class="result-value"]').Count | Should Be 6
            $Document.SelectNodes('//details[@class="finding" and @open]').Count | Should Be 0
            $Document.SelectNodes('//tr[@class="finding"]').Count | Should Be 0
            ForEach ($Class in @('passed', 'failed', 'unknown', 'error', 'info', 'not-applicable')) {
                $Document.SelectSingleNode("//*[@id='status-$Class']/strong").InnerText | Should Be '1'
            }
            $Document.SelectSingleNode('//dl[@class="metadata"]/dd[1]').InnerText | Should Be 'host'
            $Document.SelectSingleNode('//dl[@class="metadata"]/dd[2]').InnerText | Should Be 'host\user'
            $Document.SelectSingleNode('//dl[@class="metadata"]/dd[3]').InnerText | Should Be '2026-10-29T12:00:00+09:00'
            $Document.SelectSingleNode('//*[@id="summary-heading"]').InnerText | Should Be '개선 또는 재점검이 필요합니다.'
            $Document.SelectSingleNode('//details[@data-status="Info"]//span[@class="value-origin origin-reference"]').InnerText | Should Be '참고 정보'
        }
        It 'never describes unknown, informational, excluded or empty results as compliant' {
            $Unknown = [xml](ConvertTo-SecurityAuditHtml -Findings @($Rows | Where-Object TestResult -eq Unknown))
            $Unknown.SelectSingleNode('//*[@id="summary-heading"]').InnerText | Should Be '확인되지 않은 항목이 있습니다.'
            $NoAssessment = [xml](ConvertTo-SecurityAuditHtml -Findings @($Rows | Where-Object { $_.TestResult -in @('Info', 'NotApplicable') }))
            $NoAssessment.SelectSingleNode('//*[@id="summary-heading"]').InnerText | Should Be '자동 판정 대상이 없습니다.'
            $Empty = [xml](ConvertTo-SecurityAuditHtml -Findings @())
            $Empty.SelectSingleNode('//*[@id="summary-heading"]').InnerText | Should Be '점검 결과가 없습니다.'
            $Empty.SelectNodes('//details[@class="finding"]').Count | Should Be 0
            $Passed = [xml](ConvertTo-SecurityAuditHtml -Findings @($Rows | Where-Object TestResult -eq Passed))
            $Passed.SelectSingleNode('//*[@id="summary-heading"]').InnerText | Should Be '평가된 항목이 기준을 충족합니다.'
        }
        It 'encodes all data fields rather than interpreting markup from account or policy data' {
            $Payload = '<script>alert("계정 & 설정")</script><img src=x onerror="alert(1)">'
            $Row = $Rows[0]
            ForEach ($Property in @('ID', 'Category', 'Name', 'Description', 'Scope', 'List', 'Severity',
                'Target', 'Result', 'Recommended', 'Source', 'Details', 'EngineTestResult', 'UsedDefault', 'ReasonCode',
                'CheckedAt', 'ImportanceReason', 'PriorityReason')) {
                $Row.$Property = $Payload
            }
            $Html = ConvertTo-SecurityAuditHtml -Findings @($Row)
            $Document = [xml]$Html
            $Document.SelectNodes('//script|//img').Count | Should Be 0
            $Document.SelectSingleNode('//details[@class="finding"]/summary//*[@class="item-name"]').InnerText | Should Be $Payload
            $Document.SelectSingleNode('//details[@class="finding"]/summary//*[@class="item-id"]').InnerText | Should Be "$Payload / $Payload"
            $Document.SelectSingleNode('//details[@class="finding"]/summary//*[@class="item-category"]').InnerText | Should Be $Payload
            $Document.SelectSingleNode('//p[@class="description"]').InnerText | Should Be "점검 내용$Payload"
            ForEach ($Class in @('target-value', 'result-value', 'criterion-value', 'collection-details')) {
                $Document.SelectSingleNode("//details[@class='finding']//*[@class='$Class']").InnerText | Should Be $Payload
            }
            ForEach ($Property in @('Source', 'CheckedAt', 'List', 'Severity', 'EngineTestResult', 'UsedDefault', 'ReasonCode')) {
                $Document.SelectSingleNode("//dl[@class='evidence']/dd[@data-field='$Property']").InnerText | Should Be $Payload
            }
            $Document.SelectNodes('//dl[@class="evidence"]/dd').Count | Should Be 7
            $Document.SelectSingleNode('//p[@class="importance-reason"]').InnerText | Should Be "중요도 근거$Payload"
            $Document.SelectSingleNode('//p[@class="priority-reason"]').InnerText | Should Be "조치 분류 근거$Payload"
            $Html | Should Match '&lt;script&gt;'
        }
        It 'also encodes computer and identity metadata in the header' {
            $Row = $Rows | Where-Object ID -eq CTX-01
            $Row.Result = '<img src=x onerror="alert(1)">'
            $Row.Target = '사용자 & "관리자" <admin>'
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings @($Row))
            $Document.SelectNodes('//img|//admin').Count | Should Be 0
            $Document.SelectSingleNode('//dl[@class="metadata"]/dd[1]').InnerText | Should Be $Row.Result
            $Document.SelectSingleNode('//dl[@class="metadata"]/dd[2]').InnerText | Should Be $Row.Target
        }
        It 'preserves zero and false instead of displaying them as missing data' {
            $Rows[0].Result = 0
            $Rows[0].UsedDefault = $false
            $Rows[1].Result = $false
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Rows)
            $Document.SelectSingleNode('//details[@data-status="Passed"]//*[@class="result-value"]').InnerText | Should Be '0'
            $Document.SelectSingleNode('//details[@data-status="Failed"]//*[@class="result-value"]').InnerText | Should Be 'False'
            $Document.SelectSingleNode('//details[@data-status="Unknown"]//*[@class="result-value"]').InnerText | Should Be '—'
            $Document.SelectSingleNode('//details[@data-status="Passed"]//span[@class="value-origin origin-observed"]').InnerText | Should Be '실제 조회'
            $Document.SelectSingleNode('//details[@data-status="Failed"]//span[@class="value-origin origin-observed"]').InnerText | Should Be '실제 조회'
            $Document.SelectSingleNode('//details[@data-status="Unknown"]//span[@class="value-origin origin-unavailable"]').InnerText | Should Be '값 없음'
            $Document.SelectSingleNode('//details[@data-status="Passed"]//dl[@class="evidence"]/dd[@data-field="UsedDefault"]').InnerText | Should Be 'False'
        }
        It 'distinguishes default zero and false from identical observed values without changing raw CSV evidence' {
            $Values = @(0, $false)
            $Cases = @(
                For ($Index = 0; $Index -lt $Values.Count; $Index++) {
                    $Observed = New-SecurityAuditFinding -ID "observed-$Index" -Scope Machine -Category 'Fixture' `
                        -Result $Values[$Index] -TestResult Passed -ValueOrigin Observed
                    $Observed.UsedDefault = $false
                    $Observed.EngineTestResult = 'Passed'
                    $Observed
                    $Default = New-SecurityAuditFinding -ID "default-$Index" -Scope Machine -Category 'Fixture' `
                        -Result $Values[$Index] -TestResult Unknown -ValueOrigin Default -ReasonCode DefaultSubstitution
                    $Default.UsedDefault = $true
                    $Default.EngineTestResult = 'Passed'
                    $Default
                }
            )
            $BeforeRendering = ($Cases | ConvertTo-Csv -NoTypeInformation) -join "`n"
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Cases)
            (($Cases | ConvertTo-Csv -NoTypeInformation) -join "`n") | Should Be $BeforeRendering
            $Csv = @($Cases | ConvertTo-Csv -NoTypeInformation | ConvertFrom-Csv)
            ForEach ($Row in $Cases) {
                $Node = $Document.SelectSingleNode("//details[@class='finding'][summary//*[@class='item-id' and text()='Machine / $($Row.ID)']]")
                $Node.SelectSingleNode('.//*[@class="result-value"]').InnerText | Should Be ([String]$Row.Result)
                $CsvRow = $Csv | Where-Object ID -eq $Row.ID
                $CsvRow.Result | Should Be ([String]$Row.Result)
                $CsvRow.ValueOrigin | Should Be $Row.ValueOrigin
                $CsvRow.ReasonCode | Should Be $Row.ReasonCode
                $CsvRow.TestResult | Should Be $Row.TestResult
                If ($Row.ValueOrigin -eq 'Default') {
                    $Node.SelectSingleNode('.//span[@class="value-origin origin-default"]').InnerText | Should Be '목록 기본값 · 미조회'
                    $Row.TestResult | Should Be 'Unknown'
                    $Node.GetAttribute('data-status') | Should Be 'Unknown'
                    $Node.SelectSingleNode('.//dl[@class="evidence"]/dd[@data-field="EngineTestResult"]').InnerText | Should Be 'Passed'
                    $Node.SelectSingleNode('.//dl[@class="evidence"]/dd[@data-field="UsedDefault"]').InnerText | Should Be 'True'
                    $Node.SelectSingleNode('.//dl[@class="evidence"]/dd[@data-field="ReasonCode"]').InnerText | Should Be 'DefaultSubstitution'
                    $Node.GetAttribute('data-review') | Should Be 'Review'
                } Else {
                    $Node.SelectSingleNode('.//span[@class="value-origin origin-observed"]').InnerText | Should Be '실제 조회'
                    $Row.TestResult | Should Be 'Passed'
                }
            }
            ($Cases[0].Result -is [Int]) | Should Be $true
            ($Cases[1].Result -is [Int]) | Should Be $true
            ($Cases[2].Result -is [Boolean]) | Should Be $true
            ($Cases[3].Result -is [Boolean]) | Should Be $true
            $Document.SelectSingleNode('//*[@id="status-passed"]/strong').InnerText | Should Be '2'
            $Document.SelectSingleNode('//*[@id="status-unknown"]/strong').InnerText | Should Be '2'
        }
        It 'shows an observed empty string distinctly from missing and unverified empty values' {
            $Cases = @(
                New-SecurityAuditFinding -ID 'observed-empty' -Scope Machine -Result '' -TestResult Passed -ValueOrigin Observed -Source 'Get-MpPreference.ExclusionPath'
                New-SecurityAuditFinding -ID 'missing' -Result $null -TestResult Unknown
                New-SecurityAuditFinding -ID 'empty-unavailable' -Result '' -TestResult Unknown
                New-SecurityAuditFinding -ID 'empty-unverified' -Scope Machine -Result '' -TestResult Unknown -ValueOrigin Unverified -Source 'accesschk' -ReasonCode UnverifiedEmptyExport
                New-SecurityAuditFinding -ID 'empty-default' -Result '' -TestResult Unknown -ValueOrigin Default -ReasonCode DefaultSubstitution
                New-SecurityAuditFinding -ID 'observed-null' -Result $null -TestResult Unknown -ValueOrigin Observed
            )
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Cases)
            ForEach ($Row in $Cases) {
                $Node = $Document.SelectSingleNode("//details[@class='finding'][summary//*[@class='item-id' and text()='$($Row.Scope) / $($Row.ID)']]")
                If ($Row.ID -eq 'observed-empty') {
                    $Node.SelectSingleNode('.//*[@class="result-value"]').InnerText | Should Be '(빈 값)'
                    $Node.SelectSingleNode('.//span[@class="value-origin origin-observed"]').InnerText | Should Be '실제 조회'
                } Else {
                    $Node.SelectSingleNode('.//*[@class="result-value"]').InnerText | Should Be '—'
                }
                If ($Row.ValueOrigin -eq 'Unavailable') {
                    $Node.SelectSingleNode('.//span[@class="value-origin origin-unavailable"]').InnerText | Should Be '값 없음'
                } ElseIf ($Row.ValueOrigin -eq 'Unverified') {
                    $Node.SelectSingleNode('.//span[@class="value-origin origin-unverified"]').InnerText | Should Be '조회 확인 안 됨'
                    $Node.SelectSingleNode('.//dl[@class="evidence"]/dd[@data-field="ReasonCode"]').InnerText | Should Be 'UnverifiedEmptyExport'
                    $Node.GetAttribute('data-status') | Should Be 'Unknown'
                } ElseIf ($Row.ValueOrigin -eq 'Default') {
                    $Node.SelectSingleNode('.//span[@class="value-origin origin-default"]').InnerText | Should Be '목록 기본값 · 미조회'
                    $Node.GetAttribute('data-status') | Should Be 'Unknown'
                }
            }
            ($Cases[0].Result -is [String]) | Should Be $true
            $Cases[0].Result.Length | Should Be 0
            ($null -eq $Cases[1].Result) | Should Be $true
        }
        It 'labels nonempty unknown and error values as unverified rather than observed settings' {
            $Cases = @(
                New-SecurityAuditFinding -ID 'unknown-zero' -Result 0 -TestResult Unknown -ReasonCode CollectionError
                New-SecurityAuditFinding -ID 'error-false' -Result $false -TestResult Error -ReasonCode CollectionError
            )
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Cases)
            ForEach ($Row in $Cases) {
                $Node = $Document.SelectSingleNode("//details[@class='finding' and @data-status='$($Row.TestResult)']")
                $Node.SelectSingleNode('.//*[@class="result-value"]').InnerText | Should Be ([String]$Row.Result)
                $Node.SelectSingleNode('.//span[@class="value-origin origin-unverified"]').InnerText | Should Be '조회 확인 안 됨'
                $Node.SelectSingleNode('.//dl[@class="evidence"]/dd[@data-field="ReasonCode"]').InnerText | Should Be 'CollectionError'
            }
            $Document.SelectNodes('//span[@class="value-origin origin-observed"]').Count | Should Be 0
            $Document.DocumentElement.InnerText | Should Match 'ID별 재점검'
        }
        It 'has only local navigation, no active resources and an explicit offline content policy' {
            $Html = ConvertTo-SecurityAuditHtml -Findings $Rows
            $Document = [xml]$Html
            $Document.SelectNodes('//script|//link|//img|//iframe|//object|//form').Count | Should Be 0
            $Document.SelectNodes('//a[not(starts-with(@href, "#"))]').Count | Should Be 0
            $Document.SelectSingleNode('//meta[@http-equiv="Content-Security-Policy"]').content | Should Match "default-src 'none'"
            $Document.SelectSingleNode('//meta[@charset]').charset | Should Be 'utf-8'
            $Html | Should Match '@media print'
            $Html | Should Match '@media[^{]*max-width'
            ForEach ($Link in $Document.SelectNodes('//a')) {
                $Document.SelectNodes("//*[@id='$($Link.href.Substring(1))']").Count | Should Be 1
            }
        }
        It 'rejects an unsupported status rather than inserting it into an HTML attribute' {
            $Rows[0].TestResult = 'Passed" onclick="alert(1)'
            { ConvertTo-SecurityAuditHtml -Findings $Rows } | Should Throw 'Unsupported audit result'
        }
        It 'rejects missing, arbitrary and malicious origins instead of deriving provenance for raw records' {
            ForEach ($Origin in @('', $null, 'Guessed', 'Observed" onclick="alert(1)', '<script>alert(1)</script>')) {
                $Rows[0].ValueOrigin = $Origin
                { ConvertTo-SecurityAuditHtml -Findings $Rows } | Should Throw 'Unsupported audit value origin'
            }
            $Rows[0].PSObject.Properties.Remove('ValueOrigin')
            { ConvertTo-SecurityAuditHtml -Findings $Rows } | Should Throw 'Unsupported audit value origin'
        }
        It 'rejects absent and unlisted importance and priority instead of using them as CSS or attributes' {
            ForEach ($Property in @('Importance', 'RemediationPriority')) {
                $Original = $Rows[0].$Property
                ForEach ($Value in @('', $null, 'Critical', 'high', 'P1" onclick="alert(1)', '<script>alert(1)</script>')) {
                    $Rows[0].$Property = $Value
                    { ConvertTo-SecurityAuditHtml -Findings $Rows } | Should Throw 'Unsupported audit'
                }
                $Rows[0].$Property = $Original
            }
            $Rows[0].PSObject.Properties.Remove('Importance')
            { ConvertTo-SecurityAuditHtml -Findings $Rows } | Should Throw 'Unsupported audit importance'
        }
        It 'separates importance and priority counts and preserves the source snapshot during rendering' {
            $Reference = Get-SecurityAuditPriorityReference
            $Entry = $Reference['Machine:1421']
            $Fast = New-SecurityAuditFinding -ID '1421' -Scope Machine -List $Entry.List -Category 'Firewall' `
                -Name $Entry.Name -Source $Entry.Source -Recommended $Entry.Recommended -Result 4096 `
                -TestResult Failed -Severity High -Target 'host <admin>'
            Set-SecurityAuditPriority -Finding $Fast -Reference $Reference | Out-Null
            $Unknown = New-SecurityAuditFinding -ID 'missing' -Scope Machine -Result 0 -TestResult Unknown `
                -ValueOrigin Default -Severity High -ReasonCode DefaultSubstitution
            $Unknown.UsedDefault = $true
            $Review = New-SecurityAuditFinding -ID 'custom' -Scope Machine -Result 0 -TestResult Failed -Severity Low `
                -Name '<script>alert(1)</script>'
            $Review.PriorityReason = '<img src=x onerror="alert(1)">'
            $Cases = @($Fast, $Rows[1], $Review, $Unknown, $Rows[4], $Rows[5])
            $Before = ($Cases | ConvertTo-Csv -NoTypeInformation) -join "`n"
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Cases)
            (($Cases | ConvertTo-Csv -NoTypeInformation) -join "`n") | Should Be $Before
            $Document.SelectSingleNode('//*[@id="count-importance-high"]/strong').InnerText | Should Be '3'
            $Document.SelectSingleNode('//*[@id="count-priority-p1"]/strong').InnerText | Should Be '1'
            $Document.SelectSingleNode('//*[@id="count-priority-p2"]/strong').InnerText | Should Be '1'
            $Document.SelectSingleNode('//*[@id="count-priority-review"]/strong').InnerText | Should Be '2'
            $Document.SelectSingleNode('//*[@id="count-priority-none"]/strong').InnerText | Should Be '2'
            $Document.SelectNodes('//ol[@class="action-list"]/li').Count | Should Be 3
            $Document.SelectNodes('//script|//img').Count | Should Be 0
            $Document.SelectSingleNode('//*[@id="actions-Review"]//li//a').href | Should Be '#finding-2'
            $Document.SelectSingleNode('//*[@id="finding-2"]//p[@class="priority-reason"]').InnerText | Should Be "조치 분류 근거$($Review.PriorityReason)"
            For ($Index = 0; $Index -lt $Cases.Count; $Index++) {
                $Row = $Cases[$Index]
                $Node = $Document.SelectSingleNode("//*[@id='finding-$Index']")
                $Node.GetAttribute('data-importance') | Should Be $Row.Importance
                $Node.GetAttribute('data-priority') | Should Be $Row.RemediationPriority
                $Node.GetAttribute('data-status') | Should Be $Row.TestResult
                $Node.SelectSingleNode('.//p[@class="importance-reason"]').InnerText | Should Be "중요도 근거$($Row.ImportanceReason)"
                $Node.SelectSingleNode('.//p[@class="priority-reason"]').InnerText | Should Be "조치 분류 근거$($Row.PriorityReason)"
            }
            ForEach ($Link in $Document.SelectNodes('//a')) {
                $Document.SelectNodes("//*[@id='$($Link.href.Substring(1))']").Count | Should Be 1
            }
        }
        It 'links duplicate account IDs to distinct rows and sorts actions by importance within priority' {
            $Cases = @(
                New-SecurityAuditFinding -ID 'LA-04' -Category 'Local Accounts' -Name 'Never expires' -Target 'account-A' -Result $true -TestResult Failed
                New-SecurityAuditFinding -ID 'LA-05' -Category 'Local Accounts' -Name 'Password required' -Target 'account-A' -Result $false -TestResult Failed
                New-SecurityAuditFinding -ID 'LA-04' -Category 'Local Accounts' -Name 'Never expires' -Target 'account-B' -Result $true -TestResult Failed
            )
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Cases)
            $Links = @($Document.SelectNodes('//*[@id="actions-P3"]//li//a'))
            $Links.Count | Should Be 3
            $Links[0].href | Should Be '#finding-1'
            @($Links | ForEach-Object href | Select-Object -Unique).Count | Should Be 3
            ForEach ($Link in $Links) {
                $Document.SelectNodes("//*[@id='$($Link.href.Substring(1))']").Count | Should Be 1
            }
            $Document.SelectSingleNode('//*[@id="finding-0"]/summary//*[@class="item-target"]').InnerText | Should Be 'account-A'
            $Document.SelectSingleNode('//*[@id="finding-2"]/summary//*[@class="item-target"]').InnerText | Should Be 'account-B'
            $Document.SelectNodes('//*[@id="finding-1"]/summary//*[@class="item-target"]').Count | Should Be 0
        }
        It 'uses context audit start time even when a different collection row appears first' {
            $Rows[0].CheckedAt = '2026-10-29T15:00:00+09:00'
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Rows)
            $Document.SelectSingleNode('//dl[@class="metadata"]/dd[3]').InnerText | Should Be '2026-10-29T12:00:00+09:00'
            $Document.SelectSingleNode('//*[@id="finding-0"]//dl[@class="evidence"]/dd[@data-field="CheckedAt"]').InnerText | Should Be $Rows[0].CheckedAt
        }
        It 'renders each explanation as descriptive content, separate from the item name' {
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Rows)
            $Document.SelectNodes('//p[@class="description"]').Count | Should Be $Rows.Count
            ForEach ($Row in $Rows) {
                $Description = $Document.SelectSingleNode("//details[@class='finding' and @data-status='$($Row.TestResult)']//p[@class='description']")
                $Description.InnerText | Should Be "점검 내용$($Row.Description)"
                $Row.Description.Length | Should BeGreaterThan 30
                $Row.Description | Should Match '[가-힣]'
                $Row.Description | Should Not Be $Row.Name
            }
        }
        It 'integrates disjoint review lanes with importance without calling unresolved evidence compliant' {
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Rows)
            $Expected = @{ Action = 1; Review = 2; Record = 3 }
            $Total = 0
            ForEach ($Lane in @('Action', 'Review', 'Record')) {
                $Key = $Lane.ToLowerInvariant()
                $Count = [Int]$Document.SelectSingleNode("//*[@id='review-$Key']/strong").InnerText
                $Count | Should Be $Expected[$Lane]
                $Document.SelectNodes("//*[@id='catalog-$Key']//details[@class='finding' and @data-review='$Lane']").Count | Should Be $Count
                $Total += $Count
            }
            $Total | Should Be $Rows.Count
            $Document.SelectSingleNode('//*[@id="high-unresolved-count"]').InnerText | Should Be '2'
            $Document.SelectNodes('//*[@id="catalog-record"]//details[@data-status="Passed"]').Count | Should Be 1
            $Document.SelectNodes('//*[@id="catalog-record"]//details[@data-status="Info" or @data-status="NotApplicable"]').Count | Should Be 2
            $Document.SelectNodes('//*[@id="catalog-action"]//details[@data-status="Unknown" or @data-status="Error"]').Count | Should Be 0
            $Document.SelectNodes('//*[@id="actions-Review"]//li').Count | Should Be 0
            $Document.SelectSingleNode('//*[@id="count-priority-review"]/strong').InnerText | Should Be '2'
        }
        It 'cross-tabulates importance and verdict groups using the same complete evidence set' {
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Rows)
            $Total = 0
            ForEach ($Importance in @('High', 'Medium', 'Low', 'Unrated', 'Reference')) {
                $Key = $Importance.ToLowerInvariant()
                $MatrixRow = $Document.SelectSingleNode("//*[@id='count-importance-$Key']/ancestor-or-self::tr[1]")
                ($null -eq $MatrixRow) | Should Be $false
                ForEach ($Group in @(
                    @{ Name = 'Failed'; States = @('Failed') }
                    @{ Name = 'Unresolved'; States = @('Unknown', 'Error') }
                    @{ Name = 'Passed'; States = @('Passed') }
                    @{ Name = 'Reference'; States = @('Info', 'NotApplicable') }
                )) {
                    $Expected = @($Rows | Where-Object { $_.Importance -eq $Importance -and $_.TestResult -in $Group.States }).Count
                    $Actual = [Int]$MatrixRow.SelectSingleNode("*[@data-status-group='$($Group.Name)']").InnerText
                    $Actual | Should Be $Expected
                    $Total += $Actual
                }
            }
            $Total | Should Be $Rows.Count
        }
        It 'keeps review causes separate and preserves their summary outside screen-only action queues' {
            $Default = New-SecurityAuditFinding -ID 'default' -Scope Machine -Result 0 -TestResult Unknown `
                -ValueOrigin Default -ReasonCode DefaultSubstitution
            $Default.UsedDefault = $true
            $Unmapped = New-SecurityAuditFinding -ID 'custom' -Scope Machine -Result 0 -TestResult Failed -ReasonCode Compared
            $ErrorRow = New-SecurityAuditFinding -ID 'execution' -Scope Execution -TestResult Error -ReasonCode ExecutionError
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings @($Default, $Unmapped, $ErrorRow, $Rows[2]))
            $Expected = @{ Default = 1; Applicability = 1; Evidence = 2 }
            ForEach ($Kind in $Expected.Keys) {
                $Node = $Document.SelectSingleNode("//*[@data-review-workload='$Kind']")
                $Node.SelectNodes('ancestor::*[@class="work-queues-screen"]').Count | Should Be 0
                $Sum = 0
                ForEach ($Count in $Node.SelectNodes('.//ul[@class="reason-list"]/li/strong')) { $Sum += [Int]$Count.InnerText }
                $Sum | Should Be $Expected[$Kind]
            }
            $Document.SelectSingleNode('//*[@id="review-review"]/strong').InnerText | Should Be '4'
            $Document.SelectNodes('//ol[@class="action-list"]/li').Count | Should Be 1
        }
        It 'keeps every summary reachable and full evidence available behind native disclosure controls' {
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Rows)
            ForEach ($Node in $Document.SelectNodes('//details[@class="finding"]')) {
                $Node.SelectNodes('ancestor::details').Count | Should Be 0
                $Node.SelectNodes('summary').Count | Should Be 1
                $Node.HasAttribute('open') | Should Be $false
                $Node.SelectNodes('div[@class="finding-body"]').Count | Should Be 1
                $Node.SelectNodes('.//dl[@class="evidence"]/dd[@data-field]').Count | Should Be 7
                $Node.SelectNodes('.//details//*[@class="collection-details"]').Count | Should Be 1
                $Node.SelectNodes('.//*[@class="result-value"]').Count | Should Be 1
            }
            $Document.DocumentElement.InnerText | Should Match '요약'
            $Document.DocumentElement.InnerText | Should Match '펼'
        }
        It 'assigns unique destinations even when the very same object occurs more than once' {
            $Row = New-SecurityAuditFinding -ID 'LA-04' -Name 'Repeated account' -Target 'same-account' `
                -Result $true -TestResult Failed -Description '동일한 계정 식별자라도 입력 결과 행을 임의로 합치거나 생략하지 않는지 확인합니다.'
            $Cases = @($Row, $Row)
            $Before = ($Cases | ConvertTo-Csv -NoTypeInformation) -join "`n"
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Cases)
            $Document.SelectNodes('//details[@class="finding"]').Count | Should Be 2
            $Document.SelectNodes('//*[@id="finding-0"]').Count | Should Be 1
            $Document.SelectNodes('//*[@id="finding-1"]').Count | Should Be 1
            $Links = @($Document.SelectNodes('//*[@id="actions-P3"]//li//a'))
            $Links.Count | Should Be 2
            @($Links | ForEach-Object href | Select-Object -Unique).Count | Should Be 2
            (($Cases | ConvertTo-Csv -NoTypeInformation) -join "`n") | Should Be $Before
        }
        It 'orders change candidates by priority before importance without reordering pipeline objects' {
            $Reference = Get-SecurityAuditPriorityReference
            $Entry = $Reference['User:4501']
            $Slow = New-SecurityAuditFinding -ID 'LA-05' -Name 'Password required' -Result $false -TestResult Failed
            $Medium = New-SecurityAuditFinding -ID 'PP-02' -Name 'Password length' -Result 8 -TestResult Failed
            $Fast = New-SecurityAuditFinding -ID '4501' -Scope User -List $Entry.List -Name $Entry.Name `
                -Source $Entry.Source -Recommended $Entry.Recommended -Result 1 -TestResult Failed -Severity Low
            Set-SecurityAuditPriority -Finding $Fast -Reference $Reference | Out-Null
            $Cases = @($Slow, $Medium, $Fast)
            $Before = ($Cases | ConvertTo-Csv -NoTypeInformation) -join "`n"
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Cases)
            $Nodes = @($Document.SelectNodes('//*[@id="catalog-action"]//details[@class="finding"]'))
            ($Nodes | ForEach-Object id) -join ',' | Should Be 'finding-2,finding-1,finding-0'
            $Nodes[0].GetAttribute('data-importance') | Should Be 'Low'
            $Nodes[2].GetAttribute('data-importance') | Should Be 'High'
            (($Cases | ConvertTo-Csv -NoTypeInformation) -join "`n") | Should Be $Before
        }
        It 'does not use a baseline row with a colliding context ID as audit metadata' {
            $Fake = New-SecurityAuditFinding -ID 'CTX-01' -Scope Machine -Result 'wrong-host' -Target 'wrong-user' -TestResult Info
            $Fake.CheckedAt = '2000-01-01T01:00:00+09:00'
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings (@($Fake) + $Rows))
            $Document.SelectSingleNode('//dl[@class="metadata"]/dd[1]').InnerText | Should Be 'host'
            $Document.SelectSingleNode('//dl[@class="metadata"]/dd[2]').InnerText | Should Be 'host\user'
            $Document.SelectSingleNode('//dl[@class="metadata"]/dd[3]').InnerText | Should Be '2026-10-29T12:00:00+09:00'
            $OnlyFake = [xml](ConvertTo-SecurityAuditHtml -Findings @($Fake))
            $OnlyFake.SelectSingleNode('//dl[@class="metadata"]/dd[3]').InnerText | Should Be '—'
        }
        It 'retains long multiline values and diagnostics without presentation truncation or executable markup' {
            $LongValue = ('긴 설정 값 <script>alert(1)</script> & "원문"' + "`n") * 200
            $LongDetails = ('수집 진단 <img src=x onerror="alert(1)"> & 오류' + "`n") * 250
            $Reason = '<svg onload="alert(1)">원본 사유</svg>'
            $Row = New-SecurityAuditFinding -ID 'long' -Scope Machine -Name 'Long evidence' -Target 'target' `
                -Result $LongValue -TestResult Unknown -Details $LongDetails -ReasonCode $Reason -Severity High
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings @($Row))
            $Node = $Document.SelectSingleNode('//details[@class="finding"]')
            $Node.SelectSingleNode('.//*[@class="result-value"]').InnerText | Should Be $LongValue
            $Node.SelectSingleNode('.//*[@class="collection-details"]').InnerText | Should Be $LongDetails
            $Node.SelectSingleNode('.//dd[@data-field="ReasonCode"]').InnerText | Should Be $Reason
            $Document.SelectNodes('//script|//img|//svg|//*[@onload or @onerror or @onclick]').Count | Should Be 0
            $Node.GetAttribute('data-review') | Should Be 'Review'
        }
        It 'rejects contradictory priority metadata instead of presenting unsafe quick changes' {
            $Cases = @(
                @{ Status = 'Unknown'; Origin = 'Observed'; Priority = 'P1'; Default = $false; Scope = 'Machine' }
                @{ Status = 'Error'; Origin = 'Unavailable'; Priority = 'P2'; Default = $false; Scope = 'Machine' }
                @{ Status = 'Failed'; Origin = 'Default'; Priority = 'P1'; Default = $true; Scope = 'Machine' }
                @{ Status = 'Failed'; Origin = 'Observed'; Priority = 'P1'; Default = $true; Scope = 'Machine' }
                @{ Status = 'Failed'; Origin = 'Unverified'; Priority = 'P3'; Default = $false; Scope = 'Machine' }
                @{ Status = 'Failed'; Origin = 'Observed'; Priority = 'P1'; Default = $false; Scope = 'Execution' }
                @{ Status = 'Failed'; Origin = 'Observed'; Priority = 'None'; Default = $false; Scope = 'Machine' }
                @{ Status = 'Passed'; Origin = 'Observed'; Priority = 'P1'; Default = $false; Scope = 'Machine' }
                @{ Status = 'Info'; Origin = 'Reference'; Priority = 'Review'; Default = $false; Scope = 'Context' }
                @{ Status = 'NotApplicable'; Origin = 'Unavailable'; Priority = 'P3'; Default = $false; Scope = 'Supplemental' }
            )
            ForEach ($Case in $Cases) {
                $Row = New-SecurityAuditFinding -ID 'contradiction' -Scope $Case.Scope -Result 0 `
                    -TestResult $Case.Status -ValueOrigin $Case.Origin
                $Row.RemediationPriority = $Case.Priority
                $Row.UsedDefault = $Case.Default
                { ConvertTo-SecurityAuditHtml -Findings @($Row) } | Should Throw 'Inconsistent audit remediation priority'
            }
        }
    }

    Describe 'Read-only audit orchestration and reporting' {
        BeforeEach {
            Mock Invoke-SecurityAuditBaseline {}
            Mock Invoke-HardeningKitty { Throw 'Live baseline collection is forbidden in these tests.' }
            Mock Get-AccountAuditPolicy { @{ PasswordComplexity = '1'; ClearTextPassword = '0' } }
            Mock Get-AccountAuditModalsPolicy { @{ MinimumPasswordLength = 14; MaximumPasswordAge = 90; MinimumPasswordAge = 1; PasswordHistorySize = 24 } }
            Mock Get-AccountAuditScreenSaverValue {
                $Values = @{ ScreenSaveActive = '1'; ScreenSaverIsSecure = '1'; ScreenSaveTimeOut = '600'; 'SCRNSAVE.EXE' = 'test.scr' }
                @{ Found = $true; Value = $Values[$Name]; Error = ''; Source = 'test registry' }
            }
            Mock Test-AccountAuditScreenSaverFile { @{ Status = 'Passed'; Details = 'fixture' } }
            Mock Get-LocalUser {
                [PSCustomObject]@{
                    Name = 'test,account'; SID = 'S-1-5-21-1-2-3-1001'; Enabled = $true; PrincipalSource = 'Local'
                    PasswordLastSet = [DateTime]::Now.AddDays(-5); PasswordExpires = [DateTime]::Now.AddDays(85); PasswordRequired = $true
                }
            }
            Mock Get-CimInstance {
                [PSCustomObject]@{ Name = 'different-name'; SID = 'S-1-5-21-1-2-3-1001'; PasswordExpires = $true }
            }
        }
        It 'applies requested thresholds and joins account flags by SID' {
            $Rows = @(Invoke-HardeningKittySecurityAudit -ScreenSaverTimeoutSeconds 300 -MaximumPasswordAgeDays 30 -MinimumPasswordLength 15)
            ($Rows | Where-Object ID -eq SS-03).TestResult | Should Be 'Failed'
            ($Rows | Where-Object ID -eq PP-02).TestResult | Should Be 'Failed'
            ($Rows | Where-Object ID -eq PP-03).TestResult | Should Be 'Failed'
            ($Rows | Where-Object ID -eq LA-04).TestResult | Should Be 'Passed'
            Assert-MockCalled Get-AccountAuditPolicy -Times 1 -Exactly -Scope It
            Assert-MockCalled Get-CimInstance -Times 1 -Exactly -Scope It -ParameterFilter { $Filter -eq 'LocalAccount=True' }
        }
        It 'reclassifies only after disabled and non-local account statuses are finalized' {
            Mock Get-LocalUser {
                [PSCustomObject]@{
                    Name = 'disabled'; SID = 'S-1-5-21-1-2-3-1002'; Enabled = $false; PrincipalSource = 'Local'
                    PasswordLastSet = [DateTime]::Now.AddDays(-120); PasswordExpires = [DateTime]::Now.AddDays(-30); PasswordRequired = $false
                }
                [PSCustomObject]@{
                    Name = 'online'; SID = 'S-1-5-21-1-2-3-1003'; Enabled = $true; PrincipalSource = 'MicrosoftAccount'
                    PasswordLastSet = [DateTime]::Now.AddDays(-120); PasswordExpires = [DateTime]::Now.AddDays(-30); PasswordRequired = $false
                }
            }
            Mock Get-CimInstance {
                [PSCustomObject]@{ SID = 'S-1-5-21-1-2-3-1002'; PasswordExpires = $false }
                [PSCustomObject]@{ SID = 'S-1-5-21-1-2-3-1003'; PasswordExpires = $false }
            }
            $Path = Join-Path $TestDrive 'final-account-priorities.csv'
            $Rows = @(Invoke-HardeningKittySecurityAudit -MaximumPasswordAgeDays 90 -ReportFile $Path)
            $Accounts = @($Rows | Where-Object Category -eq 'Local Accounts')
            $Accounts.Count | Should Be 10
            @($Accounts | Where-Object { $_.TestResult -eq 'NotApplicable' -and $_.RemediationPriority -eq 'None' }).Count | Should Be 5
            @($Accounts | Where-Object { $_.TestResult -eq 'Unknown' -and $_.RemediationPriority -eq 'Review' }).Count | Should Be 5
            @($Accounts | Where-Object RemediationPriority -in @('P1', 'P2', 'P3')).Count | Should Be 0
            $Csv = @(Import-Csv -LiteralPath $Path -Encoding UTF8)
            For ($Index = 0; $Index -lt $Rows.Count; $Index++) {
                ForEach ($Property in @('Importance', 'ImportanceReason', 'RemediationPriority', 'PriorityReason', 'CheckedAt')) {
                    $Csv[$Index].$Property | Should Be $Rows[$Index].$Property
                }
            }
        }
        It 'attaches a known low-impact priority to collected baseline evidence before HTML and CSV export' {
            Mock Invoke-SecurityAuditBaseline {
                If ($Scope -ne 'Machine') { Return }
                $Entry = (Get-SecurityAuditPriorityReference)['Machine:1421']
                $Row = New-SecurityAuditFinding -ID '1421' -Scope Machine -Category 'Firewall' -List $Entry.List `
                    -Name $Entry.Name -Source $Entry.Source -Recommended $Entry.Recommended -Result 4096 `
                    -TestResult Failed -Severity High -Target $Target
                $Row.CheckedAt = '2026-10-29T12:30:00+09:00'
                $Row.UsedDefault = $false
                $Row.EngineTestResult = 'Failed'
                $Row
            }
            $Path = Join-Path $TestDrive 'baseline-priority.csv'
            $Rows = @(Invoke-HardeningKittySecurityAudit -ReportFile $Path)
            $Row = $Rows | Where-Object ID -eq '1421'
            $Row.RemediationPriority | Should Be 'P1'
            $Row.Importance | Should Be 'High'
            $Row.TestResult | Should Be 'Failed'
            $Row.CheckedAt | Should Be '2026-10-29T12:30:00+09:00'
            $Csv = Import-Csv -LiteralPath $Path -Encoding UTF8 | Where-Object ID -eq '1421'
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Rows)
            $Node = $Document.SelectSingleNode('//details[@class="finding" and @data-priority="P1"]')
            $Node.GetAttribute('data-importance') | Should Be $Row.Importance
            $Csv.RemediationPriority | Should Be $Row.RemediationPriority
            $Csv.PriorityReason | Should Be $Row.PriorityReason
            $Node.SelectSingleNode('.//p[@class="priority-reason"]').InnerText | Should Be "조치 분류 근거$($Row.PriorityReason)"
        }
        It 'preserves independent SAM checks when secedit is denied' {
            Mock Get-AccountAuditPolicy { Throw 'access denied' }
            $Rows = @(Invoke-HardeningKittySecurityAudit)
            ($Rows | Where-Object ID -eq PP-01).TestResult | Should Be 'Error'
            ($Rows | Where-Object ID -eq PP-06).TestResult | Should Be 'Error'
            ($Rows | Where-Object ID -eq PP-03).TestResult | Should Be 'Passed'
            ($Rows | Where-Object ID -eq SS-01).TestResult | Should Be 'Passed'
        }
        It 'does not turn missing complexity or reversible-encryption policy into a pass' {
            Mock Get-AccountAuditPolicy { @{} }
            $Rows = @(Invoke-HardeningKittySecurityAudit)
            ($Rows | Where-Object ID -eq PP-01).TestResult | Should Be 'Unknown'
            ($Rows | Where-Object ID -eq PP-06).TestResult | Should Be 'Unknown'
        }
        It 'reports native API failures rather than substituting exported defaults' {
            Mock Get-AccountAuditModalsPolicy { Throw 'SAM denied' }
            $Rows = @(Invoke-HardeningKittySecurityAudit)
            ($Rows | Where-Object ID -eq PP-02).TestResult | Should Be 'Error'
            ($Rows | Where-Object ID -eq PP-03).TestResult | Should Be 'Error'
            ($Rows | Where-Object ID -eq PP-01).TestResult | Should Be 'Passed'
        }
        It 'distinguishes a missing screen saver value from registry access failure' {
            Mock Get-AccountAuditScreenSaverValue { @{ Found = $false; Value = $null; Error = ''; Source = 'test registry' } }
            $Rows = @(Invoke-HardeningKittySecurityAudit)
            ($Rows | Where-Object ID -eq SS-02).TestResult | Should Be 'Unknown'
            Mock Get-AccountAuditScreenSaverValue { @{ Found = $false; Value = $null; Error = 'denied'; Source = 'test registry' } }
            $Rows = @(Invoke-HardeningKittySecurityAudit)
            ($Rows | Where-Object ID -eq SS-02).TestResult | Should Be 'Error'
        }
        It 'reports account enumeration failures without losing policy results' {
            Mock Get-LocalUser { Throw 'LocalAccounts unavailable' }
            $Rows = @(Invoke-HardeningKittySecurityAudit)
            ($Rows | Where-Object ID -eq LA-00).TestResult | Should Be 'Error'
            ($Rows | Where-Object ID -eq PP-01).TestResult | Should Be 'Passed'
        }
        It 'retains dates when account-flag collection fails' {
            Mock Get-CimInstance { Throw 'WMI denied' }
            $Rows = @(Invoke-HardeningKittySecurityAudit)
            ($Rows | Where-Object ID -eq LA-01).TestResult | Should Be 'Info'
            ($Rows | Where-Object ID -eq LA-04).TestResult | Should Be 'Unknown'
            ($Rows | Where-Object ID -eq LA-04).Details | Should Match 'WMI denied'
        }
        It 'treats unmatched account SIDs as unknown' {
            Mock Get-CimInstance { [PSCustomObject]@{ Name = 'test,account'; SID = 'S-1-5-21-1-2-3-9999'; PasswordExpires = $true } }
            $Rows = @(Invoke-HardeningKittySecurityAudit)
            ($Rows | Where-Object ID -eq LA-04).TestResult | Should Be 'Unknown'
        }
        It 'exports parseable CSV with each snapshot timestamp and never overwrites an existing report' {
            $Path = Join-Path $TestDrive 'audit.csv'
            $Rows = @(Invoke-HardeningKittySecurityAudit -ReportFile $Path)
            $Csv = @(Import-Csv -LiteralPath $Path -Encoding UTF8)
            $Csv.Count | Should Be $Rows.Count
            ($Csv | Where-Object ID -eq LA-01).Target | Should Match 'test,account'
            For ($Index = 0; $Index -lt $Rows.Count; $Index++) {
                $Csv[$Index].ID | Should Be $Rows[$Index].ID
                $Csv[$Index].CheckedAt | Should Be $Rows[$Index].CheckedAt
                $Csv[$Index].CheckedAt | Should Match '[+-]\d{2}:\d{2}$'
                $Csv[$Index].Description | Should Be $Rows[$Index].Description
                $Csv[$Index].Result | Should Be ([String]$Rows[$Index].Result)
                $Csv[$Index].ValueOrigin | Should Be $Rows[$Index].ValueOrigin
                $Csv[$Index].ReasonCode | Should Be $Rows[$Index].ReasonCode
            }
            $Hash = (Get-FileHash -LiteralPath $Path).Hash
            { Invoke-HardeningKittySecurityAudit -ReportFile $Path } | Should Throw
            (Get-FileHash -LiteralPath $Path).Hash | Should Be $Hash
        }
        It 'writes a UTF-8 HTML report from the same snapshot and returns the original objects' {
            $Path = Join-Path $TestDrive 'security audit [qa].HTML'
            $Rows = @(Invoke-HardeningKittySecurityAudit -ReportFile $Path)
            $Document = [xml](Get-Content -LiteralPath $Path -Raw -Encoding UTF8)
            $Document.SelectNodes('//details[@class="finding"]').Count | Should Be $Rows.Count
            $Document.SelectSingleNode('//h1').InnerText | Should Be '시스템 보안 점검 보고서'
            $Document.SelectSingleNode('//dl[@class="metadata"]/dd[3]').InnerText | Should Be ($Rows | Where-Object ID -eq CTX-01).CheckedAt
            ($Rows | Where-Object ID -eq LA-01).Target | Should Match 'test,account'
            ($Rows[0].PSObject.Properties.Name -join ',') | Should Be 'ID,Scope,List,Category,Name,Description,Target,Result,Recommended,TestResult,Source,Details,Severity,EngineTestResult,UsedDefault,ValueOrigin,ReasonCode,CheckedAt,Importance,ImportanceReason,RemediationPriority,PriorityReason'
            ForEach ($Row in $Rows) {
                $Node = $Document.SelectSingleNode("//details[@class='finding'][summary//*[@class='item-id' and text()='$($Row.Scope) / $($Row.ID)']]")
                $Node.SelectSingleNode('.//dl[@class="evidence"]/dd[@data-field="CheckedAt"]').InnerText | Should Be $Row.CheckedAt
                $Node.SelectSingleNode('.//p[@class="description"]').InnerText | Should Be "점검 내용$($Row.Description)"
            }
            ForEach ($Status in @('Passed', 'Failed', 'Unknown', 'Error', 'Info', 'NotApplicable')) {
                $Document.SelectNodes("//details[@class='finding' and @data-status='$Status']").Count |
                    Should Be @($Rows | Where-Object TestResult -eq $Status).Count
            }
            Assert-MockCalled Get-AccountAuditPolicy -Times 1 -Exactly -Scope It
            Assert-MockCalled Get-LocalUser -Times 1 -Exactly -Scope It
        }
        It 'supports htm and refuses to overwrite an existing HTML report' {
            $Path = Join-Path $TestDrive 'audit.htm'
            Invoke-HardeningKittySecurityAudit -ReportFile $Path | Out-Null
            ([xml](Get-Content -LiteralPath $Path -Raw -Encoding UTF8)).DocumentElement.Name | Should Be 'html'
            $Hash = (Get-FileHash -LiteralPath $Path).Hash
            { Invoke-HardeningKittySecurityAudit -ReportFile $Path } | Should Throw
            (Get-FileHash -LiteralPath $Path).Hash | Should Be $Hash
        }
        It 'reports HTML write failures instead of pretending a report was saved' {
            $Path = Join-Path $TestDrive 'missing-directory\audit.html'
            { Invoke-HardeningKittySecurityAudit -ReportFile $Path } | Should Throw
            Test-Path -LiteralPath $Path | Should Be $false
            Assert-MockCalled Invoke-SecurityAuditBaseline -Times 0 -Exactly -Scope It
            Assert-MockCalled Get-AccountAuditPolicy -Times 0 -Exactly -Scope It
            Assert-MockCalled Get-LocalUser -Times 0 -Exactly -Scope It
        }
        It 'rejects unsupported report extensions before collecting any data' {
            ForEach ($Name in @('audit', 'audit.txt', 'audit.json', 'audit.html.exe')) {
                { Invoke-HardeningKittySecurityAudit -ReportFile (Join-Path $TestDrive $Name) } | Should Throw
            }
            Assert-MockCalled Invoke-SecurityAuditBaseline -Times 0 -Exactly -Scope It
            Assert-MockCalled Get-AccountAuditPolicy -Times 0 -Exactly -Scope It
        }
        It 'rejects invalid audit thresholds before collecting any data' {
            { Invoke-HardeningKittySecurityAudit -ScreenSaverTimeoutSeconds 0 } | Should Throw
            { Invoke-HardeningKittySecurityAudit -MaximumPasswordAgeDays 0 } | Should Throw
            { Invoke-HardeningKittySecurityAudit -MinimumPasswordLength 129 } | Should Throw
            Assert-MockCalled Invoke-SecurityAuditBaseline -Times 0 -Exactly -Scope It
            Assert-MockCalled Get-AccountAuditPolicy -Times 0 -Exactly -Scope It
        }
        It 'retains machine and user baselines with the same ID, plus all supplemental findings' {
            Mock Invoke-SecurityAuditBaseline {
                $Row = New-SecurityAuditFinding -ID 'shared-id' -Scope $Scope -List $Definition.Name -Category 'Fixture' `
                    -Name "$Scope baseline fixture" -Description '머신과 현재 사용자 기준의 결과가 추가 계정 점검과 함께 유지되는지 확인합니다.' `
                    -Target $Target -Result 1 -Recommended 1 -TestResult Passed -Source 'mock engine' -Severity High
                $Row.CheckedAt = '2026-10-29T10:00:00+09:00'
                If ($Scope -eq 'User') { $Row.CheckedAt = '2026-10-29T10:05:00+09:00' }
                $Row
                $Execution = New-SecurityAuditFinding -ID "ENGINE-$Scope" -Scope Execution -List $Definition.Name `
                    -Category 'Audit execution' -Name "$Scope execution" -Description '실행 중 발생한 문제와 기준 목록의 수집 범위를 별도 결과로 기록합니다.' `
                    -Target $Target -Result '1 / 1' -TestResult Info -Source 'mock execution'
                $Execution.CheckedAt = $Row.CheckedAt
                $Execution
            }
            $Path = Join-Path $TestDrive 'combined.csv'
            $Rows = @(Invoke-HardeningKittySecurityAudit -ReportFile $Path)
            $Baselines = @($Rows | Where-Object ID -eq 'shared-id')
            $Baselines.Count | Should Be 2
            ($Baselines | Where-Object Scope -eq Machine).List | Should Be 'finding_list_0x6d69636b_machine.csv'
            ($Baselines | Where-Object Scope -eq User).List | Should Be 'finding_list_0x6d69636b_user.csv'
            ($Baselines | Where-Object Scope -eq Machine).CheckedAt | Should Be '2026-10-29T10:00:00+09:00'
            ($Baselines | Where-Object Scope -eq User).CheckedAt | Should Be '2026-10-29T10:05:00+09:00'
            @($Rows | Where-Object Scope -eq Supplemental).Count | Should Be 15
            @($Rows | Where-Object ID -eq CTX-01).Count | Should Be 1
            @($Rows | Where-Object Scope -eq Execution).Count | Should Be 2
            ($Rows | Where-Object ID -eq ENGINE-Machine).TestResult | Should Be 'Info'
            ($Rows | Where-Object ID -eq ENGINE-User).TestResult | Should Be 'Info'
            $Rows.Count | Should Be 20
            $Csv = @(Import-Csv -LiteralPath $Path -Encoding UTF8)
            $Csv.Count | Should Be $Rows.Count
            For ($Index = 0; $Index -lt $Rows.Count; $Index++) {
                $Csv[$Index].Scope | Should Be $Rows[$Index].Scope
                $Csv[$Index].CheckedAt | Should Be $Rows[$Index].CheckedAt
                ForEach ($Property in @('Importance', 'ImportanceReason', 'RemediationPriority', 'PriorityReason')) {
                    $Csv[$Index].$Property | Should Be $Rows[$Index].$Property
                }
            }
            $Document = [xml](ConvertTo-SecurityAuditHtml -Findings $Rows)
            ForEach ($Row in $Baselines) {
                $Node = $Document.SelectSingleNode("//details[@class='finding'][summary//*[@class='item-id' and text()='$($Row.Scope) / shared-id']]")
                $Node.SelectSingleNode('.//dl[@class="evidence"]/dd[@data-field="CheckedAt"]').InnerText | Should Be $Row.CheckedAt
            }
            $Document.SelectSingleNode('//dl[@class="metadata"]/dd[3]').InnerText | Should Be ($Rows | Where-Object ID -eq CTX-01).CheckedAt
            Assert-MockCalled Invoke-SecurityAuditBaseline -Times 1 -Exactly -Scope It -ParameterFilter {
                $Scope -eq 'Machine' -and $Definition.Findings.Count -eq 418 -and $Target -eq $env:COMPUTERNAME
            }
            Assert-MockCalled Invoke-SecurityAuditBaseline -Times 1 -Exactly -Scope It -ParameterFilter {
                $Scope -eq 'User' -and $Definition.Findings.Count -eq 56 -and $Target -match 'S-1-5-'
            }
            Assert-MockCalled Invoke-HardeningKitty -Times 0 -Exactly -Scope It
        }
        It 'uses both caller-selected lists without applying supplemental thresholds to their definitions' {
            $MachinePath = Join-Path $TestDrive '머신 [custom].csv'
            $UserPath = Join-Path $TestDrive '사용자 [custom].csv'
            [PSCustomObject]@{ ID = 'M1'; Category = 'Fixture'; Name = 'Machine item'; Method = 'Registry'; RecommendedValue = '7'; Operator = '>='; Severity = 'High' } |
                Export-Csv -LiteralPath $MachinePath -NoTypeInformation -Encoding UTF8
            [PSCustomObject]@{ ID = 'U1'; Category = 'Fixture'; Name = 'User item'; Method = 'Registry'; RecommendedValue = '12'; Operator = '<='; Severity = 'Low' } |
                Export-Csv -LiteralPath $UserPath -NoTypeInformation -Encoding UTF8
            Invoke-HardeningKittySecurityAudit -MachineFindingList $MachinePath -UserFindingList $UserPath `
                -MinimumPasswordLength 17 -ScreenSaverTimeoutSeconds 120 -MaximumPasswordAgeDays 45 | Out-Null
            Assert-MockCalled Invoke-SecurityAuditBaseline -Times 1 -Exactly -Scope It -ParameterFilter {
                $Scope -eq 'Machine' -and $Definition.Findings[0].ID -eq 'M1' -and $Definition.Findings[0].RecommendedValue -eq '7'
            }
            Assert-MockCalled Invoke-SecurityAuditBaseline -Times 1 -Exactly -Scope It -ParameterFilter {
                $Scope -eq 'User' -and $Definition.Findings[0].ID -eq 'U1' -and $Definition.Findings[0].RecommendedValue -eq '12'
            }
        }
        It 'provides substantive Korean descriptions for every emitted supplemental row and enumeration error' {
            $Rows = @(Invoke-HardeningKittySecurityAudit)
            Mock Get-LocalUser { Throw 'fixture enumeration failure' }
            $Rows += @(Invoke-HardeningKittySecurityAudit)
            $Expected = @('CTX-01', 'SS-01', 'SS-02', 'SS-03', 'SS-04', 'PP-01', 'PP-02', 'PP-03',
                'PP-04', 'PP-05', 'PP-06', 'LA-00', 'LA-01', 'LA-02', 'LA-03', 'LA-04', 'LA-05')
            ForEach ($ID in $Expected) { @($Rows | Where-Object ID -eq $ID).Count | Should BeGreaterThan 0 }
            ForEach ($Row in $Rows) {
                $Row.Description.Length | Should BeGreaterThan 30
                $Row.Description | Should Match '[가-힣]'
                $Row.Description | Should Not Be $Row.Name
                $Row.Description | Should Not Match 'TODO|설명 없음|추후 작성'
            }
        }
        It 'rejects existing files, directory destinations and non-directory parents before collection' {
            $Existing = Join-Path $TestDrive 'existing.html'
            Set-Content -LiteralPath $Existing -Value 'unchanged report' -Encoding UTF8
            $Directory = New-Item -Path (Join-Path $TestDrive 'directory.html') -ItemType Directory
            $ParentFile = Join-Path $TestDrive 'parent-file'
            Set-Content -LiteralPath $ParentFile -Value 'not a directory'
            ForEach ($Path in @($Existing, $Directory.FullName, (Join-Path $ParentFile 'audit.csv'))) {
                { Invoke-HardeningKittySecurityAudit -ReportFile $Path } | Should Throw
            }
            (Get-Content -LiteralPath $Existing -Encoding UTF8) | Should Be 'unchanged report'
            Assert-MockCalled Invoke-SecurityAuditBaseline -Times 0 -Exactly -Scope It
            Assert-MockCalled Get-AccountAuditPolicy -Times 0 -Exactly -Scope It
            Assert-MockCalled Get-LocalUser -Times 0 -Exactly -Scope It
        }
        It 'rejects an explicitly missing destination and missing list before collecting system data' {
            { Invoke-HardeningKittySecurityAudit -ReportFile '' } | Should Throw
            { Invoke-HardeningKittySecurityAudit -ReportFile $null } | Should Throw
            { Invoke-HardeningKittySecurityAudit -MachineFindingList (Join-Path $TestDrive 'missing.csv') } | Should Throw
            Assert-MockCalled Invoke-SecurityAuditBaseline -Times 0 -Exactly -Scope It
            Assert-MockCalled Get-AccountAuditPolicy -Times 0 -Exactly -Scope It
            Assert-MockCalled Get-LocalUser -Times 0 -Exactly -Scope It
        }
    }
}
