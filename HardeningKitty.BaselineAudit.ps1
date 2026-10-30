# Private baseline collection and explanation support for HardeningKitty.SecurityAudit.psm1.

Function New-SecurityAuditDirectory {
    $Path = Join-Path ([IO.Path]::GetTempPath()) ('HardeningKitty_' + [Guid]::NewGuid().ToString('N'))
    $Directory = New-Item -Path $Path -ItemType Directory -ErrorAction Stop
    Try {
        $Acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $Acl.SetAccessRuleProtection($true, $false)
        $Rule = New-Object Security.AccessControl.FileSystemAccessRule(
            [Security.Principal.WindowsIdentity]::GetCurrent().User,
            [Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $Acl.AddAccessRule($Rule)
        Set-Acl -LiteralPath $Path -AclObject $Acl -ErrorAction Stop
        Return $Directory.FullName
    } Catch {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Throw
    }
}

Function Get-SecurityAuditCatalog {
    $Catalog = @{}
    ForEach ($File in @('descriptions-machine-core.json', 'descriptions-machine-platform.json', 'descriptions-apps-user.json')) {
        $Path = Join-Path $PSScriptRoot "report-data\$File"
        $Entries = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        ForEach ($Entry in $Entries) {
            $Key = "$($Entry.Scope):$($Entry.ID)"
            If ($Entry.Scope -notin @('Machine', 'User') -or [String]::IsNullOrWhiteSpace($Entry.ID) -or
                [String]::IsNullOrWhiteSpace($Entry.Name) -or [String]::IsNullOrWhiteSpace($Entry.Description) -or $Catalog.ContainsKey($Key)) {
                Throw "Invalid or duplicate description entry: $Key in $File"
            }
            $Catalog[$Key] = $Entry
        }
    }
    Return $Catalog
}

Function Import-SecurityAuditList {
    Param ([String] $Path)

    $Resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    $Findings = @(Import-Csv -LiteralPath $Resolved -Encoding UTF8 -ErrorAction Stop)
    If ($Findings.Count -eq 0) { Throw "Finding list is empty: $Resolved" }
    ForEach ($Column in @('ID', 'Category', 'Name', 'Method', 'RecommendedValue', 'Operator', 'Severity')) {
        If ($Findings[0].PSObject.Properties.Name -notcontains $Column) { Throw "Finding list is missing column $Column`: $Resolved" }
    }
    $IDs = @{}
    ForEach ($Finding in $Findings) {
        If ([String]::IsNullOrWhiteSpace($Finding.ID) -or $IDs.ContainsKey($Finding.ID)) {
            Throw "Missing or duplicate finding ID in $Resolved`: $($Finding.ID)"
        }
        If ([String]::IsNullOrWhiteSpace($Finding.Name) -or [String]::IsNullOrWhiteSpace($Finding.Method)) {
            Throw "Missing finding name or method in $Resolved`: $($Finding.ID)"
        }
        $IDs[$Finding.ID] = $true
    }
    Return [PSCustomObject]@{ Path = $Resolved; Name = [IO.Path]::GetFileName($Resolved); Findings = $Findings }
}

Function Get-SecurityAuditQuery {
    Param ($Finding)

    Switch ($Finding.Method) {
        'Registry' { Return "레지스트리 값: $($Finding.RegistryPath)\$($Finding.RegistryItem)" }
        'RegistryList' { Return "레지스트리 목록: $($Finding.RegistryPath), 항목 $($Finding.RegistryItem)" }
        'secedit' { Return "secedit /export SECURITYPOLICY: $($Finding.MethodArgument)" }
        'accesschk' { Return "secedit /export USER_RIGHTS: $($Finding.MethodArgument) (할당된 계정/SID 목록)" }
        'auditpol' { Return "auditpol /backup: 감사 하위 범주 $($Finding.MethodArgument)" }
        'accountpolicy' { Return "net accounts의 로컬 정책 출력: $($Finding.Name) (언어 의존 파싱)" }
        'WindowsOptionalFeature' { Return "Get-WindowsOptionalFeature -Online: $($Finding.MethodArgument)" }
        'CimInstance' { Return "Get-CimInstance: $($Finding.Namespace) / $($Finding.ClassName) / $($Finding.Property)" }
        'BitLockerVolume' { Return "Get-BitLockerVolume: $env:SystemDrive / $($Finding.MethodArgument)" }
        'LanguageMode' { Return '현재 PowerShell 실행 세션의 LanguageMode' }
        'localaccount' { Return "Get-LocalUser: 로컬 계정 RID $($Finding.MethodArgument) / $($Finding.Property)" }
        'MpComputerStatus' { Return "Get-MpComputerStatus: $($Finding.MethodArgument)" }
        'MpPreference' { Return "Get-MpPreference: $($Finding.MethodArgument)" }
        'MpPreferenceAsr' { Return "Get-MpPreference: ASR 규칙 $($Finding.MethodArgument)" }
        'MpPreferenceExclusion' { Return "Get-MpPreference: 제외 목록 $($Finding.MethodArgument)" }
        'Processmitigation' { Return "Get-ProcessMitigation -System: $($Finding.MethodArgument)" }
        'bcdedit' { Return "bcdedit 읽기 전용 출력에서 권장값 문자열 검색: $($Finding.RecommendedValue)" }
        'FirewallRule' { Return "Get-NetFirewallRule -PolicyStore ActiveStore: $($Finding.Name), Enabled 값만 조회" }
        'service' { Return "Get-Service: $($Finding.MethodArgument), StartType (실행 상태와 다름)" }
        'ScheduledTask' { Return "Get-ScheduledTask: $($Finding.MethodArgument), State" }
        Default { Return "조회 메서드 $($Finding.Method), 인수 $($Finding.MethodArgument), 속성 $($Finding.Property)" }
    }
}

Function Get-SecurityAuditCriterion {
    Param ($Finding)

    $Value = [String]$Finding.RecommendedValue
    If ($Value.Length -eq 0) { $Value = '(빈 값)' }
    Switch ($Finding.Operator) {
        '=' { Return "같음 (=): $Value" }
        '!=' { Return "다름 (!=): $Value" }
        '<=' { Return "이하 (<=): $Value" }
        '<=!0' { Return "0이 아니면서 이하 (<=!0): $Value" }
        '>=' { Return "이상 (>=): $Value" }
        'contains' { Return "포함 (contains): $Value" }
        'notcontains' { Return "포함하지 않음 (notcontains): $Value" }
        '=|0' { Return "같거나 빈 값 (=|0): $Value" }
        Default { Return "연산자 $($Finding.Operator): $Value" }
    }
}

Function Get-SecurityAuditDescription {
    Param ($Finding, [String] $Scope, [Hashtable] $Catalog)

    If (-not [String]::IsNullOrWhiteSpace($Finding.Description)) { Return [String]$Finding.Description }
    $Entry = $Catalog["$Scope`:$($Finding.ID)"]
    If ($null -ne $Entry -and $Entry.Name -ceq $Finding.Name) { Return [String]$Entry.Description }
    # Custom lists can provide Description. Never present generated query metadata as authored security rationale.
    Return "목록 작성자의 항목 설명이 없는 사용자 정의 점검입니다. $(Get-SecurityAuditQuery -Finding $Finding)에서 얻은 값을 '$(Get-SecurityAuditCriterion -Finding $Finding)' 기준과 비교합니다. 업무상 의미와 적용 가능성은 목록 제공자에게 확인하세요."
}

Function Invoke-SecurityAuditEngine {
    Param (
        [String] $ListPath,
        [ValidateNotNullOrEmpty()]
        [String] $FindingID
    )

    $Directory = New-SecurityAuditDirectory
    $ReportPath = Join-Path $Directory 'results.csv'
    $OldTemp = $env:TEMP
    $OldTmp = $env:TMP
    $EngineInformation = @()
    $EngineErrors = @()
    $EngineWarnings = @()
    $Rows = @()
    $Completed = $false
    $Failure = ''
    $EngineSession = $null
    $SavedDefaults = $null
    $HadDefaults = $false
    $ChangedDefaults = $false
    $Selection = @{}
    Try {
        If ($PSBoundParameters.ContainsKey('FindingID')) {
            $SelectedID = [String]$FindingID
            $Selection.Filter = { [String]$_.ID -ceq $SelectedID }.GetNewClosure()
        }
        # A caller-local preference does not cross a script-module boundary.
        # Temporarily set the engine module's own encoding preference, then restore it.
        $EngineCommand = Get-Command Invoke-HardeningKitty -CommandType Function -ErrorAction Stop
        # Module points at the re-exporting manifest; ScriptBlock.Module owns the actual function.
        $EngineModule = $EngineCommand.ScriptBlock.Module
        If ($null -eq $EngineModule) { Throw 'Import HardeningKitty.psd1 before running the comprehensive audit.' }
        $EngineSession = $EngineModule.SessionState
        $Variable = $EngineSession.PSVariable.Get('script:PSDefaultParameterValues')
        $HadDefaults = $null -ne $Variable
        If ($HadDefaults) { $SavedDefaults = $Variable.Value }
        $CurrentDefaults = $EngineSession.PSVariable.GetValue('PSDefaultParameterValues')
        $EngineDefaults = @{}
        ForEach ($Key in $CurrentDefaults.Keys) { $EngineDefaults[$Key] = $CurrentDefaults[$Key] }
        $EngineDefaults['Export-Csv:Encoding'] = 'UTF8'
        $EngineSession.PSVariable.Set('script:PSDefaultParameterValues', $EngineDefaults)
        $ChangedDefaults = $true
        # Contain the original engine's temporary files even if its cleanup is bypassed.
        $env:TEMP = $Directory
        $env:TMP = $Directory
        # An unlabeled Break/Continue in the legacy function must not escape this boundary.
        For ($Attempt = 0; $Attempt -lt 1; $Attempt++) {
            & $EngineCommand @Selection -Mode Audit -Source GPO -FileFindingList $ListPath -Report -ReportFile $ReportPath `
                -SkipMachineInformation -SkipUserInformation -InformationVariable EngineInformation `
                -WarningVariable EngineWarnings -ErrorVariable EngineErrors -ErrorAction Continue | Out-Null
            $Completed = $true
        }
        If (-not $Completed) { $Failure = '원본 엔진이 정상 반환 전에 실행을 중단했습니다.' }
        If (Test-Path -LiteralPath $ReportPath -PathType Leaf) {
            $Rows = @(Import-Csv -LiteralPath $ReportPath -Encoding UTF8 -ErrorAction Stop)
        } Else {
            $Failure += ' 원본 엔진이 CSV 보고서를 생성하지 않았습니다.'
        }
        If ($Selection.ContainsKey('Filter') -and ($Rows.Count -ne 1 -or [String]$Rows[0].ID -cne $FindingID)) {
            $Failure += " 개별 조회 결과는 요청한 ID '$FindingID'의 단일 행이어야 합니다. 반환 행 수: $($Rows.Count)."
        }
    } Catch {
        $Failure = $_.Exception.Message
    } Finally {
        $env:TEMP = $OldTemp
        $env:TMP = $OldTmp
        If ($ChangedDefaults) {
            Try {
                If ($HadDefaults) {
                    $EngineSession.PSVariable.Set('script:PSDefaultParameterValues', $SavedDefaults)
                } Else {
                    $EngineSession.PSVariable.Remove('script:PSDefaultParameterValues')
                }
            } Catch { $Failure += " 엔진 인코딩 기본 설정 복원 실패: $($_.Exception.Message)" }
        }
        Try { Remove-Item -LiteralPath $Directory -Recurse -Force -ErrorAction Stop } Catch {
            $Failure += " 임시 디렉터리 정리 실패: $Directory. $($_.Exception.Message)"
        }
    }
    # [!] prefixes both protocol errors and ordinary High-severity verdicts.
    # Exclude only complete verdict messages corroborated by the actual CSV.
    $HighVerdicts = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    ForEach ($Row in $Rows) {
        If ($Row.TestResult -eq 'Failed' -and $Row.Severity -eq 'High') {
            [void]$HighVerdicts.Add("[!] ID $($Row.ID), $($Row.Name), Result=$($Row.Result), Recommended=$($Row.Recommended), Severity=High")
            # The != operator decorates only the displayed recommendation, not the CSV.
            [void]$HighVerdicts.Add("[!] ID $($Row.ID), $($Row.Name), Result=$($Row.Result), Recommended=Not $($Row.Recommended), Severity=High")
        }
    }
    $Information = @($EngineInformation | ForEach-Object { $_.ToString() } | Where-Object { -not $HighVerdicts.Contains($_) })
    $Messages = @($Information | Where-Object {
        $_ -match '^\[(\!|\?)\]' -or $_ -match 'Finding list (verified|is custom)'
    })
    $Messages += @($EngineWarnings | ForEach-Object { $_.ToString() })
    $Messages += @($EngineErrors | ForEach-Object { $_.ToString() })
    $Diagnostics = ($Messages | Select-Object -Unique) -join "`n"
    If ($Diagnostics.Length -gt 8000) { $Diagnostics = $Diagnostics.Substring(0, 8000) + "`n[추가 진단 메시지 생략]" }
    $HasErrors = @($EngineErrors).Count -gt 0 -or @($Information | Where-Object { $_ -match '^\[!\]' }).Count -gt 0
    Return [PSCustomObject]@{ Rows = $Rows; Completed = $Completed; Error = $Failure.Trim(); Diagnostics = $Diagnostics; HasErrors = $HasErrors }
}

Function ConvertFrom-SecurityAuditEngineReport {
    Param ($Definition, $Run, [String] $Scope, [String] $Target, [Hashtable] $Catalog, [DateTimeOffset] $CheckedAt)

    $ByID = @{}
    $Unexpected = New-Object 'System.Collections.Generic.List[string]'
    $Expected = @{}
    ForEach ($Finding in $Definition.Findings) { $Expected[$Finding.ID] = $true }
    ForEach ($Row in $Run.Rows) {
        If ([String]::IsNullOrWhiteSpace($Row.ID) -or -not $Expected.ContainsKey($Row.ID)) {
            $Unexpected.Add([String]$Row.ID)
            Continue
        }
        If (-not $ByID.ContainsKey($Row.ID)) { $ByID[$Row.ID] = New-Object 'System.Collections.Generic.List[object]' }
        $ByID[$Row.ID].Add($Row)
    }
    $MissingCount = 0
    $DefaultCount = 0
    $DuplicateCount = 0
    ForEach ($Finding in $Definition.Findings) {
        $Rows = $ByID[$Finding.ID]
        $Result = $null
        $EngineStatus = ''
        $UsedDefault = $null
        $Status = 'Error'
        $ValueOrigin = 'Unavailable'
        $ReasonCode = 'MissingResult'
        $Details = ''
        If ($null -eq $Rows) {
            $MissingCount++
            $Details = '선택한 기준 목록에는 있지만 원본 CSV에 결과가 없습니다. 권한·명령 부재·실행 오류 등 원인을 확인해야 하며 통과 또는 적용 제외로 추정하지 않습니다.'
        } ElseIf ($Rows.Count -ne 1) {
            $DuplicateCount++
            $ReasonCode = 'DuplicateResult'
            $Details = '동일 ID에 여러 결과가 있어 하나의 판정을 선택할 수 없습니다.'
        } Else {
            $Row = $Rows[0]
            $Result = $Row.Result
            $EngineStatus = [String]$Row.TestResult
            $ParsedDefault = $false
            $DefaultKnown = [Boolean]::TryParse([String]$Row.DefaultValue, [ref]$ParsedDefault)
            If ($DefaultKnown) { $UsedDefault = $ParsedDefault }
            If ($UsedDefault) { $DefaultCount++ }
            $Status = $EngineStatus
            $ValueOrigin = 'Unverified'
            $ReasonCode = 'Compared'
            If ($UsedDefault) { $ValueOrigin = 'Default' }
            $Details = "원본 판정: $EngineStatus. 원본 권장값: $($Row.Recommended)."
            If ($Row.PSObject.Properties.Name -notcontains 'Result') {
                $Status = 'Error'
                $ValueOrigin = 'Unavailable'
                $ReasonCode = 'MissingResultColumn'
                $Details += ' 원본 CSV에 Result 열이 없어 빈 조회값과 구분할 수 없습니다.'
            } ElseIf ($Status -notin @('Passed', 'Failed')) {
                $Status = 'Error'
                $ReasonCode = 'InvalidEngineVerdict'
                $Details += ' 원본 판정 형식이 유효하지 않습니다.'
            } ElseIf (-not $DefaultKnown) {
                $Status = 'Unknown'
                $ReasonCode = 'UnknownDefaultFlag'
                $Details += ' 기본값 대체 여부가 없거나 유효하지 않아 실제 조회값인지 확인할 수 없습니다.'
            } ElseIf ($UsedDefault) {
                $Status = 'Unknown'
                $ReasonCode = 'DefaultSubstitution'
                $Details += ' 값이 없거나 조회에 실패하여 기준 목록의 기본값으로 대체되었습니다. 실측 통과로 인정하지 않습니다.'
            } ElseIf ($Finding.Method -eq 'MpPreferenceAsr' -and [String]$Result -eq [String]$Finding.DefaultValue) {
                $Status = 'Unknown'
                $ReasonCode = 'UnverifiedAsrDefault'
                $Details += ' 원본 ASR 수집기는 규칙이 없을 때 대체 여부 표시 없이 기본값을 반환할 수 있습니다. 실제 규칙 배열을 확인해야 합니다.'
            } ElseIf ([String]$Result -match '^(\-NODATA\-|NotSupported|NotConfigured|PathNotExists|WinningProviderNotExists|Not available|Manual check required)$') {
                $Status = 'Unknown'
                $ValueOrigin = 'Unavailable'
                $ReasonCode = 'CollectorMarker'
                $Details += ' 직접 판정할 수 없는 원본 수집기 표시값입니다.'
            } ElseIf ($Finding.Method -eq 'accesschk' -and [String]::IsNullOrWhiteSpace([String]$Result)) {
                $Status = 'Unknown'
                $ReasonCode = 'UnverifiedEmptyExport'
                $Details += ' 원본 USER_RIGHTS 수집기는 secedit의 종료 코드를 확인하지 않습니다. 빈 내보내기 파일과 실제로 비어 있는 권한 할당을 구분할 성공 근거가 없어 통과 또는 미충족으로 단정하지 않습니다.'
            } Else {
                $Number = 0L
                $NumericExpected = 0L
                $IsNumeric = $Finding.Operator -in @('<=', '<=!0', '>=') -or
                    ($Finding.Operator -in @('=', '!=') -and [Long]::TryParse([String]$Finding.RecommendedValue, [ref]$NumericExpected))
                If ($IsNumeric -and -not [Long]::TryParse([String]$Result, [ref]$Number)) {
                    $Status = 'Unknown'
                    $ReasonCode = 'InvalidNumericEvidence'
                    $Details += ' 수치 비교에 필요한 실제 값이 누락되었거나 숫자가 아닙니다.'
                } ElseIf ([String]::IsNullOrWhiteSpace([String]$Result) -and
                    -not ($Finding.Operator -eq '=|0' -or $Finding.Method -in @('accesschk', 'MpPreferenceExclusion') -or
                    ($Finding.Operator -eq '=' -and [String]$Finding.RecommendedValue -eq ''))) {
                    $Status = 'Unknown'
                    $ValueOrigin = 'Unavailable'
                    $ReasonCode = 'EmptyValue'
                    $Details += ' 조회 결과가 비어 있어 관측된 상태로 판정하지 않습니다.'
                } Else {
                    $ValueOrigin = 'Observed'
                }
            }
            If ($Finding.Method -eq 'FirewallRule') { $Details += ' 방화벽 규칙의 Enabled만 확인하며 포트·동작·실제 통신 차단을 검증하지 않습니다.' }
            If ($Finding.Method -eq 'service') { $Details += ' 서비스 시작 유형 점검이며 현재 실행 여부 점검과 다릅니다.' }
        }
        If (-not [String]::IsNullOrWhiteSpace($Run.Error)) {
            $Details += " 실행 오류: $($Run.Error)"
            $Status = 'Error'
            $ReasonCode = 'ExecutionError'
        } ElseIf (-not $Run.Completed) {
            $Details += ' 원본 엔진의 정상 완료가 확인되지 않았습니다.'
            $Status = 'Error'
            $ReasonCode = 'ExecutionIncomplete'
        } ElseIf ($Run.HasErrors -and $Status -in @('Passed', 'Failed')) {
            $Status = 'Unknown'
            $ValueOrigin = 'Unverified'
            $ReasonCode = 'CollectionError'
            $Details += ' 이 실행에서 수집 오류가 발생하여 정상 조회된 값인지 확인할 수 없습니다. 오류 없는 항목별 수집 근거 없이는 통과 또는 미충족으로 단정하지 않습니다.'
        }
        If ($Status -eq 'Error' -and $ValueOrigin -eq 'Observed') { $ValueOrigin = 'Unverified' }
        $Record = New-SecurityAuditFinding -ID $Finding.ID -Scope $Scope -List $Definition.Name -Category $Finding.Category `
            -Name $Finding.Name -Description (Get-SecurityAuditDescription -Finding $Finding -Scope $Scope -Catalog $Catalog) `
            -Target $Target -Result $Result -Recommended (Get-SecurityAuditCriterion -Finding $Finding) -TestResult $Status `
            -Source (Get-SecurityAuditQuery -Finding $Finding) -Details $Details -Severity $Finding.Severity `
            -ValueOrigin $ValueOrigin -ReasonCode $ReasonCode
        $Record.EngineTestResult = $EngineStatus
        $Record.UsedDefault = $UsedDefault
        $Record.CheckedAt = $CheckedAt.ToString('o')
        $Record
    }
    $ExecutionStatus = 'Info'
    If ($Run.Error -or $Run.HasErrors -or -not $Run.Completed -or $MissingCount -gt 0 -or $DuplicateCount -gt 0 -or $Unexpected.Count -gt 0) { $ExecutionStatus = 'Error' }
    $Summary = "예정 $($Definition.Findings.Count)개; 원본 행 $(@($Run.Rows).Count)개; 누락 $MissingCount; 중복 ID $DuplicateCount; 예상하지 않은 ID $($Unexpected.Count); 기본값 대체 $DefaultCount."
    If ($Unexpected.Count -gt 0) { $Summary += " 예상하지 않은 ID: $($Unexpected -join ', ')." }
    $Summary += "`n$($Run.Error)`n$($Run.Diagnostics)"
    $Execution = New-SecurityAuditFinding -ID "ENGINE-$Scope" -Scope 'Execution' -List $Definition.Name -Category 'Audit execution' `
        -Name "$Scope baseline collection" -Description '기준 목록의 모든 예정 항목이 보고서에 반영되었는지와 원본 엔진의 진단 메시지를 확인합니다. 일부 항목이 실행되지 않았는데도 점검 완료로 오해하지 않도록 실행 범위를 기록합니다.' `
        -Target $Target -Result "$(@($Run.Rows).Count) / $($Definition.Findings.Count)" -Recommended '모든 예정 항목의 결과와 수집 근거 확인' `
        -TestResult $ExecutionStatus -Source $Definition.Path -Details $Summary.Trim()
    $Execution.CheckedAt = $CheckedAt.ToString('o')
    $Execution
}

Function Invoke-SecurityAuditBaseline {
    Param ($Definition, [String] $Scope, [String] $Target, [Hashtable] $Catalog)

    $CheckedAt = [DateTimeOffset]::Now
    Try { $Run = Invoke-SecurityAuditEngine -ListPath $Definition.Path } Catch {
        $Run = [PSCustomObject]@{ Rows = @(); Completed = $false; Error = $_.Exception.Message; Diagnostics = '' }
    }
    $Records = @(ConvertFrom-SecurityAuditEngineReport -Definition $Definition -Run $Run -Scope $Scope -Target $Target -Catalog $Catalog -CheckedAt $CheckedAt)
    $DefinitionsByID = @{}
    ForEach ($Finding in $Definition.Findings) { $DefinitionsByID[$Finding.ID] = $Finding }
    $Rechecked = 0
    $Comparable = 0
    For ($Index = 0; $Index -lt $Records.Count; $Index++) {
        $Record = $Records[$Index]
        If ($Record.Scope -ne $Scope -or $Record.ReasonCode -ne 'CollectionError') { Continue }

        # Only comparable observations affected by collection errors reach this path.
        # Reuse the original collectors and comparisons; never infer success from a value alone.
        $Rechecked++
        $ItemTime = [DateTimeOffset]::Now
        $ItemDefinition = [PSCustomObject]@{
            Path = $Definition.Path; Name = $Definition.Name; Findings = @($DefinitionsByID[$Record.ID])
        }
        Try {
            $ItemRun = Invoke-SecurityAuditEngine -ListPath $Definition.Path -FindingID $Record.ID
        } Catch {
            $ItemRun = [PSCustomObject]@{ Rows = @(); Completed = $false; Error = $_.Exception.Message; Diagnostics = ''; HasErrors = $true }
        }
        # Validate this contract here too: unexpected/duplicate rows must not be lost
        # when discarding the isolated execution-summary row below.
        If (@($ItemRun.Rows).Count -ne 1 -or [String]$ItemRun.Rows[0].ID -cne $Record.ID) {
            $ItemRun.Error = "$($ItemRun.Error) 개별 재조회에서 요청한 ID의 단일 결과를 확인하지 못했습니다.".Trim()
        }
        $ItemRecords = @(ConvertFrom-SecurityAuditEngineReport -Definition $ItemDefinition -Run $ItemRun `
            -Scope $Scope -Target $Target -Catalog $Catalog -CheckedAt $ItemTime)
        $Replacement = $ItemRecords[0]
        $Replacement.Details = '수집 오류의 영향을 분리하기 위해 이 ID만 개별 재조회한 결과입니다. ' + $Replacement.Details
        If (-not [String]::IsNullOrWhiteSpace($ItemRun.Diagnostics)) { $Replacement.Details += "`n개별 수집 진단: $($ItemRun.Diagnostics)" }
        If ($Replacement.TestResult -in @('Passed', 'Failed')) { $Comparable++ }
        $Records[$Index] = $Replacement
    }
    If ($Rechecked -gt 0) {
        $Execution = $Records | Where-Object { $_.Scope -eq 'Execution' -and $_.ID -eq "ENGINE-$Scope" }
        $Execution.Details += "`n오류 영향 분리를 위한 ID별 개별 재조회: $Rechecked; 정상 비교 가능: $Comparable; 미확인 또는 오류: $($Rechecked - $Comparable). 위 예정/원본 행 수와 진단은 최초 일괄 실행 기록이며, 항목별 값과 시각은 개별 재조회 결과를 사용합니다."
    }
    $Records
}
