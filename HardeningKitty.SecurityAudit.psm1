#Requires -Version 5.1

. (Join-Path $PSScriptRoot 'HardeningKitty.BaselineAudit.ps1')
. (Join-Path $PSScriptRoot 'HardeningKitty.PriorityAudit.ps1')
. (Join-Path $PSScriptRoot 'HardeningKitty.Report.ps1')

Function New-SecurityAuditFinding {
    Param (
        [String] $ID,
        [String] $Category,
        [String] $Name,
        [String] $Target,
        $Result,
        [String] $Recommended,
        [ValidateSet('Passed', 'Failed', 'Unknown', 'Error', 'Info', 'NotApplicable')]
        [String] $TestResult,
        [String] $Source,
        [String] $Details,
        [String] $Description,
        [String] $Scope = 'Supplemental',
        [String] $List,
        [String] $Severity,
        [ValidateSet('Observed', 'Default', 'Unverified', 'Unavailable', 'Reference')]
        [String] $ValueOrigin,
        [String] $ReasonCode = ''
    )

    If ([String]::IsNullOrWhiteSpace($Description) -and $Scope -eq 'Supplemental') {
        $Description = Get-SupplementalAuditDescription -ID $ID
    }
    If (-not $PSBoundParameters.ContainsKey('ValueOrigin')) {
        If ($Scope -in @('Context', 'Execution')) {
            $ValueOrigin = 'Reference'
        } ElseIf ($null -eq $Result -or [String]$Result -eq '') {
            $ValueOrigin = 'Unavailable'
        } ElseIf ($TestResult -in @('Unknown', 'Error')) {
            $ValueOrigin = 'Unverified'
        } Else {
            $ValueOrigin = 'Observed'
        }
    }
    $Finding = [PSCustomObject][ordered]@{
        ID = $ID
        Scope = $Scope
        List = $List
        Category = $Category
        Name = $Name
        Description = $Description
        Target = $Target
        Result = $Result
        Recommended = $Recommended
        TestResult = $TestResult
        Source = $Source
        Details = $Details
        Severity = $Severity
        EngineTestResult = $null
        UsedDefault = $null
        ValueOrigin = $ValueOrigin
        ReasonCode = $ReasonCode
        CheckedAt = $null
    }
    Set-SecurityAuditPriority -Finding $Finding
}

Function Get-SupplementalAuditDescription {
    Param ([String] $ID)

    $Descriptions = @{
        'CTX-01' = '이 보고서를 실행한 컴퓨터와 사용자 SID 및 점검 범위를 기록합니다. 머신 설정과 현재 사용자 설정을 구분하여 다른 계정의 결과로 오해하지 않도록 합니다.'
        'SS-01' = '사용자가 입력하지 않는 동안 화면 보호기가 작동하도록 설정되어 있는지 확인합니다. 활성화 값만으로 잠금이 보장되지는 않으므로 대기시간·실행 파일·암호 보호 설정도 함께 확인해야 합니다.'
        'SS-02' = '화면 보호기에서 돌아올 때 다시 인증하도록 설정되어 있는지 확인합니다. 자리를 비운 사이 다른 사람이 로그인된 세션을 사용하는 위험을 줄이기 위한 설정입니다.'
        'SS-03' = '입력이 없는 상태에서 화면 보호기가 시작되기까지의 시간을 초 단위로 확인합니다. 0초 또는 지나치게 긴 대기시간은 방치된 세션을 보호하지 못할 수 있습니다.'
        'SS-04' = '설정된 화면 보호기 파일이 실제로 존재하는 로컬 .scr 파일인지 확인합니다. 활성화되어 있어도 실행 파일이 없으면 화면 보호기가 작동하지 않을 수 있으며, 파일을 실행하거나 원격 공유에 연결하지는 않습니다.'
        'PP-01' = '새 비밀번호를 설정할 때 Windows의 복잡도 조건을 적용하는 정책인지 확인합니다. 기존 비밀번호의 실제 강도나 Windows Hello PIN을 검사하는 항목은 아닙니다.'
        'PP-02' = '새 비밀번호에 요구되는 최소 문자 수를 확인합니다. 짧은 비밀번호는 추측과 자동화된 대입 공격에 취약하므로 조직의 길이 기준과 비교합니다.'
        'PP-03' = '일반 로컬 계정 비밀번호를 변경 없이 사용할 수 있는 최대 기간을 일 단위로 확인합니다. 계정별 무기한 사용 플래그는 별도로 적용되며, 정기 변경 필요성은 조직 정책에 따라 판단해야 합니다.'
        'PP-04' = '비밀번호를 변경한 뒤 다시 변경할 수 있기까지 기다려야 하는 최소 기간을 확인합니다. 즉시 여러 번 변경하여 비밀번호 재사용 제한을 우회하는 상황을 줄이기 위한 정책입니다.'
        'PP-05' = '이전에 사용한 비밀번호를 몇 개까지 기억해 재사용을 막는지 확인합니다. 예전 비밀번호를 반복하여 사용하는 것을 제한하는 정책이며 실제 비밀번호나 해시를 수집하지 않습니다.'
        'PP-06' = '비밀번호를 원문으로 복구할 수 있는 형태로 저장하도록 허용하는지 확인합니다. 이 방식은 인증 저장소가 노출될 때 피해가 커질 수 있으므로 사용 필요성과 비활성화 여부를 점검합니다.'
        'LA-00' = '로컬 계정 목록을 정상적으로 읽을 수 있었는지 확인합니다. 조회 실패를 계정이 없거나 안전한 상태인 것으로 해석하지 않도록 오류를 별도 결과로 남깁니다.'
        'LA-01' = '로컬 계정 저장소에 기록된 마지막 비밀번호 설정·변경 시각을 확인합니다. Microsoft·Entra ID·도메인 계정의 실제 온라인 변경일을 증명하는 자료는 아닙니다.'
        'LA-02' = '마지막 비밀번호 변경 이후의 경과일을 이번 점검의 기간 기준과 비교합니다. 호스트 시계가 부정확하거나 변경일이 없으면 신뢰할 수 있는 판정이 불가능합니다.'
        'LA-03' = 'Windows가 반환한 비밀번호 만료 예정 시각이 지났는지 확인합니다. 만료 시각이 없는 경우 무기한 사용이라고 단정하지 않고 계정 플래그와 최대 사용 기간 정책을 함께 확인합니다.'
        'LA-04' = '계정에 비밀번호가 만료되지 않도록 하는 예외 플래그가 설정되어 있는지 확인합니다. 머신의 최대 사용 기간이 유한해도 이 플래그가 켜진 계정에는 정기 만료가 적용되지 않을 수 있습니다.'
        'LA-05' = '계정 생성·설정에서 비밀번호를 필수로 요구하는 플래그를 확인합니다. 이 값만으로 현재 비밀번호가 비어 있거나 충분히 강한지 판단할 수는 없습니다.'
    }
    Return $Descriptions[$ID]
}

Function ConvertFrom-AccountAuditPolicy {
    Param ([String[]] $Lines)

    $Policy = @{}
    $Section = ''
    ForEach ($Line in $Lines) {
        If ($Line -match '^\s*\[([^\]]+)\]\s*$') {
            $Section = $Matches[1].Trim()
        } ElseIf ($Section -eq 'System Access' -and $Line -match '^\s*([^;=][^=]*?)\s*=\s*(.*?)\s*$') {
            $Policy[$Matches[1].Trim()] = $Matches[2].Trim()
        }
    }
    Return $Policy
}

Function Export-AccountAuditPolicy {
    Param ([String] $Path, [String] $LogPath)

    $Secedit = Join-Path -Path $env:SystemRoot -ChildPath 'System32\secedit.exe'
    & $Secedit /export /cfg $Path /mergedpolicy /areas SECURITYPOLICY /log $LogPath /quiet | Out-Null
    If ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Throw "secedit export failed (exit code $LASTEXITCODE). Run an elevated PowerShell as the same user being audited."
    }
}

Function Get-AccountAuditPolicy {
    $DirectoryPath = New-SecurityAuditDirectory
    Try {
        $PolicyPath = Join-Path -Path $DirectoryPath -ChildPath 'security-policy.inf'
        $LogPath = Join-Path -Path $DirectoryPath -ChildPath 'secedit.log'
        Export-AccountAuditPolicy -Path $PolicyPath -LogPath $LogPath
        ConvertFrom-AccountAuditPolicy -Lines (Get-Content -LiteralPath $PolicyPath -ErrorAction Stop)
    } Finally {
        Remove-Item -LiteralPath $DirectoryPath -Recurse -Force -ErrorAction Stop
    }
}

Function ConvertFrom-AccountAuditModalsPolicy {
    Param ($Policy)

    $MaximumAge = $Policy.MaximumPasswordAgeSeconds / 86400
    If ($Policy.MaximumPasswordAgeSeconds -eq [UInt32]::MaxValue) { $MaximumAge = 0 }
    Return @{
        MinimumPasswordLength = $Policy.MinimumPasswordLength
        MaximumPasswordAge = $MaximumAge
        MinimumPasswordAge = $Policy.MinimumPasswordAgeSeconds / 86400
        PasswordHistorySize = $Policy.PasswordHistoryLength
    }
}

Function Get-AccountAuditModalsPolicy {
    # secedit can omit unset password-policy entries. Read these four values
    # directly from the local SAM using the documented, language-neutral API.
    If (-not ('HardeningKitty.AccountAudit.NativePolicy' -as [Type])) {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace HardeningKitty.AccountAudit
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PasswordPolicy
    {
        public uint MinimumPasswordLength;
        public uint MaximumPasswordAgeSeconds;
        public uint MinimumPasswordAgeSeconds;
        public uint ForceLogoffSeconds;
        public uint PasswordHistoryLength;
    }

    public static class NativePolicy
    {
        [DllImport("Netapi32.dll", ExactSpelling = true)]
        private static extern uint NetUserModalsGet(IntPtr server, uint level, out IntPtr buffer);
        [DllImport("Netapi32.dll", ExactSpelling = true)]
        private static extern uint NetApiBufferFree(IntPtr buffer);

        public static PasswordPolicy Read()
        {
            IntPtr buffer = IntPtr.Zero;
            try
            {
                uint status = NetUserModalsGet(IntPtr.Zero, 0, out buffer);
                if (status != 0) throw new Win32Exception((int)status);
                if (buffer == IntPtr.Zero) throw new InvalidOperationException("No local password policy returned.");
                return (PasswordPolicy)Marshal.PtrToStructure(buffer, typeof(PasswordPolicy));
            }
            finally
            {
                if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
            }
        }
    }
}
'@
    }
    ConvertFrom-AccountAuditModalsPolicy -Policy ([HardeningKitty.AccountAudit.NativePolicy]::Read())
}

Function Get-AccountAuditScreenSaverValue {
    Param ([String] $Name)

    # Policy takes precedence per value, including an explicit zero or empty string.
    ForEach ($Path in @('HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop', 'HKCU:\Control Panel\Desktop')) {
        Try {
            $Properties = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
            $Property = $Properties.PSObject.Properties[$Name]
            If ($null -ne $Property) {
                Return @{ Value = $Property.Value; Source = "$Path\$Name"; Error = ''; Found = $true }
            }
        } Catch [System.Management.Automation.ItemNotFoundException] {
            Continue
        } Catch {
            Return @{ Value = $null; Source = "$Path\$Name"; Error = $_.Exception.Message; Found = $false }
        }
    }
    Return @{ Value = $null; Source = 'HKCU policy and user preference'; Error = ''; Found = $false }
}

Function Test-AccountAuditNumber {
    Param ($Value, [Long] $Minimum, [Long] $Maximum)

    $Number = 0L
    If (-not [Long]::TryParse([String]$Value, [ref]$Number)) { Return 'Unknown' }
    If ($Number -ge $Minimum -and $Number -le $Maximum) { Return 'Passed' }
    Return 'Failed'
}

Function Test-AccountAuditScreenSaverFile {
    Param ([String] $Value)

    If ([String]::IsNullOrWhiteSpace($Value)) {
        Return @{ Status = 'Failed'; Details = 'No screen saver executable is configured.' }
    }
    $Path = [Environment]::ExpandEnvironmentVariables($Value.Trim().Trim('"'))
    # Do not contact a remote share (and potentially send credentials) during an audit.
    If ($Path.StartsWith('\\') -or $Path.StartsWith('//') -or $Path.Contains('%')) {
        Return @{ Status = 'Unknown'; Details = 'Remote or unresolved path; file existence was not checked.' }
    }
    If ($Path -notmatch '^[A-Za-z]:[\\/]') {
        If ($Path -match '[\\/:]') {
            Return @{ Status = 'Unknown'; Details = 'Ambiguous relative path; file existence was not checked.' }
        }
        $Path = Join-Path -Path $env:SystemRoot -ChildPath "System32\$Path"
    }
    Try {
        $Drive = New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($Path))
        If ($Drive.DriveType -eq [IO.DriveType]::Network) {
            Return @{ Status = 'Unknown'; Details = 'Mapped network drive; file existence was not checked.' }
        }
        If ([IO.Path]::GetExtension($Path) -ieq '.scr' -and (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction Stop)) {
            Return @{ Status = 'Passed'; Details = "Configured file exists: $Path. The executable was not run." }
        }
        Return @{ Status = 'Failed'; Details = "Configured .scr file was not found: $Path" }
    } Catch {
        Return @{ Status = 'Error'; Details = $_.Exception.Message }
    }
}

Function Get-AccountAuditUserFinding {
    Param ($User, $AccountFlags, [String] $FlagsError, [DateTimeOffset] $Now, [Int] $MaximumPasswordAgeDays)

    $Target = "$env:COMPUTERNAME\$($User.Name) [$($User.SID)]"
    $Source = "Get-LocalUser (PrincipalSource=$($User.PrincipalSource))"
    $LastSet = $null
    $Age = $null
    $AgeStatus = 'Unknown'
    $LastSetStatus = 'Unknown'
    $DateDetails = 'No last-set timestamp returned; this does not prove a blank password or that it was never changed.'
    If ($null -ne $User.PasswordLastSet) {
        $LastSetDate = [DateTimeOffset]$User.PasswordLastSet
        $LastSet = $LastSetDate.ToLocalTime().ToString('o')
        $ElapsedDays = ($Now - $LastSetDate).TotalDays
        $Age = [Math]::Floor($ElapsedDays)
        If ($ElapsedDays -lt 0) {
            $DateDetails = 'Last-set timestamp is in the future relative to the host clock; verify the clock and record.'
        } Else {
            $LastSetStatus = 'Info'
            $AgeStatus = 'Failed'
            If ($ElapsedDays -lt $MaximumPasswordAgeDays) { $AgeStatus = 'Passed' }
            $DateDetails = 'Local SAM timestamp; elapsed age is evaluated against the supplied audit limit, not a claim about password strength.'
        }
    }

    $Expires = $null
    $ExpiryStatus = 'Info'
    If ($null -ne $User.PasswordExpires) {
        $ExpiryDate = [DateTimeOffset]$User.PasswordExpires
        $Expires = $ExpiryDate.ToLocalTime().ToString('o')
        If ($ExpiryDate -le $Now) { $ExpiryStatus = 'Failed' }
    }
    $NeverExpires = $null
    $NeverStatus = 'Unknown'
    If ($null -ne $AccountFlags -and $null -ne $AccountFlags.PasswordExpires) {
        $NeverExpires = -not $AccountFlags.PasswordExpires
        $NeverStatus = 'Passed'
        If ($NeverExpires) { $NeverStatus = 'Failed' }
    }
    $RequiredStatus = 'Unknown'
    If ($null -ne $User.PasswordRequired) {
        $RequiredStatus = 'Failed'
        If ($User.PasswordRequired) { $RequiredStatus = 'Passed' }
    }

    $Findings = @(
        (New-SecurityAuditFinding -ID 'LA-01' -Category 'Local Accounts' -Name 'Password last set' -Target $Target -Result $LastSet -Recommended 'Available, non-future timestamp' -TestResult $LastSetStatus -Source $Source -Details $DateDetails)
        (New-SecurityAuditFinding -ID 'LA-02' -Category 'Local Accounts' -Name 'Password age (days)' -Target $Target -Result $Age -Recommended "< $MaximumPasswordAgeDays days (audit limit)" -TestResult $AgeStatus -Source $Source -Details $DateDetails)
        (New-SecurityAuditFinding -ID 'LA-03' -Category 'Local Accounts' -Name 'Password expiry date' -Target $Target -Result $Expires -Recommended 'Not expired' -TestResult $ExpiryStatus -Source $Source -Details 'A missing expiry date alone does not establish the never-expire flag. See the account flag and maximum-age policy separately.')
        (New-SecurityAuditFinding -ID 'LA-04' -Category 'Local Accounts' -Name 'Password never expires (account flag)' -Target $Target -Result $NeverExpires -Recommended 'False' -TestResult $NeverStatus -Source 'Win32_UserAccount.PasswordExpires (matched by SID)' -Details $FlagsError)
        (New-SecurityAuditFinding -ID 'LA-05' -Category 'Local Accounts' -Name 'Password required (account flag)' -Target $Target -Result $User.PasswordRequired -Recommended 'True' -TestResult $RequiredStatus -Source $Source -Details 'This flag does not reveal whether the current password is blank or meets complexity requirements.')
    )
    ForEach ($Finding in $Findings) {
        If ($User.Enabled -eq $false) {
            $Finding.TestResult = 'NotApplicable'
            $Finding.Details = 'Disabled account; metadata retained but excluded from compliance assessment. ' + $Finding.Details
        } ElseIf ([String]$User.PrincipalSource -ne 'Local') {
            $Finding.TestResult = 'Unknown'
            $Finding.Details = 'Non-local or unknown identity source: local SAM metadata is not authoritative for the online/domain password. Verify with the identity provider. ' + $Finding.Details
        }
        If ($Finding.ID -eq 'LA-04' -and $null -eq $NeverExpires -and [String]::IsNullOrEmpty($FlagsError)) {
            $Finding.Details += ' No matching SID or expiry flag was returned.'
        }
        $Finding
    }
}

Function Get-AccountAuditFinding {
    [CmdletBinding()]
    Param (
        [ValidateRange(1, 86400)]
        [Int] $ScreenSaverTimeoutSeconds = 900,
        [ValidateRange(1, 999)]
        [Int] $MaximumPasswordAgeDays = 365,
        [ValidateRange(1, 128)]
        [Int] $MinimumPasswordLength = 14
    )

    If ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Throw 'This audit requires Windows.'
    }
    $Now = [DateTimeOffset]::Now
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $UserTarget = "$($Identity.Name) [$($Identity.User.Value)]"
    $Findings = New-Object 'System.Collections.Generic.List[object]'

    $ScreenChecks = @(
        @{ ID = 'SS-01'; Name = 'Screen saver enabled'; Key = 'ScreenSaveActive'; Minimum = 1; Maximum = 1; Recommended = '1' }
        @{ ID = 'SS-02'; Name = 'Password protection on resume'; Key = 'ScreenSaverIsSecure'; Minimum = 1; Maximum = 1; Recommended = '1' }
        @{ ID = 'SS-03'; Name = 'Screen saver timeout (seconds)'; Key = 'ScreenSaveTimeOut'; Minimum = 1; Maximum = $ScreenSaverTimeoutSeconds; Recommended = "1..$ScreenSaverTimeoutSeconds seconds" }
        @{ ID = 'SS-04'; Name = 'Screen saver executable'; Key = 'SCRNSAVE.EXE'; Recommended = 'Existing local .scr file' }
    )
    ForEach ($Check in $ScreenChecks) {
        $Setting = Get-AccountAuditScreenSaverValue -Name $Check.Key
        $Details = ''
        If ($Setting.Error) {
            $Status = 'Error'
            $Details = $Setting.Error
        } ElseIf (-not $Setting.Found) {
            $Status = 'Unknown'
            $Details = 'Not configured in either registry location; no Windows default is assumed.'
        } ElseIf ($Check.ID -eq 'SS-04') {
            $FileCheck = Test-AccountAuditScreenSaverFile -Value $Setting.Value
            $Status = $FileCheck.Status
            $Details = $FileCheck.Details
        } Else {
            $Status = Test-AccountAuditNumber -Value $Setting.Value -Minimum $Check.Minimum -Maximum $Check.Maximum
            If ($Status -eq 'Unknown') { $Details = 'Value is missing or is not an integer.' }
        }
        $Findings.Add((New-SecurityAuditFinding -ID $Check.ID -Category 'Screen Saver' -Name $Check.Name -Target $UserTarget -Result $Setting.Value -Recommended $Check.Recommended -TestResult $Status -Source $Setting.Source -Details $Details))
    }

    $Policy = @{}
    $PolicyError = ''
    Try { $Policy = Get-AccountAuditPolicy } Catch { $PolicyError = $_.Exception.Message }
    $ModalsPolicy = @{}
    $ModalsError = ''
    Try { $ModalsPolicy = Get-AccountAuditModalsPolicy } Catch { $ModalsError = $_.Exception.Message }
    $PolicyChecks = @(
        @{ ID = 'PP-01'; Key = 'PasswordComplexity'; Name = 'Password complexity policy'; Minimum = 1; Maximum = 1; Recommended = '1 (enabled)' }
        @{ ID = 'PP-02'; Key = 'MinimumPasswordLength'; Method = 'SAM'; Name = 'Minimum password length'; Minimum = $MinimumPasswordLength; Maximum = 128; Recommended = ">= $MinimumPasswordLength characters" }
        @{ ID = 'PP-03'; Key = 'MaximumPasswordAge'; Method = 'SAM'; Name = 'Maximum password age'; Minimum = 1; Maximum = $MaximumPasswordAgeDays; Recommended = "1..$MaximumPasswordAgeDays days" }
        @{ ID = 'PP-04'; Key = 'MinimumPasswordAge'; Method = 'SAM'; Name = 'Minimum password age'; Minimum = 1; Maximum = 999; Recommended = '>= 1 day' }
        @{ ID = 'PP-05'; Key = 'PasswordHistorySize'; Method = 'SAM'; Name = 'Password history size'; Minimum = 24; Maximum = 24; Recommended = '24 remembered passwords' }
        @{ ID = 'PP-06'; Key = 'ClearTextPassword'; Name = 'Store passwords using reversible encryption'; Minimum = 0; Maximum = 0; Recommended = '0 (disabled)' }
    )
    ForEach ($Check in $PolicyChecks) {
        $Value = $Policy[$Check.Key]
        $ReadError = $PolicyError
        $Source = "secedit /export /mergedpolicy: System Access\$($Check.Key)"
        If ($Check.Method -eq 'SAM') {
            $Value = $ModalsPolicy[$Check.Key]
            $ReadError = $ModalsError
            $Source = "NetUserModalsGet (local SAM): $($Check.Key)"
        }
        $Details = 'Machine policy only; does not prove existing passwords comply or describe directory/cloud policies.'
        $Status = Test-AccountAuditNumber -Value $Value -Minimum $Check.Minimum -Maximum $Check.Maximum
        If ($ReadError) {
            $Status = 'Error'
            $Details = $ReadError
        } ElseIf ($Status -eq 'Unknown') {
            $Details = 'Policy value was absent or invalid; no default is substituted.'
        } ElseIf ($Check.Key -eq 'MaximumPasswordAge' -and [Long]$Value -le 0) {
            $Details = 'Unlimited/no periodic expiry; does not meet the selected finite-age audit baseline.'
        }
        $Findings.Add((New-SecurityAuditFinding -ID $Check.ID -Category 'Password Policy' -Name $Check.Name -Target $env:COMPUTERNAME -Result $Value -Recommended $Check.Recommended -TestResult $Status -Source $Source -Details $Details))
    }

    $FlagsBySid = @{}
    $FlagsError = ''
    Try {
        Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop | ForEach-Object {
            $FlagsBySid[[String]$_.SID] = $_
        }
    } Catch { $FlagsError = $_.Exception.Message }
    Try {
        $Users = @(Get-LocalUser -ErrorAction Stop)
        If ($Users.Count -eq 0) { Throw 'No local accounts were returned.' }
        ForEach ($User in $Users) {
            Get-AccountAuditUserFinding -User $User -AccountFlags $FlagsBySid[[String]$User.SID] -FlagsError $FlagsError -Now $Now -MaximumPasswordAgeDays $MaximumPasswordAgeDays | ForEach-Object {
                $Findings.Add($_)
            }
        }
    } Catch {
        $Findings.Add((New-SecurityAuditFinding -ID 'LA-00' -Category 'Local Accounts' -Name 'Local account enumeration' -Target $env:COMPUTERNAME -Result $null -Recommended 'Readable local account metadata' -TestResult 'Error' -Source 'Get-LocalUser' -Details $_.Exception.Message))
    }

    ForEach ($Finding in $Findings) { $Finding.CheckedAt = $Now.ToString('o') }
    $Findings
}

Function Invoke-HardeningKittySecurityAudit {
    <#
    .SYNOPSIS
        Runs machine and current-user security baselines plus supplemental account checks, with an explained HTML/CSV report.
    .DESCRIPTION
        Calls the original Invoke-HardeningKitty engine only in Audit mode with the GPO collection source.
        Reconciles every baseline definition with the generated CSV, retaining missing and default-based evidence as unresolved.
        Preserves the initial full-list runs and rechecks valid comparisons affected by run-level collection errors by ID.
        These independent checks use the same Audit engine and unchanged lists; only clean observations resolve a verdict.
        This fork retains the unsigned upstream 0.9.5 Git engine; neither it nor these extensions are a signed release.
        Adds screen saver, password-policy and local-account checks. No security settings or passwords are changed.
        Descriptions explain each default baseline item; custom lists may supply a Description column.
        Import HardeningKitty.psd1. Machine and user audit execution is sequential in the current PowerShell session.
    .PARAMETER MachineFindingList
        Machine CSV baseline. Defaults to lists/finding_list_0x6d69636b_machine.csv.
    .PARAMETER UserFindingList
        Current-user CSV baseline. Defaults to lists/finding_list_0x6d69636b_user.csv. Does not scan other user hives.
    .PARAMETER ScreenSaverTimeoutSeconds
        Supplemental screen saver timeout upper bound, 1..86400 seconds. Default: 900.
    .PARAMETER MaximumPasswordAgeDays
        Supplemental maximum password age policy/elapsed-age limit, 1..999 days. Default: 365.
    .PARAMETER MinimumPasswordLength
        Supplemental minimum password length policy limit, 1..128 characters. Default: 14.
    .PARAMETER ReportFile
        Optional .html/.htm or .csv output. Existing files are never overwritten; the parent directory must exist.
        The same complete result objects are also returned to the pipeline. All report data is UTF-8.
        ValueOrigin distinguishes observed, default, unverified, unavailable and reference values; ReasonCode records the evidence reason.
        HTML labels collection provenance without changing raw Result values in objects or CSV.
        The offline HTML integrates review lanes, importance/verdict counts and Failed-only queues with expandable evidence for every row.
        Importance and ImportanceReason describe security significance, separately from RemediationPriority and PriorityReason.
        P1/P2/P3 indicate low-impact candidates, impact review and planned changes, not permission to remediate.
    .EXAMPLE
        Invoke-HardeningKittySecurityAudit -ReportFile .\security-report.html
    .EXAMPLE
        Invoke-HardeningKittySecurityAudit -MaximumPasswordAgeDays 90 -ScreenSaverTimeoutSeconds 600
    .NOTES
        Run 64-bit PowerShell on 64-bit Windows. Elevate as the intended user; HKCU belongs to the executing identity.
        Threshold parameters affect supplemental checks only, not the recommendations in the baseline lists.
        Default substitutions, language-dependent collectors and OS/product applicability require review.
        ID-level rechecks can take additional time. Each CheckedAt belongs to that row's collection, not one shared instant.
        Collection errors, default substitutions, ambiguous ASR evidence, missing rows and duplicates remain unresolved.
        Empty accesschk exports lack native export-success evidence and remain Unknown/Unverified (UnverifiedEmptyExport).
        Genuinely successful empty Get-MpPreference exclusions can be evaluated against the baseline.
        Online/domain password dates, Windows Hello PIN strength and actual network exposure are not proven.
        Temporary exports use private directories and are removed in finally. Dates rely on the host clock.
        No HailMary/GPO write mode, automatic policy changes, or blanket execution-policy bypass is used.
    #>
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String] $MachineFindingList = (Join-Path $PSScriptRoot 'lists\finding_list_0x6d69636b_machine.csv'),
        [ValidateNotNullOrEmpty()]
        [String] $UserFindingList = (Join-Path $PSScriptRoot 'lists\finding_list_0x6d69636b_user.csv'),
        [ValidateRange(1, 86400)]
        [Int] $ScreenSaverTimeoutSeconds = 900,
        [ValidateRange(1, 999)]
        [Int] $MaximumPasswordAgeDays = 365,
        [ValidateRange(1, 128)]
        [Int] $MinimumPasswordLength = 14,
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            If ([IO.Path]::GetExtension($_) -notin @('.csv', '.html', '.htm')) {
                Throw 'ReportFile must have a .html, .htm or .csv extension.'
            }
            $true
        })]
        [String] $ReportFile
    )

    If ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { Throw 'This audit requires Windows.' }
    If ($ReportFile) {
        $ReportFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReportFile)
        If (Test-Path -LiteralPath $ReportFile) { Throw "Report already exists: $ReportFile" }
        If (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($ReportFile)) -PathType Container)) {
            Throw "Report parent directory does not exist: $ReportFile"
        }
    }
    $Catalog = Get-SecurityAuditCatalog
    $Machine = Import-SecurityAuditList -Path $MachineFindingList
    $User = Import-SecurityAuditList -Path $UserFindingList
    $Now = [DateTimeOffset]::Now
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $UserTarget = "$($Identity.Name) [$($Identity.User.Value)]"
    $IsAdmin = ([Security.Principal.WindowsPrincipal]$Identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $Findings = New-Object 'System.Collections.Generic.List[object]'
    $ScopeDetails = "머신 기준: $($Machine.Name) ($($Machine.Findings.Count)개). 현재 사용자 기준: $($User.Name) ($($User.Findings.Count)개). 추가 화면 보호기·로컬 비밀번호 정책·계정 날짜 점검 포함. 관리자 권한: $IsAdmin. 원본 엔진 수집 소스: GPO."
    $Context = New-SecurityAuditFinding -ID 'CTX-01' -Scope 'Context' -Category 'Scope' -Name 'Audit scope' `
        -Description (Get-SupplementalAuditDescription -ID 'CTX-01') -Target $UserTarget -Result $env:COMPUTERNAME `
        -TestResult 'Info' -Source "Executing Windows identity; PowerShell $($PSVersionTable.PSVersion)" -Details $ScopeDetails
    $Context.CheckedAt = $Now.ToString('o')
    $Findings.Add($Context)

    Invoke-SecurityAuditBaseline -Definition $Machine -Scope 'Machine' -Target $env:COMPUTERNAME -Catalog $Catalog |
        ForEach-Object { $Findings.Add($_) }
    Invoke-SecurityAuditBaseline -Definition $User -Scope 'User' -Target $UserTarget -Catalog $Catalog |
        ForEach-Object { $Findings.Add($_) }
    Get-AccountAuditFinding -ScreenSaverTimeoutSeconds $ScreenSaverTimeoutSeconds -MaximumPasswordAgeDays $MaximumPasswordAgeDays -MinimumPasswordLength $MinimumPasswordLength |
        ForEach-Object { $Findings.Add($_) }

    # Re-evaluate metadata only after collectors have finalized status, provenance and account scope.
    $PriorityReference = Get-SecurityAuditPriorityReference
    ForEach ($Finding in $Findings) {
        Set-SecurityAuditPriority -Finding $Finding -Reference $PriorityReference | Out-Null
    }

    If ($ReportFile) {
        If ([IO.Path]::GetExtension($ReportFile) -in @('.html', '.htm')) {
            ConvertTo-SecurityAuditHtml -Findings $Findings.ToArray() |
                Out-File -LiteralPath $ReportFile -Encoding UTF8 -NoClobber -ErrorAction Stop
        } Else {
            $Findings | Export-Csv -LiteralPath $ReportFile -NoTypeInformation -Encoding UTF8 -NoClobber -ErrorAction Stop
        }
    }
    $Findings
}

Export-ModuleMember -Function Invoke-HardeningKittySecurityAudit
