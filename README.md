# HardeningKitty and Windows Hardening

## Introduction

The project started as a simple hardening list for Windows 10. After some time, HardeningKitty was created to simplify the hardening of Windows. Now, HardeningKitty supports guidelines from Microsoft, CIS Benchmarks, DoD STIG and BSI SiSyPHuS Win10. And of course my own hardening list.

This is a hardening checklist that can be used in private and business environments for hardening Windows 10. The checklist can be used for all Windows versions, but in Windows 10 Home the Group Policy Editor is not integrated and the adjustment must be done directly in the registry. For this, there is the _HailMary_ mode from _HardeningKitty_.

The settings should be seen as security and privacy recommendation and should be carefully checked whether they will affect the operation of your infrastructure or impact the usability of key functions. It is important to weigh security against usability.

The project started with the creation of a simple hardening checklist for Windows 10. The focus has shifted to the audit of various well-known frameworks / benchmarks with the development of _HardeningKitty_. Meanwhile, various CIS benchmarks and Microsoft Security Baselines are supported. With the development of the _HailMary_ mode, it will also be possible to apply settings of any hardening checklist on a Windows system.

## HardeningKitty

_HardeningKitty_ originates from the [Windows Hardening Project by Michael Schneider](https://github.com/0x6d69636b/windows_hardening). This fork retains the original **0.9.5** upstream Git module and adds a local, read-only **comprehensive security audit with explained HTML reporting**.

원본 `HardeningKitty.psm1`과 공식 점검 목록은 유지하고, `HardeningKitty.SecurityAudit.psm1`, 내부 수집 지원 파일 `HardeningKitty.BaselineAudit.ps1`, 중요도·조치 분류 파일 `HardeningKitty.PriorityAudit.ps1`, 보고서 표시 파일 `HardeningKitty.Report.ps1`, 항목 설명 `report-data/`를 추가했습니다. 기본 머신 **418개**와 현재 사용자 **56개** 기준 항목에 화면 보호기·비밀번호·계정 날짜 점검을 합칩니다. 이 Git 체크아웃의 원본 `HardeningKitty.psm1`은 **서명되지 않은 0.9.5 개발 코드**이며 추가 코드·설명 카탈로그·수정된 manifest도 서명된 릴리스가 아닙니다. `lists/`의 서명된 목록 manifest는 목록 무결성용이며 엔진이나 확장 코드의 서명을 뜻하지 않습니다. 공개 통합 명령은 `Invoke-HardeningKittySecurityAudit`이며 `HardeningKitty.psd1`을 가져와 사용합니다.

_HardeningKitty_ supports hardening of a Windows system. The configuration of the system is retrieved and assessed using a finding list. In addition, the system can be hardened according to predefined values. _HardeningKitty_ reads settings from the registry and uses other modules to read configurations outside the registry.

The script was developed for English systems. It is possible that in other languages the analysis is incorrect. Please create an issue if this occurs.

### Signed Version

The development of _HardeningKitty_ happens in this repository. In the [repository of scip AG](https://github.com/scipag/HardeningKitty) is a stable version of _HardeningKitty_ that has been *signed* with the code signing certificate of _scip AG_. This means that _HardeningKitty_ can also be run on systems that only allow signed scripts.

### How To Run

#### HTML 보고서 빠른 시작

Windows PowerShell **5.1 이상**에서 실행합니다. 64비트 Windows에서는 64비트 PowerShell을 사용하세요. 이 디렉터리를 작업 경로로 열고, 보안 정책 조회를 위해 **점검할 사용자와 동일한 계정으로 관리자 권한 실행**합니다. 다른 관리자 계정으로 실행하면 화면 보호기 점검 대상(HKCU)도 그 계정으로 바뀝니다.

```powershell
Import-Module .\HardeningKitty.psd1 -Force
$ReportPath = Join-Path $PWD ("system-security-{0}.html" -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$Results = Invoke-HardeningKittySecurityAudit -ReportFile $ReportPath
Start-Process -FilePath $ReportPath
```

보고서가 브라우저에서 열립니다. 시스템 설정이나 비밀번호는 변경하지 않으며, 기존 보고서는 덮어쓰지 않습니다. 브라우저 실행이 필요 없으면 마지막 줄을 생략하세요.

#### 명령별 용도

| 명령 | 용도 | 보고서 |
| :--- | :--- | :--- |
| `Invoke-HardeningKittySecurityAudit` | 머신·현재 사용자 기준 목록 + 화면 보호기·비밀번호·계정 보완 점검 통합 | 설명 포함 HTML/CSV: `-ReportFile`의 `.html` / `.htm` / `.csv`로 선택 |
| `Invoke-HardeningKitty` | 공식/사용자 정의 목록 기반 전체 보안 점검 및 하드닝 | `-Report`로 CSV 저장, `-Log`로 로그 저장 |

**계정 보안에 한정하지 않습니다.** 통합 명령은 원본 엔진을 `Audit` 모드로 실행하여 머신·현재 사용자 기준 목록 전체를 먼저 점검합니다. 실행 단위 수집 오류로 비교를 신뢰할 수 없었던 항목은 ID별로 독립 재점검한 뒤, 보완 점검과 함께 설명이 포함된 보고서를 생성합니다. 기존 `Invoke-HardeningKitty`에 `.html` 파일명만 지정하는 방식이 아니라 **통합 명령**을 사용하세요.

기존 머신 설정 점검은 다음과 같이 실행합니다. 사용자 설정 목록은 점검할 일반 사용자 계정으로 실행하는 것이 적절합니다.

```powershell
Invoke-HardeningKitty -Mode Audit -Log -Report
```

설정 변경을 원하지 않으면 `HailMary` / `GPO` 모드를 실행하지 마세요. 통합 명령은 변경 모드를 노출하지 않습니다. 상세 옵션은 [통합 보안 점검 사용법](#comprehensive-security-audit)을 참고하세요.

#### Native engine example

The sample output below is historical; this checkout uses native 0.9.5. Import `HardeningKitty.psd1` for both public commands; importing only `HardeningKitty.psm1` exposes only the native engine.

Run the script with administrative privileges to access machine settings. For the user settings it is better to execute them with a normal user account. Ideally, the user account is used for daily work.

Download _HardeningKitty_ and copy it to the target system (script and lists). Then HardeningKitty can be imported and executed:

```text
PS C:\tmp> Import-Module .\HardeningKitty.psm1
PS C:\tmp> Invoke-HardeningKitty -EmojiSupport


         =^._.^=
        _(      )/  HardeningKitty 0.9.0-1662273740


[*] 9/4/2022 8:54:12 AM - Starting HardeningKitty


[*] 9/4/2022 8:54:12 AM - Getting user information
[*] Hostname: DESKTOP-DG83TOD
[*] Domain: WORKGROUP

...

[*] [*] 9/4/2022 8:54:12 AM - Starting Category Account Policies
[😺] ID 1103, Store passwords using reversible encryption, Result=0, Severity=Passed
[😺] ID 1100, Account lockout threshold, Result=10, Severity=Passed
[😺] ID 1101, Account lockout duration, Result=30, Severity=Passed

...

[*] 9/4/2022 8:54:12 AM - Starting Category User Rights Assignment
[😿] ID 1200, Access this computer from the network, Result=BUILTIN\Administrators;BUILTIN\Users, Recommended=BUILTIN\Administrators, Severity=Medium

...

[*] 9/4/2022 8:54:14 AM - Starting Category Administrative Templates: Printer
[🙀] ID 1764, Point and Print Restrictions: When installing drivers for a new connection (CVE-2021-34527), Result=1, Recommended=0, Severity=High
[🙀] ID 1765, Point and Print Restrictions: When updating drivers for an existing connection (CVE-2021-34527), Result=2, Recommended=0, Severity=High

...

[*] 9/4/2022 8:54:19 AM - Starting Category MS Security Guide
[😿] ID 2200, LSA Protection, Result=, Recommended=1, Severity=Medium
[😼] ID 2201, Lsass.exe audit mode, Result=, Recommended=8, Severity=Low

...

[*] 9/4/2022 8:54:25 AM - HardeningKitty is done
[*] 9/4/2022 8:54:25 AM - Your HardeningKitty score is: 4.82. HardeningKitty Statistics: Total checks: 325 - Passed: 213, Low: 33, Medium: 76, High: 3.
```

### How To Install

First create the directory *HardeningKitty* and for every version a sub directory like *0.9.5* in a path listed in the *PSModulePath* environment variable.

Copy *HardeningKitty.psm1*, *HardeningKitty.SecurityAudit.psm1*, *HardeningKitty.BaselineAudit.ps1*, *HardeningKitty.PriorityAudit.ps1*, *HardeningKitty.Report.ps1*, *HardeningKitty.psd1*, and both the *lists* and *report-data* directories to this new directory.

```powershell
PS C:\tmp> $Version = "0.9.5"
PS C:\tmp> New-Item -Path $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version -ItemType Directory
PS C:\tmp> Copy-Item -Path .\HardeningKitty.psd1,.\HardeningKitty.psm1,.\HardeningKitty.SecurityAudit.psm1,.\HardeningKitty.BaselineAudit.ps1,.\HardeningKitty.PriorityAudit.ps1,.\HardeningKitty.Report.ps1,.\lists\,.\report-data\ -Destination $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\ -Recurse
```

For more information see Microsoft's article [Installing a PowerShell Module](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module).

### How to Automatically Download and Install the Latest Release

You can use the script below to download and install the latest release of *HardeningKitty*.

This downloads the upstream release, not this fork's comprehensive audit extensions. To retain the audit and item explanations, install this checkout's manifest, both modules, all three support scripts, `lists/` and `report-data/` together as described above. The signed stable release linked above is separate from this unsigned Git checkout; review and follow your organization's script-signing policy rather than treating the list signature as code-signing approval.

```powershell
Function InstallHardeningKitty() {
    $Version = (((Invoke-WebRequest "https://api.github.com/repos/0x6d69636b/windows_hardening/releases/latest" -UseBasicParsing) | ConvertFrom-Json).Name).SubString(2)
    $HardeningKittyLatestVersionDownloadLink = ((Invoke-WebRequest "https://api.github.com/repos/0x6d69636b/windows_hardening/releases/latest" -UseBasicParsing) | ConvertFrom-Json).zipball_url
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest $HardeningKittyLatestVersionDownloadLink -Out HardeningKitty$Version.zip
    Expand-Archive -Path ".\HardeningKitty$Version.zip" -Destination ".\HardeningKitty$Version" -Force
    $Folder = Get-ChildItem .\HardeningKitty$Version | Select-Object Name -ExpandProperty Name
    Move-Item ".\HardeningKitty$Version\$Folder\*" ".\HardeningKitty$Version\"
    Remove-Item ".\HardeningKitty$Version\$Folder\"
    New-Item -Path $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version -ItemType Directory
    Set-Location .\HardeningKitty$Version
    Copy-Item -Path .\HardeningKitty.psd1,.\HardeningKitty.psm1,.\lists\ -Destination $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\ -Recurse
    Import-Module "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\HardeningKitty.psm1"
}
InstallHardeningKitty
```

### Examples

#### Audit

The default mode is _audit_. With `-Report` and `-Log`, HardeningKitty saves the results to a CSV file and creates a log file. The files are automatically named and receive a timestamp. Using the parameters _ReportFile_ or _LogFile_, it is also possible to assign your own name and path.

The _Filter_ parameter can be used to filter the hardening list. For this purpose the PowerShell ScriptBlock syntax must be used, for example `{ $_.ID -eq 4505 }`. The following elements are useful for filtering: ID, Category, Name, Method, and Severity.

```powershell
Invoke-HardeningKitty -Mode Audit -Log -Report
```

HardeningKitty can be executed with a specific list defined by the parameter _FileFindingList_. If HardeningKitty is run several times on the same system, it may be useful to hide the machine information. The parameter _SkipMachineInformation_ is used for this purpose.

```powershell
Invoke-HardeningKitty -FileFindingList .\lists\finding_list_0x6d69636b_user.csv -SkipMachineInformation
```

HardeningKitty uses the default list, and checks only tests with the severity Medium.

```powershell
Invoke-HardeningKitty -Filter { $_.Severity -eq "Medium" }
```

#### Comprehensive security audit

`Invoke-HardeningKittySecurityAudit`은 머신과 현재 사용자 기준 목록 전체 및 보완 항목을 읽기 전용으로 점검합니다. 원본 모듈만 직접 가져오면 이 명령이 없으므로 **manifest인 `HardeningKitty.psd1`을 가져와야 합니다**.

##### 점검 항목

| 분류 / ID | 점검 내용 | 조회 방식 |
| :--- | :--- | :--- |
| 범위 / `CTX-01` | 실행 컴퓨터·사용자·SID | 실행 중인 Windows 계정 |
| 머신 기준 / `Machine` | Windows 방화벽, Defender·ASR, 감사 정책, 사용자 권한, 네트워크·원격 접속, BitLocker, 서비스, 악용 방지 등 418개 | 원본 엔진의 머신 목록 Audit |
| 사용자 기준 / `User` | 사용자 정책, PowerShell 로깅, Office 매크로·연결 기능, Windows 사용자 설정 등 56개 | 원본 엔진의 사용자 목록 Audit |
| 실행 진단 / `ENGINE-Machine`, `ENGINE-User` | 예정·반환·누락·중복 수와 원본 진단 메시지 | 원본 CSV와 기준 목록 대조 |
| 화면 보호기 / `SS-01`~`SS-04` | 활성화, 복귀 시 암호 보호, 대기시간, 설정된 `.scr` 파일 존재 여부 | 현재 사용자 HKCU 정책·사용자 설정 |
| 비밀번호 정책 / `PP-01`~`PP-06` | 복잡도, 최소 길이, 최대·최소 사용 기간, 재사용 제한, 복호화 가능한 암호화 저장 | 로컬 SAM `NetUserModalsGet` 및 `secedit /export /mergedpolicy` |
| 로컬 계정 / `LA-01`~`LA-05` | 최근 변경일, 경과일, 만료일, 무기한 사용, 비밀번호 필수 여부 | `Get-LocalUser`, SID로 매칭한 `Win32_UserAccount` |
| 조회 오류 / `LA-00` | 계정 목록을 읽지 못한 이유 | 계정 조회 예외 |

화면 보호기는 **정책 값이 사용자 설정보다 우선**하며, 명시적으로 꺼진 값도 그대로 반영합니다. 실제 화면 보호기를 실행하거나 화면 잠금 동작을 검증하지는 않습니다. 비밀번호 자체나 해시는 수집하지 않습니다.

보고서에는 모든 기본 기준 항목의 **무엇을 점검하는지와 보안상 의미**를 한국어로 설명합니다. 원본 항목명은 유지하며, 실제 레지스트리 경로·명령·속성과 비교 연산자를 함께 표시합니다. 머신과 사용자에서 ID가 같아도 `Scope`와 `List`로 구분하므로 서로 덮어쓰지 않습니다.

##### 실행 옵션

| 매개변수 | 기본값 | 허용 범위 / 의미 |
| :--- | :--- | :--- |
| `-MachineFindingList` | `lists/finding_list_0x6d69636b_machine.csv` | 사용할 머신 기준 CSV |
| `-UserFindingList` | `lists/finding_list_0x6d69636b_user.csv` | 사용할 현재 사용자 기준 CSV |
| `-ScreenSaverTimeoutSeconds` | `900` | `1`~`86400`초. 화면 보호기 대기시간 상한 |
| `-MaximumPasswordAgeDays` | `365` | `1`~`999`일. 최대 사용 기간 정책의 상한 및 계정 비밀번호 경과일 기준 |
| `-MinimumPasswordLength` | `14` | `1`~`128`자. 최소 길이 정책의 하한 |
| `-ReportFile` | 지정하지 않음 | `.html` / `.htm`: HTML, `.csv`: CSV. 다른 확장자는 거부 |

기간·길이·대기시간 옵션은 **Supplemental 보완 항목에만 적용**하며 원본 기준 목록의 권장값을 바꾸지 않습니다. 보완 항목은 최소 사용 기간 **1일 이상**, 재사용 제한 **24개**, 복잡도 **활성화**, 복호화 가능한 암호화 저장 **비활성화**도 점검합니다. 이 기준들은 옵션으로 변경하지 않습니다. 최대 사용 기간 정책은 지정한 상한 **이하**여야 하고, 계정 경과일은 그 한계에 **도달하면** 개선 필요로 판정합니다.

비밀번호 정책의 기본 기준은 포함된 CIS Windows 11 24H2 목록을 따릅니다. 이는 **평가 기준이며 Windows에 적용하는 설정이 아닙니다**. 정기 변경이 모든 환경에 필요한 것은 아니므로 조직 정책에 맞게 사용하세요.

조직 기준이 90일·10분·14자일 때의 HTML 보고서 예시:

```powershell
Import-Module .\HardeningKitty.psd1 -Force
$ReportPath = Join-Path $PWD ("system-security-{0}.html" -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$Results = Invoke-HardeningKittySecurityAudit `
    -MaximumPasswordAgeDays 90 `
    -ScreenSaverTimeoutSeconds 600 `
    -MinimumPasswordLength 14 `
    -ReportFile $ReportPath
$Results | Format-Table Scope, ID, Name, TestResult, Importance, RemediationPriority -AutoSize
```

##### HTML·CSV 보고서

HTML은 **종합 검토 → 중요도별 판정 현황 → 조치·재확인 작업 → 전체 결과 → 해석 기준** 순서입니다. 중요도와 우선순위를 따로 나열하는 대신 어떤 항목을 조치 검토할지, 어떤 근거를 더 확인할지 먼저 구분합니다. 안전 점수나 준수율을 임의로 만들지 않습니다. 컴퓨터·사용자·점검 시작 시각·범위와 여섯 가지 판정은 그대로 제공합니다.

| 종합 검토 그룹 | 포함 결과 | 읽는 방법 |
| :--- | :--- | :--- |
| 조치 검토 | 실제 관측된 `Failed` 중 `P1`·`P2`·`P3` | 우선순위별로 보고, 같은 순위에서는 보안 중요도 높은 항목부터 확인 |
| 근거·적용성 재확인 | `Unknown`·`Error` 및 `Review`로 분류된 `Failed` | 목록 기본값 대체·수집 오류·적용 대상·기준 방향 등을 확인. 곧바로 설정 변경하지 않음 |
| 현재 추가 조치 없음 | `Passed`·`Info`·`NotApplicable` | 통과와 참고·대상 아님을 구분. 그룹 전체가 보안 통과라는 뜻이 아님 |

세 그룹은 중복 없이 전체 결과를 포함합니다. **높은 중요도 미해결 수**는 `High` 중 `Failed`·`Unknown`·`Error`인 부분집합이며, 전체 High 개수나 확인된 취약점 수와 다릅니다. 중요도별 판정 표는 개선 필요, 미확인·오류, 통과, 참고·대상 아님을 함께 보여 줍니다. 재확인 작업은 사유별로 집계하여 기본값 대체와 실제 조회 실패를 구분합니다. 검토 그룹은 표시용이며 객체·CSV의 기존 분류를 바꾸지 않습니다.

전체 결과는 **간결한 요약 행 + 펼쳐 보는 상세 근거** 구조입니다. 요약에는 범위·ID·이름·분류와 판정·중요도·우선순위가 표시됩니다. 동일 범위·ID가 반복되는 계정별 결과는 요약에도 대상을 표시하여 구분합니다. 바로가기는 항상 보이는 항목 요약으로 이동하며, 요약을 클릭하거나 키보드로 선택 후 Enter/Space를 눌러 펼칠 수 있습니다. ID·항목명은 브라우저 찾기 기능으로 찾을 수 있습니다. 상세에서는 전체 값·판정 기준·설명·대상·조치 근거와 원본 판정·기본값 대체·출처·사유·시각을 확인합니다. 긴 수집 진단은 추가로 펼쳐 읽으며 원문을 생략하지 않습니다.

**외부 리소스나 JavaScript 없이 오프라인에서 열람**할 수 있습니다. 최신 Chromium/Edge의 인쇄/PDF 저장에서는 화면에서 접힌 항목과 중첩된 수집 근거까지 표시하며, 긴 진단은 여러 페이지로 이어집니다. 중복되는 빠른 작업 목록·탐색만 생략하고 재확인 사유별 요약·전체 결과·해석 기준은 유지합니다. 좁은 화면에서는 항목별 카드 형태로 읽을 수 있습니다. 개별 점검명과 원본 진단 메시지는 영문일 수 있습니다.

보고서는 필요한 ID별 재점검까지 마친 뒤 반환되는 PowerShell 객체와 **동일한 결과 스냅샷**으로 생성됩니다. HTML·CSV 출력 자체가 추가 조회를 실행하지는 않습니다. 수집값과 사유 코드는 HTML 이스케이프 처리하므로 계정명이나 설정값에 포함된 태그가 실행되지 않습니다. 수집값에는 수집 구분을 함께 표시합니다. 누락값은 `—`, 실제 조회된 빈 문자열은 `(빈 값)`으로 표시하며, `0`과 `False`는 기본값 대체 여부와 무관하게 그대로 표시합니다. **객체와 CSV의 `Result` 원본 값은 표시용 문구로 바꾸지 않습니다.**

위 실행 결과를 **재조회 없이** CSV로도 저장하려면:

```powershell
$CsvPath = [IO.Path]::ChangeExtension($ReportPath, '.csv')
$Results | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8 -NoClobber
```

CSV만 필요한 새 점검에서는 `-ReportFile .\system-security.csv`처럼 지정합니다. `-ReportFile`을 생략하면 통합 객체만 반환하고 최종 보고서는 저장하지 않습니다.

공통 결과 필드는 `ID`, `Scope`, `List`, `Category`, `Name`, `Description`, `Target`, `Result`, `Recommended`, `TestResult`, `Source`, `Details`, `Severity`, `EngineTestResult`, `UsedDefault`, `ValueOrigin`, `ReasonCode`, `CheckedAt`, `Importance`, `ImportanceReason`, `RemediationPriority`, `PriorityReason`입니다. `EngineTestResult`는 해당 행을 수집한 원본 엔진의 판정, `UsedDefault`는 원본의 기본값 대체 플래그입니다. 보완 항목처럼 원본 엔진 결과가 아닌 항목에서는 두 필드가 비어 있습니다. `CheckedAt`은 각 행의 수집 시각이며 ID별 재점검 행에는 새 수집 시각이 기록됩니다. 모든 행이 한 시점의 상태를 뜻하지는 않으며 보고서 머리말은 `CTX-01`의 점검 시작 시각을 사용합니다.

`ValueOrigin`은 판정과 별개인 **값의 수집 구분**이며 HTML의 값 옆에도 다음 문구로 표시합니다. ‘실제 조회’는 관측했다는 뜻이지 기준을 충족했다는 뜻은 아닙니다.

| `ValueOrigin` | HTML 표시 | 의미 |
| :--- | :--- | :--- |
| `Observed` | 실제 조회 | 해당 수집에서 확인된 값. 실제 조회된 빈 문자열도 포함 |
| `Default` | 목록 기본값 · 미조회 | 조회값 대신 기준 목록의 기본값을 사용. 현재 설정으로 단정 금지 |
| `Unverified` | 조회 확인 안 됨 | 값이 있어도 수집 오류·불명확한 근거 등으로 조회를 확인하지 못함 |
| `Unavailable` | 값 없음 | 판단에 사용할 수집값이 없음 |
| `Reference` | 참고 정보 | 범위·실행 진단 등 설정값이 아닌 참고 자료 |

`ReasonCode`는 근거를 구분하는 짧은 코드입니다. 예를 들어 `DefaultSubstitution`은 목록 기본값 대체, `CollectionError`는 수집 오류로 비교를 신뢰할 수 없는 상태, `UnverifiedEmptyExport`는 성공 여부를 확인할 수 없는 빈 권한 내보내기를 뜻합니다. 누락·중복·유효하지 않은 근거도 구분하며, 보완·범위 항목에서는 별도 코드가 없으면 빈 문자열입니다. 자세한 이유는 `Details`와 함께 확인하세요. HTML의 상세 근거 마지막에도 사유 코드를 표시합니다.

HTML과 CSV는 UTF-8로 저장하며 기존 파일을 덮어쓰지 않습니다. 기존에 저장한 보고서가 자동으로 다시 작성되는 것은 아닙니다. 새 동작의 결과는 새 파일명으로 점검하여 저장하세요.

##### 보안 중요도와 조치 우선순위

**보안 중요도는 통제의 의미이며, 조치 우선순위는 빠르게 변경할 수 있는지와 운영 영향을 구분한 안내입니다.** 높은 중요도의 항목이 3순위 또는 재확인일 수 있습니다. 중요도와 우선순위가 원본 판정·실측값을 바꾸거나 설정 변경을 실행하지는 않습니다.

| `Importance` | 표시 | 정의 |
| :--- | :--- | :--- |
| `High` | 높음 | 접근·인증·자격증명·데이터 보호 등 직접적인 보안 통제 |
| `Medium` | 보통 | 방어 계층·탐지·감사·정책 운영을 보완하는 통제 |
| `Low` | 낮음 | 편의 기능·정보 노출 축소 등 보조 통제 |
| `Unrated` | 미분류 | 지원되는 중요도 근거가 없어 추정하지 않음. 낮음과 다름 |
| `Reference` | 참고 | 점검 범위·실행 진단·날짜 정보 등 보안 등급을 부여하지 않는 기록 |

머신·사용자 목록은 원본 `Severity`의 정확한 `High` / `Medium` / `Low`를 표준화해 표시합니다. 이는 **목록 작성자의 분류**이며 현재 호스트의 실제 침해 가능성을 재계산한 점수가 아닙니다. 원본 값은 `Severity`에 그대로 보존합니다. 보완 항목은 화면 잠금 인증·암호 강도·복구 가능한 암호 저장·암호 필수 플래그 등을 높음, 기간·기록·예외 및 운영 보완 통제를 보통으로 별도 정의합니다. 행별 근거는 `ImportanceReason`에 기록합니다.

| `RemediationPriority` | 표시 | 정의 및 예 |
| :--- | :--- | :--- |
| `P1` | 1순위 · 낮은 영향 후보 | 로그 용량, 일부 감사·차단 기록, Windows 팁 설정. 공간·운영 조건 확인은 필요하며 무위험을 뜻하지 않음 |
| `P2` | 2순위 · 영향 확인 후 | 로그량, 로그인·권한 요청, 암호 변경, 장치 공유·Xbox·WebClient 사용 여부 확인 |
| `P3` | 3순위 · 계획 변경 | SMB·인증·인쇄·암호화·PowerShell 정책 등. 호환성 테스트와 복구 준비 필요. 낮은 보안 중요도를 뜻하지 않음 |
| `Review` | 재확인 | 수집 실패·기본값 대체·적용 대상·유효 설정·변경 영향이 불명확하여 일괄 변경 제외 |
| `None` | 현재 조치 없음 | 통과·참고·대상 아님. 참고나 대상 아님을 보안 통과로 간주하지 않음 |

`P1`~`P3`는 **실제 관측된 Failed 행에만** 부여합니다. `Unknown`·`Error`는 중요도와 관계없이 재확인입니다. `NOTSET` 완화 기능은 Windows 기본값 사용으로 실제 보호 상태를 확인해야 하며, Defender 상태는 활성 백신과 적용 대상 확인 전까지 일괄 변경에서 제외합니다. 서비스가 현재 중지되어 있다고 미사용으로 단정하지 않습니다.

**AutoPlay 기준 방향 주의:** 기본 사용자 목록의 `4505`는 `DisableAutoplay = 0`을 요구합니다. 이를 “자동재생 해제”라고 안내하면 반대 방향으로 변경할 수 있으므로 Failed여도 `Review`로 분류합니다. 원본 목록·권장값·판정은 보존하며, 기준 의도와 유효 설정부터 확인해야 합니다.

기본 목록의 분류는 `Scope`, `ID`, `List`, `Name`, `Source`, `Recommended`가 참조 정의와 정확히 일치할 때만 연결합니다. 사용자 정의·이름/조회 대상/기준이 달라진 항목 또는 명시된 영향 분류가 없는 항목은 `Review`로 남기며 ID나 원본 중요도만으로 저위험 변경을 추정하지 않습니다. 구체적인 영향과 확인 사항은 `PriorityReason`에 기록합니다.

HTML의 중요도·전체 우선순위 집계는 **모든 결과 행** 기준입니다. 빠른 조치 작업 목록은 **Failed만** 우선순위별로 묶지만, 재확인 작업 요약과 전체 결과에는 **Unknown·Error도 빠짐없이 포함**합니다. 따라서 재확인 전체 집계와 Failed만 표시한 검토 목록의 수는 다릅니다. 중복된 서비스 점검이나 계정별 행 때문에 행 수는 독립 변경 작업 수와 같지 않습니다. 우선순위와 판정·수집 구분이 서로 모순되는 입력은 임의로 보정하거나 저위험 조치로 표시하지 않고 보고서 생성 오류로 알립니다.

##### 항목 설명과 사용자 정의 기준

`report-data/`의 JSON 설명 카탈로그는 기본 머신·사용자 474개 항목에 대한 로컬 작성 설명입니다. 원본 목록의 서명이나 공급자 공식 설명으로 간주하지 않습니다. 설명은 `Scope`·`ID`·정확한 `Name`을 확인하여 연결합니다.

다른 기준 목록은 `-MachineFindingList` / `-UserFindingList`로 지정합니다. 사용자 정의 CSV에 `Description` 열을 추가하면 해당 내용을 우선 사용합니다. 카탈로그와 일치하지 않고 설명 열도 없는 항목은 **조회 정보 기반의 일반 설명임을 명시**하며 보안 목적을 임의로 만들어 내지 않습니다. 원본 목록을 수정하지 말고 별도 사용자 정의 CSV를 만드세요.

##### 판정 해석

| `TestResult` | 보고서 표시 | 의미 |
| :--- | :--- | :--- |
| `Passed` | 통과 | 해당 점검값이 실행 기준을 충족 |
| `Failed` | 개선 필요 | 해당 점검값이 실행 기준을 미충족 |
| `Unknown` | 확인 필요 | 값 누락·형식 불명·권위 있는 자료 부족으로 판정 불가 |
| `Error` | 조회 오류 | 점검 자료 조회 중 오류 발생 |
| `Info` | 참고 | 범위·날짜 등 참고 자료이며 적합 판정이 아님 |
| `NotApplicable` | 대상 아님 | 비활성 계정 등 평가 제외 항목. 조회된 정보는 유지 |

`Unknown` / `Error`는 통과로 간주하지 않습니다. `Info` / `NotApplicable`도 통과 수에 합산하지 않으며, 원본 HardeningKitty의 점수 공식을 이 보고서에 적용하지 않습니다.

원본 엔진이 기본값으로 대체한 항목은 원본 판정과 관계없이 통합 보고서에서 `Unknown`으로 표시합니다. 원본 CSV에 빠진 예정 항목이나 중복 결과는 `Error`로 남깁니다. 숫자가 필요한데 비어 있거나 형식이 잘못된 결과, 수동 확인 표시값, 실제 규칙과 구분되지 않는 ASR 기본값도 통과로 간주하지 않습니다. 따라서 원본 CSV의 통과 수와 통합 보고서의 통과 수가 다를 수 있습니다.

**최초 머신·사용자 전체 목록 점검은 유지합니다.** 원본 엔진이 실행 단위 수집 오류를 보고하여 유효한 비교값의 신뢰 여부를 개별 ID에 연결할 수 없으면, 해당 항목을 **같은 원본 엔진의 `Audit` 모드로 ID별 독립 재조회**합니다. 다른 점검의 오류만으로 정상 값을 계속 `Unknown`으로 남기지 않고, 오류 없이 단일 항목의 조회값과 비교를 확인한 경우에만 `Passed` / `Failed`로 판정합니다. 재조회에서도 수집 오류·기본값 대체·ASR 모호성·결과 누락·중복이 있으면 미해결 상태로 남깁니다. 원본 CSV의 `Failed`·`High` 행과 정확히 일치하는 판정 메시지는 기준 미충족 결과이지 수집 오류가 아닙니다.

**빈 결과도 출처에 따라 구분합니다.** 정상 조회가 확인된 `Get-MpPreference`의 빈 Defender 제외 목록은 원본 기준에 따라 통과할 수 있으며 `(빈 값)`·‘실제 조회’로 표시합니다. 반면 원본 `accesschk` 수집기는 `secedit`의 네이티브 종료 코드를 확인하지 않아 미리 만든 빈 파일과 성공한 빈 권한 내보내기를 구분할 수 없습니다. 내보내기 성공 근거가 없는 빈 `accesschk` 값은 오류가 없는 단일 항목 실행에서도 `Unknown` / `Unverified`, 사유 코드 `UnverifiedEmptyExport`로 남깁니다. 이를 ‘권한 없음’ 또는 통과로 해석하지 마세요.

재점검도 **동일한 전체 기준 목록을 수정하지 않고 ID로 선택**하여 수행하며 보안 정책을 변경하지 않습니다. 독립 호출 때문에 실행 시간이 더 걸릴 수 있습니다. `EngineTestResult`, `UsedDefault`, `ValueOrigin`, `ReasonCode`, `Details`와 `ENGINE-Machine` / `ENGINE-User` 진단 내용을 함께 확인하세요.

##### 범위와 제한 사항

- **기준 목록 전체이지 모든 위협은 아님:** OS 버전·제품 설치 여부·업무 환경에 따른 적용 가능성을 자동 확정하지 않습니다. 없는 제품의 기본값 추정이나 미조회 결과를 자동으로 적용 제외하지 않습니다.
- **원본 엔진 제약 유지:** 원본을 `-Mode Audit -Source GPO`로 순차 실행합니다. 여기서 `Source GPO`는 조회 소스이며 GPO를 만드는 모드가 아닙니다. Intune 전용 감사나 모든 사용자 프로필 점검은 지원하지 않습니다. 언어 의존 수집기와 숨겨진 기본값 처리 한계는 원본에 남아 있습니다.
- **조회 범위와 동작 검증 구분:** 방화벽 규칙은 `Enabled`, 서비스는 `StartType` 등을 조회합니다. 실제 포트 차단·서비스 실행 여부·공격 방어 성공까지 검증한 것으로 해석하지 마세요.
- **현재 실행 사용자만 점검:** 화면 보호기의 HKCU는 대화형 데스크톱 사용자와 다를 수 있습니다. `CTX-01`의 사용자와 SID를 확인하세요. 다른 사용자 프로필의 레지스트리를 로드하지 않습니다.
- **정책과 실제 암호는 별개:** 복잡도 정책이 켜져 있어도 기존 비밀번호가 그 기준을 충족하는지 증명하지 않습니다. Windows Hello PIN은 점검 대상이 아닙니다.
- **미구성 정책:** 일부 Windows는 `secedit` 내보내기에 복잡도·복호화 가능 암호화 저장 값을 포함하지 않습니다. 이를 활성화/비활성화로 추정하지 않고 `Unknown`으로 표시합니다. SAM의 길이·기간·이력 조회는 독립적으로 수행합니다.
- **온라인·도메인 계정:** Microsoft 계정·Entra ID·도메인 계정의 실제 변경일과 정책은 인증 공급자에서 확인해야 합니다. 로컬 SAM 기록이 있어도 권위 있는 온라인 기록으로 간주하지 않습니다.
- **누락된 날짜:** 최근 변경일이 없다고 빈 비밀번호나 변경 이력 없음으로 단정하지 않습니다. 만료일이 없다고 무기한 사용 플래그를 추정하지도 않습니다.
- **시간 기준:** 날짜는 기록된 시간대 오프셋을 유지합니다. 각 행의 `CheckedAt`은 해당 수집 시각이며, 독립 재점검은 최초 전체 목록 점검과 다른 시각일 수 있습니다. 경과일은 호스트 시계 기준이며 인증된 사건 발생 시각이 아닙니다.
- **파일 및 보안:** 임시 정책 내보내기는 접근 제한 디렉터리에 생성하고 성공·실패 시 정리합니다. 보고서에는 사용자 식별자와 보안 설정이 있으므로 접근을 제한해 보관하세요.

##### 문제 해결

| 증상 | 확인할 사항 |
| :--- | :--- |
| `Invoke-HardeningKittySecurityAudit`을 찾지 못함 | 설치 항목의 파일·디렉터리를 모두 함께 두고 새 PowerShell에서 manifest 가져오기 |
| 설명 카탈로그를 읽지 못함 | `report-data/`의 JSON 파일들이 모듈과 함께 배포되었는지 확인 |
| `Get-LocalUser` 사용 불가 | 64비트 Windows에서 64비트 PowerShell인지 확인 |
| `secedit` 접근 거부 / 내보내기 실패 | 점검할 사용자와 동일한 계정으로 관리자 권한 실행 |
| 복잡도 또는 화면 보호기가 `Unknown` | `Source`·`Details`를 확인하고 로컬 보안 정책/관리 정책 또는 해당 사용자의 설정에서 확인. 통과나 비활성화로 단정 금지 |
| 보고서 파일이 이미 존재함 | 새 파일명 또는 타임스탬프 파일명 사용. 기존 결과는 보존 |
| 보고서 저장 경로 오류 | 상위 폴더 존재 여부와 쓰기 권한 확인. 상위 폴더는 자동 생성하지 않음 |

##### 회귀 테스트

Windows PowerShell 5.1 / Pester 3.4.0 환경에서 다음과 같이 실행합니다.

```powershell
$TestResults = Invoke-Pester .\tests -PassThru
if ($TestResults.FailedCount -gt 0) { throw 'Security audit regression tests failed.' }
```

테스트는 전체 기준 목록과 설명의 대응, 결과 누락·중복·기본값 대체 처리, 읽기 전용 엔진 호출, 정책·날짜 경계값, 클라우드·비활성 계정 구분, 임시 파일 정리, HTML 설명·집계·인젝션 방지·UTF-8 출력, CSV 출력과 기존 보고서 보호를 검증합니다.

#### Config

The mode _config_ retrives all current settings of a system. If a setting has not been configured, HardeningKitty will use a default value stored in the finding list. This mode can be combined with other functions, for example to create a backup.

HardeningKitty gets the current settings and stores them in a report:

```powershell
Invoke-HardeningKitty -Mode Config -Report -ReportFile C:\tmp\my_hardeningkitty_report.csv
```

#### Backup

Backups are important. Really important. Therefore, HardeningKitty also has a function to retrieve the current configuration and save it in a form that can be partially restored.

**Disclaimer:** HardeningKitty tries to restore the original configuration. This works quite well with registry keys and Hardening Kitty really tries its best. But the backup function is not a snapshot and does not replace a real system backup. It is not possible to restore the system 1:1 with HardeningKitty alone after HailMary. If this is a requirement, create an image or system backup and restore it.

The _Backup_ switch specifies that the file is written in form of a finding list and can thus be used for the _HailMary_ mode. The name and path of the backup can be specified with the parameter _BackupFile_.

```powershell
Invoke-HardeningKitty -Mode Config -Backup
```

Please test this function to see if it really works properly on the target system before making any serious changes. A Schrödinger's backup is dangerous.

##### Non-Default Finding List

Note that if _-FileFindingList_ is not specified, the backup is referred to the default finding list. Before deploying a _specific_ list in _HailMary_ mode, always create a backup _referred to that specific list_.

```powershell
Invoke-HardeningKitty -Mode Config -Backup -BackupFile ".\myBackup.csv" -FileFindingList ".\list\{list}.csv"
```

##### Restoring a Backup

The _Backup_ switch creates a file in form of a finding list, to restore the backup load it in _HailMary_ mode like any find list:

```powershell
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList ".\myBackup.csv"
```

#### HailMary

The _HailMary_ method is very powerful. It can be used to deploy a finding list on a system. All findings are set on this system as recommended in the list. With power comes responsibility. Please use this mode only if you know what you are doing. Be sure to have a backup of the system.

For now, the filter function is only supported in Audit and Config mode. As the HailMary mode is a delicate matter, create your own file and remove all the lines you want to filter.

```powershell
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\lists\finding_list_0x6d69636b_machine.csv
```

Before HailMary is run, a finding list must be picked. It is important to check whether the settings have an influence on the stability and functionality of the system. Before running HailMary, a backup should be made.

#### Create a Group Policy (experimental)

Thanks to [@gderybel](https://github.com/gderybel), HardeningKitty can convert a finding list into a group policy. As a basic requirement, the Group Policy Management PowerShell module must be installed. At the moment only registry settings can be converted and not everything has been tested yet. A new policy is created, as long as it is not assigned to an object, no change is made to the system. Use it with care.

```powershell
Invoke-HardeningKitty -Mode GPO -FileFindingList .\lists\finding_list_0x6d69636b_machine.csv -GPOName HardeningKitty-Machine-01
```

### Finding List Integrity

In the write modes (_HailMary_ and _GPO_) the finding list fully controls what is applied to the system. To ensure that a list has not been tampered with en route to the operator (e.g. poisoned repository, shared baseline, downloaded or emailed 'run this list'), HardeningKitty can verify that a list is the authentic and unaltered from that published by the maintainer.

The official lists are attested by a signed manifest shipped in the `lists\` directory:

* `lists\hardeningkitty_lists_manifest.psd1` - a readable file mapping each official list to its SHA-256 hash
* `lists\hardeningkitty_lists_manifest.psd1.p7s` - a detached signature over that manifest, created with the maintainer certificate

At runtime, HardeningKitty verifies the detached signature and checks that the signer's certificate matches the thumbprint pinned in the module (`$HardeningKittyListSigningThumbprint`). It also compares the hash of the loaded list against the manifest. A list whose hash is in the signed manifest is **official / verified**. Any other list is **custom / unverified**. This is provenance, not an allow-list - custom lists are fully supported.

Behaviour by mode:

* **Audit / Config** (read-only): the verification result is shown as information only. Custom lists run without restriction
* **HailMary / GPO** (write): a verified official list runs normally. A custom or modified list will be **refused** unless the risk is explicitly accepted with the `-AllowCustomList` switch

```powershell
# Apply your own (unverified) list in HailMary - accept the risk
Invoke-HardeningKitty -Mode HailMary -FileFindingList .\my_custom_list.csv -AllowCustomList
```

Note that verification only confirms that a list has not been altered by the publisher. It cannot guarantee that the settings in a list are safe. It also does not protect against a malicious administrator - someone with administrator privileges can change the system directly. However, it does protect the honest operator against running a tampered or incorrect list.

#### Running Your Own Lists

Building and running your own custom lists is fully supported. An unsigned custom list simply runs in Audit/Config and requires the `-AllowCustomList` switch in write mode. To get the same 'verified' experience for your own lists, sign your list content with your code-signing certificate and pin your thumbprint locally. HardeningKitty's trust anchor is a single thumbprint.

#### Why RSA and not ECC?

The manifest is signed and verified as a PKCS#7/CMS structure (`System.Security.Cryptography.Pkcs.SignedCms`). On Windows PowerShell 5.1 (.NET Framework 4.x, still the default on Windows) CMS signing/verification with ECDSA keys is unreliable, whereas RSA works across both Windows PowerShell 5.1 and PowerShell 7. Since HardeningKitty must run on both, RSA-4096 is the interoperable choice.

### HardeningKitty Score

Each Passed finding gives 4 points, a Low finding gives 2 points, a Medium finding gives 1 point and a High Finding gives 0 points.

The formula for the HardeningKitty Score is _(Points achieved / Maximum points) * 5 + 1_.

#### Rating

| Score | Rating Casual | Rating Professional |
| :---- | :------------ | :------------------ |
| 6 | 😹 Excellent | Excellent |
| 5 | 😺 Well done | Good |
| 4 | 😼 Sufficient | Sufficient |
| 3 | 😿 You should do better | Insufficient |
| 2 | 🙀 Weak | Insufficient |
| 1 | 😾 Bogus | Insufficient |

### HardeningKitty Interface

[@ataumo](https://github.com/ataumo) build a web based interface for HardeningKitty. The tool can be used to create your own lists and provides additional information on the hardening settings. The [source code](https://github.com/ataumo/policies_hardening_interface) is under AGPL license and there is a [demo site](https://phi.cryptonit.fr/policies_hardening_interface/).

### KittyPorter - Make Hardening Kitty Reports Great Again

[Yair](https://github.com/Y8765) took care of presenting HardeningKitty results for sysadmins and even management in the form of a beautiful Excel spreadsheet containing Security Assessment Dashboards and a Dashboard with Dynamic Updates based on the status of findings, as well as an HTML Report Overview. He publishes his work in the [KittyPorter](https://github.com/Y8765/KittyPorter) repo.

### Last Update

HardeningKitty can be used to audit systems against the following baselines / benchmarks:

| Name | System Version    | Version  |
| :--- | :---------------- | :------  |
| 0x6d69636b Windows 11 (Machine) | 25H2 | |
| 0x6d69636b Windows 11 (User) | 25H2 | |
| BSI SiSyPHuS Windows 10 hoher Schutzbedarf Domänenmitglied (Machine) | 1809 | 1.0 |
| BSI SiSyPHuS Windows 10 hoher Schutzbedarf Domänenmitglied (User) | 1809| 1.0
| BSI SiSyPHuS Windows 10 normaler Schutzbedarf Domänenmitglied (Machine) | 1809| 1.0 |
| BSI SiSyPHuS Windows 10 normaler Schutzbedarf Domänenmitglied (User) | 1809| 1.0 |
| BSI SiSyPHuS Windows 10 normaler Schutzbedarf Einzelrechner (Machine) | 1809| 1.0 |
| BSI SiSyPHuS Windows 10 normaler Schutzbedarf Einzelrechner (User) | 1809 | 1.0 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 1809 | 1.6.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 1809 | 1.6.1 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 1903 | 1.7.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 1903 | 1.7.1 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 1909 | 1.8.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 1909 | 1.8.1 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 2004 | 1.9.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 2004 | 1.9.1 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 20H2 | 1.10.1 |
| CIS Microsoft Windows 10 Enterprise (User) | 20H2 | 1.10.1 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 21H1 | 1.11.0 |
| CIS Microsoft Windows 10 Enterprise (User) | 21H1 | 1.11.0 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 21H2 | 1.12.0 |
| CIS Microsoft Windows 10 Enterprise (User) | 21H2 | 1.12.0 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 22H2 | 2.0.0 |
| CIS Microsoft Windows 10 Enterprise (User) | 22H2 | 2.0.0 |
| CIS Microsoft Windows 10 Enterprise (Machine) | 22H2 | 3.0.0 |
| CIS Microsoft Windows 10 Enterprise (User) | 22H2 | 3.0.0 |
| CIS Microsoft Windows 11 Enterprise (Machine) | 21H2 | 1.0.0 |
| CIS Microsoft Windows 11 Enterprise (User) | 21H2 | 1.0.0 |
| CIS Microsoft Windows 11 Enterprise (Machine) | 22H2 | 2.0.0 |
| CIS Microsoft Windows 11 Enterprise (User) | 22H2 | 2.0.0 |
| CIS Microsoft Windows 11 Enterprise (Machine) | 23H2 | 3.0.0 |
| CIS Microsoft Windows 11 Enterprise (User) | 23H2 | 3.0.0 |
| CIS Microsoft Windows 11 Enterprise (Machine) | 24H2 | 4.0.0 |
| CIS Microsoft Windows 11 Enterprise (User) | 24H2 | 4.0.0 |
| CIS Microsoft Windows 11 Enterprise (Machine) | 25H2 | 5.1.0 |
| CIS Microsoft Windows 11 Enterprise (User) | 25H2 | 5.1.0 |
| CIS Microsoft Windows Server 2012 R2 (Machine) | R2 | 2.4.0 |
| CIS Microsoft Windows Server 2012 R2 (User) | R2 | 2.4.0 |
| CIS Microsoft Windows Server 2012 R2 (Machine) | R2 | 2.6.0 |
| CIS Microsoft Windows Server 2012 R2 (User) | R2 | 2.6.0 |
| CIS Microsoft Windows Server 2012 R2 (Machine) | R2 | 3.0.0 |
| CIS Microsoft Windows Server 2012 R2 (User) | R2 | 3.0.0 |
| CIS Microsoft Windows Server 2016 (Machine) | 1607 | 1.2.0 |
| CIS Microsoft Windows Server 2016 (User) | 1607 | 1.2.0 |
| CIS Microsoft Windows Server 2016 (Machine) | 1607 | 1.3.0 |
| CIS Microsoft Windows Server 2016 (User) | 1607 | 1.3.0 |
| CIS Microsoft Windows Server 2016 (Machine) | 1607 | 2.0.0 |
| CIS Microsoft Windows Server 2016 (User) | 1607 | 2.0.0 |
| CIS Microsoft Windows Server 2016 (Machine) | 1607 | 3.0.0 |
| CIS Microsoft Windows Server 2016 (User) | 1607 | 3.0.0 |
| CIS Microsoft Windows Server 2019 (Machine) | 1809 | 1.1.0 |
| CIS Microsoft Windows Server 2019 (User) | 1809 | 1.1.0 |
| CIS Microsoft Windows Server 2019 (Machine) | 1809 | 1.2.1 |
| CIS Microsoft Windows Server 2019 (User) | 1809 | 1.2.1 |
| CIS Microsoft Windows Server 2019 (Machine) | 1809 | 2.0.0 |
| CIS Microsoft Windows Server 2019 (User) | 1809 | 2.0.0 |
| CIS Microsoft Windows Server 2019 (Machine) | 1809 | 3.0.0 |
| CIS Microsoft Windows Server 2019 (User) | 1809 | 3.0.0 |
| CIS Microsoft Windows Server 2022 (Machine) | 21H2 | 1.0.0 |
| CIS Microsoft Windows Server 2022 (User) | 21H2 | 1.0.0 |
| CIS Microsoft Windows Server 2022 (Machine) | 22H2 | 2.0.0 |
| CIS Microsoft Windows Server 2022 (User) | 22H2 | 2.0.0 |
| CIS Microsoft Windows Server 2022 (Machine) | 22H2 | 3.0.0 |
| CIS Microsoft Windows Server 2022 (User) | 22H2 | 3.0.0 |
| CIS Microsoft Windows Server 2022 (Machine) | 22H2 | 4.0.0 |
| CIS Microsoft Windows Server 2022 (User) | 22H2 | 4.0.0 |
| CIS Microsoft Windows Server 2025 (Machine) | 24H2 | 1.0.0 |
| CIS Microsoft Windows Server 2025 (User) | 24H2 | 1.0.0 |
| DoD Microsoft Windows 10 STIG (Machine) | 20H2 | v2r1 |
| DoD Microsoft Windows 10 STIG (User) | 20H2 | v2r1 |
| DoD Windows Server 2019 Domain Controller STIG (Machine) | 20H2 | v2r1 |
| DoD Windows Server 2019 Domain Controller STIG (User) | 20H2 | v2r1 |
| DoD Windows Server 2019 Member Server STIG (Machine) | 20H2 | v2r1 |
| DoD Windows Server 2019 Member Server STIG (User) | 20H2 | v2r1 |
| DoD Windows Defender Antivirus STIG | 20H2 | v2r1 |
| DoD Windows Firewall STIG | 20H2 | v1r7 |
| Microsoft Security baseline for Microsoft Edge | 87 | Final |
| Microsoft Security baseline for Microsoft Edge | 88, 89, 90, 91 | Final |
| Microsoft Security baseline for Microsoft Edge | 92 | Final |
| Microsoft Security baseline for Microsoft Edge | 93, 94 | Final |
| Microsoft Security baseline for Microsoft Edge | 95 | Final |
| Microsoft Security baseline for Microsoft Edge | 96 | Final |
| Microsoft Security baseline for Microsoft Edge | 97 | Final |
| Microsoft Security baseline for Microsoft Edge | 98, 99, 100, 101, 102, 103, 104, 105, 106 | Final |
| Microsoft Security baseline for Microsoft Edge | 107, 108, 109, 110, 111 | Final |
| Microsoft Security baseline for Microsoft Edge | 112, 113 | Final |
| Microsoft Security baseline for Microsoft Edge | 114, 115, 116 | Final |
| Microsoft Security baseline for Microsoft Edge | 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127 | Final |
| Microsoft Security baseline for Microsoft Edge | 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138 | Final |
| Microsoft Security baseline for Microsoft Edge | 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150 | Final |
| Microsoft Security baseline for Microsoft Edge | 151, 152, 153, 154, 155, 156 | Final |
| Microsoft Security baseline for Windows 10 | 2004 | Final |
| Microsoft Security baseline for Windows 10 | 20H2, 21H1 | Final |
| Microsoft Security baseline for Windows 10 | 21H2 | Final |
| Microsoft Security baseline for Windows 10 (Machine) | 22H2 | Final |
| Microsoft Security baseline for Windows 10 (User) | 22H2 | Final |
| Microsoft Security baseline for Windows 11 | 21H2 | Final |
| Microsoft Security baseline for Windows 11 (Machine) | 22H2 | Final |
| Microsoft Security baseline for Windows 11 (User) | 22H2 | Final |
| Microsoft Security baseline for Windows 11 (Machine) | 23H2 | Final |
| Microsoft Security baseline for Windows 11 (User) | 23H2 | Final |
| Microsoft Security baseline for Windows 11 (Machine) | 24H2 | Final |
| Microsoft Security baseline for Windows 11 (User) | 24H2 | Final |
| Microsoft Security baseline for Windows 11 (Machine) | 25H2 | Final |
| Microsoft Security baseline for Windows 11 (User) | 25H2 | Final |
| Microsoft Security baseline for Windows 11 (Machine) | 26H2 | Final |
| Microsoft Security baseline for Windows 11 (User) | 26H2 | Final |
| Microsoft Security baseline for Windows Server (DC) | 2004 | Final |
| Microsoft Security baseline for Windows Server (Member) | 2004 | Final |
| Microsoft Security baseline for Windows Server (DC) | 20H2 | Final |
| Microsoft Security baseline for Windows Server (Member) | 20H2 | Final |
| Microsoft Security baseline for Windows Server 2022 (DC) | 21H2 | Final |
| Microsoft Security baseline for Windows Server 2022 (Member) | 21H2 | Final |
| Microsoft Security baseline for Windows Server 2025 (DC) | 24H2 | Final |
| Microsoft Security baseline for Windows Server 2025 (Member) | 24H2 | Final |
| Microsoft Security baseline for Windows Server 2025 (DC) | 2506 | Final |
| Microsoft Security baseline for Windows Server 2025 (Member) | 2506 | Final |
| Microsoft Security baseline for Windows Server 2025 (DC) | 2602 | Final |
| Microsoft Security baseline for Windows Server 2025 (Member) | 2602 | Final |
| Microsoft Security baseline for Office 365 ProPlus (Machine) | Sept 2019 | Final |
| Microsoft Security baseline for Office 365 ProPlus (User) | Sept 2019 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (Machine) | v2104, v2106 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (User) | v2104, v2106 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (Machine) | v2112 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (User) | v2112 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (Machine) | v2206 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (User) | v2206 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (Machine) | v2306, v2312 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (User) | v2306, v2312 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (Machine) | v2412 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (User) | v2412 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (Machine) | v2512 | Final |
| Microsoft Security Baseline for Microsoft 365 Apps for enterprise (User) | v2512 | Final |
| Microsoft Windows Server TLS Settings | 1809 | 1.0 |
| Microsoft Windows Server TLS Settings (Future Use with TLSv1.3) | 1903 | 1.0 |

## Sources

* [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* [Security baseline (FINAL): Windows 10 and Windows Server, version 2004](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-final-windows-10-and-windows-server-version/ba-p/1543631)
* [Security baseline (FINAL) for Windows 10 and Windows Server, version 20H2](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-final-for-windows-10-and-windows-server/ba-p/1999393)
* [Security baseline (FINAL) for Windows 10, version 21H1](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-final-for-windows-10-version-21h1/ba-p/2362353)
* [Security baseline for Windows 10, version 21H2](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-windows-10-version-21h2/ba-p/3042703)
* [Windows Server 2022 Security Baseline](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-server-2022-security-baseline/ba-p/2724685)
* [Security baseline for Windows Server 2025, security baseline](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/windows-server-2025-security-baseline/4358733)
* [Security baseline for Windows Server 2025, version 2506](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-baseline-for-windows-server-2025-version-2506/4426431)
* [Security baseline for Windows Server 2025, version 2602](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-baseline-for-windows-server-2025-version-2602/4496468)
* [Windows 11 Security baseline](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-11-security-baseline/ba-p/2810772)
* [Windows 11, version 22H2 Security baseline](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-11-version-22h2-security-baseline/ba-p/3632520)
* [Windows 11, version 23H2 security baseline](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-11-version-23h2-security-baseline/ba-p/3967618)
* [Windows 11, version 24H2 security baseline](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-11-version-24h2-security-baseline/ba-p/4252801)
* [Windows 11, version 25H2 security baseline](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/windows-11-version-25h2-security-baseline/4456231)
* [Windows 11, version 26H2 security baseline](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-11-version-26h2-security-baseline/ba-p/4560382)
* [Kernel DMA Protection for Thunderbolt 3](https://docs.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt)
* [BitLocker Countermeasures](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures)
* [Blocking the SBP-2 driver and Thunderbolt controllers to reduce 1394 DMA and Thunderbolt DMA threats to BitLocker](https://support.microsoft.com/en-us/help/2516445/blocking-the-sbp-2-driver-and-thunderbolt-controllers-to-reduce-1394-d)
* [Manage Windows Defender Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
* [Reduce attack surfaces with attack surface reduction rules](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction)
* [Configuring Additional LSA Protection](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
* [Securely opening Microsoft Office documents that contain Dynamic Data Exchange (DDE) fields](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2017/4053440)
* [DDE registry settings](https://gist.githubusercontent.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b/raw/69c9d9d14b386d8f178e59a046804501ec1ee304/disable_ddeauto.reg)
* [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
* [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
* [Dane Stuckey - @cryps1s Endpoint Isolation with the Windows Firewall](https://medium.com/@cryps1s/endpoint-isolation-with-the-windows-firewall-462a795f4cfb)
* [Microsoft Security Compliance Toolkit 1.0](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
* [Policy Analyzer](https://blogs.technet.microsoft.com/secguide/2016/01/22/new-tool-policy-analyzer/)
* [Security baseline for Office 365 ProPlus (v1908, Sept 2019) - FINAL](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-office-365-proplus-v1908-sept-2019-final/ba-p/873084)
* [Security baseline for Microsoft 365 Apps for enterprise v2104 - FINAL](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-365-apps-for-enterprise-v2104/ba-p/2307695)
* [Security baseline for Microsoft 365 Apps for enterprise v2106 - FINAL](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-365-apps-for-enterprise-v2106/ba-p/2492355)
* [Security baseline for Microsoft 365 Apps for enterprise, v2112](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-365-apps-for-enterprise-v2112/ba-p/3038172)
* [Security baseline for Microsoft 365 Apps for enterprise v2206](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-m365-apps-for-enterprise-v2306/ba-p/3858702)
* [Security baseline for Microsoft 365 Apps for enterprise v2306](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-m365-apps-for-enterprise-v2306/ba-p/3858702)
* [Security baseline for Microsoft 365 Apps for enterprise v2312](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-m365-apps-for-enterprise-v2312/ba-p/4009591)
* [Security Baseline for M365 Apps for enterprise v2412](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-baseline-for-m365-apps-for-enterprise-v2412/4357320)
* [Security Baseline for M365 Apps for enterprise v2512](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-baseline-for-m365-apps-for-enterprise-v2512/4487213)
* [mackwage/windows_hardening.cmd](https://gist.github.com/mackwage/08604751462126599d7e52f233490efe)
* [Security baseline for Microsoft Edge version 87](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-87/ba-p/1950297)
* [Security baseline for Microsoft Edge version 89](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-89/ba-p/2186265)
* [Security baseline for Microsoft Edge v92](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v92/ba-p/2563679)
* [Security baseline for Microsoft Edge v93](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v93/ba-p/2744505)
* [Security baseline for Microsoft Edge v95](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v95/ba-p/2897269)
* [Security baseline for Microsoft Edge v96](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v96/ba-p/2997665)
* [Security baseline for Microsoft Edge v97](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v97/ba-p/3062252)
* [Security baseline for Microsoft Edge v98](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v98/ba-p/3165443)
* [Security baseline for Microsoft Edge v99](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v99/ba-p/3249241)
* [Security baseline for Microsoft Edge v100](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v100/ba-p/3281982)
* [Security baseline for Microsoft Edge v101](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v101/ba-p/3298140)
* [Security baseline for Microsoft Edge v102](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v102/ba-p/3465195)
* [Security baseline for Microsoft Edge v103](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v103/ba-p/3548236)
* [Security baseline for Microsoft Edge v104](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v104/ba-p/3593826)
* [Security baseline for Microsoft Edge v105](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v105/ba-p/3615904)
* [Security baseline for Microsoft Edge v106](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-106/ba-p/3643958)
* [Security baseline for Microsoft Edge v107](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-v107/ba-p/3678903)
* [Security baseline for Microsoft Edge v108](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-108/ba-p/3691250)
* [Security baseline for Microsoft Edge v109](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-109/ba-p/3713981)
* [Security baseline for Microsoft Edge v110](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-110/ba-p/3740900)
* [Security baseline for Microsoft Edge v111](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-111/ba-p/3767483)
* [Security baseline for Microsoft Edge v112](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-112/ba-p/3789975)
* [Security baseline for Microsoft Edge v113](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-113/ba-p/3814398)
* [Security baseline for Microsoft Edge v114](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-114/ba-p/3839728)
* [Security baseline for Microsoft Edge v115](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-115/ba-p/3882420)
* [Security baseline for Microsoft Edge v116](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-116/ba-p/3905425)
* [Security baseline for Microsoft Edge v117](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-117/ba-p/3930862)
* [Security baseline for Microsoft Edge v118](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-118/ba-p/3955123)
* [Security baseline for Microsoft Edge v119](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-119/ba-p/3978427)
* [Security baseline for Microsoft Edge v120](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-120/ba-p/4009561)
* [Security baseline for Microsoft Edge v121](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-121/ba-p/4057135)
* [Security baseline for Microsoft Edge v122](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-122/ba-p/4073142)
* [Security baseline for Microsoft Edge v123](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-123/ba-p/4098458)
* [Security baseline for Microsoft Edge v124](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-124/ba-p/4124826)
* [Security baseline for Microsoft Edge v125](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-125/ba-p/4146218)
* [Security baseline for Microsoft Edge v126](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-126/ba-p/4168263)
* [Security baseline for Microsoft Edge v127](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-127/ba-p/4205820)
* [Security baseline for Microsoft Edge v128](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-128/ba-p/4237524)
* [Security baseline for Microsoft Edge v129](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-129/ba-p/4250551)
* [Security baseline for Microsoft Edge v130](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-130/ba-p/4273981)
* [Security baseline for Microsoft Edge v131](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-review-for-microsoft-edge-version-131/4298314)
* [Security baseline for Microsoft Edge v132](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-review-for-microsoft-edge-version-132/4358734)
* [Security baseline for Microsoft Edge v133](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-review-for-microsoft-edge-version-133/4376048)
* [Security baseline for Microsoft Edge v134](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-review-for-microsoft-edge-version-134/4393674)
* [Security baseline for Microsoft Edge v135](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-review-for-microsoft-edge-version-135/4406195)
* [Security baseline for Microsoft Edge v136](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-review-for-microsoft-edge-version-136/4410797)
* [Security baseline for Microsoft Edge v137](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-review-for-microsoft-edge-version-137/4420095)
* [Security baseline for Microsoft Edge v138](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-review-for-microsoft-edge-version-138/4427877)
* [Security baseline for Microsoft Edge v139](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-139/4441251)
* [Security baseline for Microsoft Edge v140](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-140/ba-p/4452553)
* [Security baseline for Microsoft Edge v141](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-141/ba-p/4460481)
* [Security baseline for Microsoft Edge v142](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-142/ba-p/4466598)
* [Security baseline for Microsoft Edge v143](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-143/ba-p/4474871)
* [Security baseline for Microsoft Edge v144](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-144/ba-p/4486065)
* [Security baseline for Microsoft Edge v145](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-145/ba-p/4494968)
* [Security baseline for Microsoft Edge v146](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-146/ba-p/4502057)
* [Security baseline for Microsoft Edge v147](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-review-for-microsoft-edge-version-147/4509974)
* [Security baseline for Microsoft Edge v148](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-review-for-microsoft-edge-version-148/4521209)
* [Security baseline for Microsoft Edge v149](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-review-for-microsoft-edge-version-149/4526371)
* [Security baseline for Microsoft Edge v150](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-review-for-microsoft-edge-version-150/4546730)
* [Security baseline for Microsoft Edge v151](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-151/4549607)
* [Security baseline for Microsoft Edge v152](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-review-for-microsoft-edge-version-152/4550956)
* [Security baseline for Microsoft Edge v156](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-review-for-microsoft-edge-version-156/ba-p/4567729)
* [Microsoft Edge - Policies](https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-policies)
* [A hint for Office 365 Telemetry](https://twitter.com/milenkowski/status/1326865844215934979)
* [BSI: Microsoft Office Telemetry Analysis report](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/Studien/Office_Telemetrie/Office_Telemetrie.pdf?__blob=publicationFile&v=5)
* [Use policy settings to manage privacy controls for Microsoft 365 Apps for enterprise](https://docs.microsoft.com/en-us/deployoffice/privacy/manage-privacy-controls)
* [DoD Cyber Exchange Public - Security Technical Implementation Guides (STIGs) - Group Policy Objects](https://public.cyber.mil/stigs/gpo/)
* [BSI SiSyPHuS Win10: Windows 10 Hardening Guideline](https://www.bsi.bund.de/EN/Topics/Cyber-Security/Recommendations/SiSyPHuS_Win10/AP11/SiSyPHuS_AP11.html)
* [Setup Microsoft Windows or IIS for SSL Perfect Forward Secrecy and TLS 1.2](https://www.hass.de/content/setup-microsoft-windows-or-iis-ssl-perfect-forward-secrecy-and-tls-12)
* [Nartac Software - IIS Crypto](https://www.nartac.com/Products/IISCrypto/)
* [Transport Layer Security (TLS) best practices with the .NET Framework](https://docs.microsoft.com/en-us/dotnet/framework/network-programming/tls)
* [TLS Cipher Suites in Windows Server 2022](https://docs.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022)
* [Transport Layer Security (TLS) registry settings](https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings)
* [Windows Defender Antivirus can now run in a sandbox](https://www.microsoft.com/security/blog/2018/10/26/windows-defender-antivirus-can-now-run-in-a-sandbox/)
* [KB5005010: Restricting installation of new printer drivers after applying the July 6, 2021 updates](https://support.microsoft.com/en-us/topic/kb5005010-restricting-installation-of-new-printer-drivers-after-applying-the-july-6-2021-updates-31b91c02-05bc-4ada-a7ea-183b129578a7)
* [admx.help - Group Policy Administrative Templates Catalog](https://admx.help/)
* [How to Defend Users from Interception Attacks via SMB Client Defense](https://techcommunity.microsoft.com/t5/itops-talk-blog/how-to-defend-users-from-interception-attacks-via-smb-client/ba-p/1494995)
* [Migrating from Windows PowerShell 5.1 to PowerShell 7](https://learn.microsoft.com/en-us/powershell/scripting/whats-new/migrating-from-windows-powershell-51-to-powershell-7)
* [Data security and Python in Excel](https://support.microsoft.com/en-us/office/data-security-and-python-in-excel-33cc88a4-4a87-485e-9ff9-f35958278327)
* [Deprecated features for Windows client](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features)
* [Windows Client management - Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-configuration-service-provider)
