# Private, read-only classification support for HardeningKitty.SecurityAudit.psm1.

Function Get-SecurityAuditPriorityReference {
    $Reference = [Hashtable]::new([StringComparer]::Ordinal)
    ForEach ($Scope in @('Machine', 'User')) {
        $List = "finding_list_0x6d69636b_$($Scope.ToLowerInvariant()).csv"
        $Definitions = @(Import-Csv -LiteralPath (Join-Path $PSScriptRoot "lists\$List") -Encoding UTF8 -ErrorAction Stop)
        ForEach ($Definition in $Definitions) {
            $Reference["$($Scope):$($Definition.ID)"] = [PSCustomObject]@{
                Scope = $Scope
                ID = $Definition.ID
                List = $List
                Name = $Definition.Name
                Source = Get-SecurityAuditQuery -Finding $Definition
                Recommended = Get-SecurityAuditCriterion -Finding $Definition
                Method = $Definition.Method
            }
        }
    }
    Return $Reference
}

Function Set-SecurityAuditPriority {
    Param (
        [Parameter(Mandatory = $true)] $Finding,
        [Hashtable] $Reference = @{}
    )

    $Importance = 'Unrated'
    $ImportanceReason = '명시적인 중요도 분류 근거가 없습니다. 미분류는 낮은 위험이나 안전을 뜻하지 않습니다.'
    $ImportanceBasis = ''
    If ($Finding.Scope -cin @('Context', 'Execution')) {
        $Importance = 'Reference'
        $ImportanceReason = '점검 범위 또는 수집 실행에 관한 참고 정보이며, 보안 통제의 중요도 등급이 아닙니다.'
    } ElseIf ($Finding.Scope -cin @('Machine', 'User')) {
        If ($Finding.Severity -cin @('High', 'Medium', 'Low')) {
            $Importance = [String]$Finding.Severity
            $ImportanceBasis = '원본 Severity를 그대로 분류한 기준 목록 작성자의 판단입니다. 관측된 호스트 위험 수준이나 적용 가능성을 증명하지 않습니다.'
        } Else {
            $ImportanceReason = '원본 Severity가 정확히 High, Medium, Low 중 하나가 아니므로 미분류입니다. 원문은 보존하며, 호스트 위험을 추정하지 않습니다.'
        }
    } ElseIf ($Finding.Scope -ceq 'Supplemental') {
        If ($Finding.ID -cin @('SS-02', 'SS-03', 'PP-01', 'PP-02', 'PP-06', 'LA-05')) {
            $Importance = 'High'
        } ElseIf ($Finding.ID -cin @('SS-01', 'SS-04', 'PP-03', 'PP-04', 'PP-05', 'LA-02', 'LA-03', 'LA-04')) {
            $Importance = 'Medium'
        } ElseIf ($Finding.ID -ceq 'LA-01') {
            $Importance = 'Reference'
            $ImportanceReason = '비밀번호 설정·변경일이라는 날짜 메타데이터입니다. 날짜 자체는 보안 통제의 합격이나 위험 수준을 증명하지 않습니다.'
        }
        $ImportanceBasis = '보조 점검 항목의 명시적 보안 목적에 따른 분류이며, 호스트의 실제 위험이나 변경 순서를 뜻하지 않습니다.'
    }
    Switch -CaseSensitive ($Importance) {
        'High' { $ImportanceReason = "직접적인 접근 통제·자격 증명·데이터 보호에 관한 높은 중요도입니다. $ImportanceBasis" }
        'Medium' { $ImportanceReason = "방어·탐지·정책 이행을 지원하는 중간 중요도입니다. $ImportanceBasis" }
        'Low' { $ImportanceReason = "주로 편의 기능 또는 노출 감소에 관한 낮은 중요도입니다. $ImportanceBasis" }
    }

    $Priority = 'Review'
    $PriorityReason = '이 항목에는 검증된 변경 순서가 정의되지 않았습니다. 적용 가능성과 의존성을 검토해야 하며, ID·범주·중요도만으로 변경을 권하지 않습니다.'
    If ($Finding.TestResult -in @('Passed', 'Info', 'NotApplicable')) {
        $Priority = 'None'
        Switch ($Finding.TestResult) {
            'Passed' { $PriorityReason = '현재 보고된 판정은 Passed이므로 이 행에서 변경을 요청하지 않습니다. 전체 시스템의 안전을 보장하는 판정은 아닙니다.' }
            'Info' { $PriorityReason = '정보 제공 행이므로 변경을 요청하지 않습니다. Info는 자동 준수나 보안 통제의 합격을 뜻하지 않습니다.' }
            'NotApplicable' { $PriorityReason = '현재 보고된 적용 제외 판정에 따라 변경을 요청하지 않습니다. NotApplicable은 자동 준수나 보안 통제의 합격을 뜻하지 않으며 적용 제외 근거를 별도로 유지해야 합니다.' }
        }
    } ElseIf ($Finding.TestResult -in @('Unknown', 'Error')) {
        $PriorityReason = '판정이 Unknown 또는 Error이므로 변경보다 수집 오류·증거·적용 가능성 확인이 먼저입니다. 실패나 준수로 바꾸어 해석하지 않습니다.'
    } ElseIf ($Finding.TestResult -ne 'Failed') {
        $PriorityReason = '확인 가능한 실패 판정이 아니므로 변경 순서를 부여하지 않습니다. 원본 상태와 증거를 검토해야 합니다.'
    } ElseIf ($Finding.ValueOrigin -cne 'Observed' -or $Finding.UsedDefault -eq $true) {
        $PriorityReason = '실측(Observed) 실패가 아니거나 기본값으로 대체된 값입니다. 변경 전에 원본 설정을 다시 확인해야 하며 기본값을 호스트 증거로 간주하지 않습니다.'
    } ElseIf ($Finding.Scope -cin @('Context', 'Execution')) {
        $PriorityReason = '점검 범위·실행 정보는 직접적인 설정 변경 대상이 아닙니다. 수집 및 실행 근거를 검토해야 합니다.'
    } ElseIf ($Finding.Scope -ceq 'Supplemental') {
        Switch -CaseSensitive ($Finding.ID) {
            'SS-01' { $Priority = 'P2'; $PriorityReason = '화면 보호기 활성화는 대기시간·파일·재인증 설정을 함께 확인해야 합니다. 업무 중 잠금과 자격 증명 재입력의 영향을 검토해야 합니다.' }
            'SS-02' { $Priority = 'P2'; $PriorityReason = '복귀 시 재인증은 방치된 세션 접근을 줄입니다. 잠금 해제용 자격 증명과 업무 흐름을 확인하고 재입력 영향을 검토해야 합니다.' }
            'SS-03' { $Priority = 'P2'; $PriorityReason = '유휴 대기시간 조정은 세션 노출 시간을 줄일 수 있습니다. 발표·장시간 작업 중 잠금과 자격 증명 재입력의 영향을 확인해야 합니다.' }
            'SS-04' { $Priority = 'P2'; $PriorityReason = '화면 보호기 파일의 존재·신뢰성과 조직의 승인 여부를 확인해야 합니다. 파일을 실행하지 않고 경로를 검토하며 잠금·재인증 정책과 함께 판단해야 합니다.' }
            'PP-01' { $Priority = 'P2'; $PriorityReason = '복잡도는 향후 비밀번호 설정·변경에 적용됩니다. 조직 정책과 계정별 적용 범위 및 다음 자격 증명 변경 시의 사용자 영향을 확인해야 합니다.' }
            'PP-02' { $Priority = 'P2'; $PriorityReason = '최소 길이는 향후 비밀번호 설정·변경을 제한합니다. 조직 정책·지원 가능한 길이·계정별 적용 범위와 다음 자격 증명 변경 시의 영향을 확인해야 합니다.' }
            'PP-04' { $Priority = 'P2'; $PriorityReason = '최소 사용 기간은 반복 변경을 통한 기록 우회를 줄이지만 긴급 자격 증명 재설정을 제약할 수 있습니다. 지원 절차와 최대 사용 기간의 조합을 확인해야 합니다.' }
            'PP-05' { $Priority = 'P2'; $PriorityReason = '비밀번호 기록은 이전 자격 증명의 재사용을 제한합니다. 조직 정책·최소 사용 기간과 향후 비밀번호 변경 및 복구 지원 영향을 확인해야 합니다.' }
            'PP-03' { $Priority = 'P3'; $PriorityReason = '정기 비밀번호 만료의 필요성을 조직 정책과 계정별 예외에 따라 판단해야 합니다. 서비스·예약 작업의 자격 증명 의존성과 변경·복구 절차를 확인해야 합니다.' }
            'PP-06' { $Priority = 'P3'; $PriorityReason = '가역 암호화 저장은 자격 증명 노출 영향을 키울 수 있습니다. 이를 요구하는 인증 방식과 애플리케이션 의존성, 기존 비밀번호의 재설정 필요성을 확인해야 합니다.' }
            'LA-02' { $Priority = 'P3'; $PriorityReason = '비밀번호 경과일만으로 일괄 변경하지 않습니다. 날짜 근거·조직 정책·계정 용도와 서비스·예약 작업의 자격 증명 갱신 및 복구 절차를 확인해야 합니다.' }
            'LA-03' { $Priority = 'P3'; $PriorityReason = '만료 상태와 적용 정책·계정 예외를 확인해야 합니다. 계정 복구 수단과 서비스·예약 작업의 자격 증명 갱신 절차를 마련해야 합니다.' }
            'LA-04' { $Priority = 'P3'; $PriorityReason = '비밀번호 무기한 사용 예외는 계정 용도와 조직 정책을 확인한 뒤 판단해야 합니다. 서비스·예약 작업 중단을 피할 자격 증명 갱신·복구 절차가 필요합니다.' }
            'LA-05' { $Priority = 'P3'; $PriorityReason = '비밀번호 필수 플래그는 실제 빈 비밀번호의 증거가 아닙니다. 계정 용도·대체 인증·서비스 의존성과 접근 복구 수단을 확인한 뒤 정책을 계획해야 합니다.' }
        }
    } ElseIf ($Finding.Scope -cin @('Machine', 'User')) {
        $Key = "$($Finding.Scope):$($Finding.ID)"
        $Entry = $Reference[$Key]
        $MatchesReference = $null -ne $Entry
        If ($MatchesReference) {
            ForEach ($Property in @('Scope', 'ID', 'List', 'Name', 'Source', 'Recommended')) {
                If (-not [String]::Equals([String]$Finding.$Property, [String]$Entry.$Property, [StringComparison]::Ordinal)) {
                    $MatchesReference = $false
                    Break
                }
            }
        }
        If (-not $MatchesReference) {
            $PriorityReason = '번들 기준 목록의 Scope·ID·List·Name·Source·Recommended와 대소문자까지 정확히 일치하는 참조가 없습니다. 사용자 정의 목록이나 변경된 정의에 기존 ID의 변경 순서를 적용하지 않습니다.'
        } ElseIf ($Entry.Method -ceq 'Processmitigation') {
            If ($Finding.Result -eq 'NOTSET') {
                $PriorityReason = 'NOTSET은 명시적 재정의가 없어 Windows 기본 동작을 따를 수 있다는 뜻이며 보호 기능이 꺼짐을 뜻하지 않습니다. 실제 유효 보호와 애플리케이션 호환성을 확인한 뒤 판단해야 합니다.'
            } Else {
                $PriorityReason = '프로세스 완화 설정은 Windows의 유효 보호 상태·적용 범위와 애플리케이션 호환성 검토가 필요합니다. 결과만으로 일괄 변경하지 않습니다.'
            }
        } ElseIf ($Entry.Method -ceq 'MpComputerStatus') {
            $PriorityReason = '현재 활성 백신과 Defender의 실행·수동 모드 및 해당 기능의 적용 가능성을 확인해야 합니다. 타사 백신 사용을 가정하지 않으며, 이 값만으로 NotApplicable이나 안전을 판정하지 않습니다.'
        } ElseIf ($Key -cin @('Machine:1421', 'Machine:1427', 'Machine:1433', 'Machine:1774')) {
            $Priority = 'P1'
            $PriorityReason = '방화벽 또는 이벤트 로그의 용량 확대는 보존 가능한 기록을 늘리는 후보입니다. 디스크 여유·보존 및 덮어쓰기 정책·로그 전달 설정을 먼저 확인해야 합니다.'
        } ElseIf ($Key -cin @('Machine:1502', 'Machine:1506', 'Machine:1509', 'Machine:1519', 'Machine:1520', 'Machine:1524')) {
            $Priority = 'P1'
            $PriorityReason = '선별된 감사 이벤트 추가는 탐지 근거를 보완하는 후보입니다. 기존 성공 감사를 제거하지 않고 필요한 실패·성공 기록을 추가하는지, 정책 상속·로그 용량에 영향이 없는지 확인해야 합니다.'
        } ElseIf ($Key -cin @('Machine:1422', 'Machine:1428', 'Machine:1434')) {
            $Priority = 'P1'
            $PriorityReason = '차단된 패킷 로깅은 방화벽 허용·차단 규칙을 바꾸지 않고 조사 근거를 보완하는 후보입니다. 차단 트래픽에 따른 로그 증가·저장 공간·보존 및 접근 권한을 확인해야 합니다.'
        } ElseIf ($Key -ceq 'User:4501') {
            $Priority = 'P1'
            $PriorityReason = 'Windows 팁·추천 표시를 줄이는 편의 기능 조정 후보입니다. 사용자가 해당 안내를 활용하는지와 조직의 사용자 환경 정책을 확인해야 합니다.'
        } ElseIf ($Key -ceq 'User:4505') {
            $PriorityReason = '원본 기준은 DisableAutoplay = 0을 요구합니다. 이를 자동재생 해제로 안내하면 설정 방향을 반대로 해석할 수 있으므로 기준 의도와 유효 설정을 재확인해야 합니다. 자동재생 해제를 위한 빠른 조치 목록에서는 제외하며 원본 판정과 권장값은 유지합니다. USB 파일의 직접 열기와 AutoPlay는 별개입니다.'
        } ElseIf ($Entry.Method -ceq 'auditpol') {
            $Priority = 'P2'
            $PriorityReason = '감사 범위 변경은 탐지를 보완하지만 로그 양·저장 및 전달 용량·수집 부하가 늘 수 있습니다. 적용 대상과 정책 상속을 확인하고 기존 성공 감사도 보존해야 합니다.'
        } ElseIf ($Key -cin @('Machine:1423', 'Machine:1429', 'Machine:1435')) {
            $Priority = 'P2'
            $PriorityReason = '성공 연결 로깅은 정상 통신 기록도 늘립니다. 로그 양·디스크 및 전달 용량·개인정보 보존·분석 필요성을 확인한 뒤 적용을 판단해야 합니다.'
        } ElseIf ($Key -ceq 'Machine:1303') {
            $Priority = 'P2'
            $PriorityReason = '최근 로그인 사용자 숨김은 계정명 노출을 줄이지만 사용자 이름과 자격 증명을 직접 입력해야 할 수 있습니다. 로그인 방식과 사용자 지원 영향을 확인해야 합니다.'
        } ElseIf ($Key -ceq 'Machine:1320') {
            $Priority = 'P2'
            $PriorityReason = '로그인 전 종료 제한은 종료 작업에 로그인을 요구할 수 있습니다. 공유 장치의 운영·자격 증명 입력·접근성 및 비상 종료 요구를 확인해야 합니다.'
        } ElseIf ($Key -cin @('Machine:1322', 'Machine:1323', 'Machine:1328')) {
            $Priority = 'P2'
            $PriorityReason = 'UAC 또는 프린터 드라이버 설치 권한 강화는 관리자 승인·자격 증명 입력을 요구할 수 있습니다. 관리자 접근 수단과 설치·지원 업무의 영향을 확인해야 합니다.'
        } ElseIf ($Key -cin @('Machine:2400', 'Machine:2403', 'Machine:2404', 'Machine:2405', 'Machine:2406', 'Machine:2407', 'Machine:2408', 'Machine:2409', 'Machine:2410', 'Machine:2412', 'Machine:2413')) {
            $Priority = 'P2'
            $PriorityReason = 'Xbox 기능·주변기기 또는 WebClient/WebDAV 의존성이 없고 미사용임을 확인한 경우에만 비활성화를 검토할 후보입니다. Stopped는 현재 실행 상태일 뿐 미사용의 증거가 아니며, 필요 시 시작되는 기능도 확인해야 합니다.'
        } ElseIf ($Key -ceq 'User:4502') {
            $Priority = 'P2'
            $PriorityReason = '장치 간 공유·연결 경험 기능을 실제로 사용하지 않는 경우에만 제한을 검토해야 합니다. 연동 앱과 사용자의 장치 간 작업 흐름을 확인해야 합니다.'
        } ElseIf ($Key -cin @('Machine:1305', 'Machine:1307', 'Machine:1308', 'Machine:1310', 'Machine:1315', 'Machine:1316')) {
            $Priority = 'P3'
            $PriorityReason = 'SMB 서명·NTLM 세션 보안·익명 접근 제한은 적용 가능성과 NAS·파일 공유·구형 장치의 인증 호환성을 시험해야 합니다. 실제 연결 영향과 복원 가능한 기존 설정을 확인해야 합니다.'
        } ElseIf ($Key -ceq 'Machine:1311') {
            $Priority = 'P3'
            $PriorityReason = '네트워크 인증용 저장 자격 증명 제한은 공유·원격 연결·자동 작업을 중단시킬 수 있습니다. 저장된 자격 증명 의존성과 대체 인증·복구 수단을 확인해야 합니다.'
        } ElseIf ($Key -cin @('Machine:2401', 'Machine:2402')) {
            $Priority = 'P3'
            $PriorityReason = 'Spooler 제한은 인쇄와 가상 프린터·PDF 출력에 영향을 줄 수 있습니다. 로컬·공유 프린터 및 응용 프로그램의 인쇄 의존성을 확인해야 합니다.'
        } ElseIf ($Key -cin @('Machine:1708', 'Machine:1762')) {
            $Priority = 'P3'
            $PriorityReason = 'BitLocker 정책값만으로 실제 암호화를 증명하지 않습니다. 실제 볼륨 암호화·보호 상태와 복구 키의 안전한 보관 및 사용 가능성, 부팅·복구 절차를 먼저 확인해야 합니다.'
        } ElseIf ($Key -ceq 'User:4303') {
            $Priority = 'P3'
            $PriorityReason = 'PowerShell 언어 모드는 현재 세션 정보만으로 영구적인 통제를 입증하지 않습니다. 애플리케이션 제어 정책의 적용 범위와 관리 스크립트·자동화의 호환성을 검증해야 합니다.'
        }
    }

    If ($Priority -eq 'P1') {
        $PriorityReason += ' P1은 저영향 우선 검토 후보이지 무위험 변경 승인이 아닙니다.'
    } ElseIf ($Priority -eq 'P3') {
        $PriorityReason += ' P3은 낮은 보안 중요도가 아니라 변경·롤백·복구 계획이 필요한 순서입니다.'
    }
    If ($Priority -in @('P1', 'P2', 'P3')) {
        $PriorityReason += ' 정적 안내이며 해당 호스트에 대한 적용 가능성의 증거가 아닙니다.'
    }

    Add-Member -InputObject $Finding -MemberType NoteProperty -Name Importance -Value $Importance -Force
    Add-Member -InputObject $Finding -MemberType NoteProperty -Name ImportanceReason -Value $ImportanceReason -Force
    Add-Member -InputObject $Finding -MemberType NoteProperty -Name RemediationPriority -Value $Priority -Force
    Add-Member -InputObject $Finding -MemberType NoteProperty -Name PriorityReason -Value $PriorityReason -Force
    Return $Finding
}
