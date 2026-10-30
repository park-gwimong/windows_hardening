# Private, presentation-only HTML support for HardeningKitty.SecurityAudit.psm1.

Function ConvertTo-SecurityAuditHtmlText {
    Param ($Value)

    If ($null -eq $Value -or [String]$Value -eq '') { Return '—' }
    Return [Net.WebUtility]::HtmlEncode([String]$Value)
}

Function ConvertTo-SecurityAuditHtml {
    Param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Object[]] $Findings
    )

    # Classes and attribute enums come only from these fixed, case-sensitive sets.
    $States = [ordered]@{
        Passed = @{ Label = '통과'; Class = 'passed'; Count = 0 }
        Failed = @{ Label = '개선 필요'; Class = 'failed'; Count = 0 }
        Unknown = @{ Label = '확인 필요'; Class = 'unknown'; Count = 0 }
        Error = @{ Label = '조회 오류'; Class = 'error'; Count = 0 }
        Info = @{ Label = '참고'; Class = 'info'; Count = 0 }
        NotApplicable = @{ Label = '대상 아님'; Class = 'not-applicable'; Count = 0 }
    }
    $Origins = @{
        Observed = @{ Label = '실제 조회'; Class = 'origin-observed' }
        Default = @{ Label = '목록 기본값 · 미조회'; Class = 'origin-default' }
        Unverified = @{ Label = '조회 확인 안 됨'; Class = 'origin-unverified' }
        Unavailable = @{ Label = '값 없음'; Class = 'origin-unavailable' }
        Reference = @{ Label = '참고 정보'; Class = 'origin-reference' }
    }
    $ImportanceLevels = [ordered]@{
        High = @{ Label = '높음'; Class = 'importance-high'; Count = 0; Definition = '접근·인증·자격증명·데이터 보호 등 직접적인 보안 통제의 중요도' }
        Medium = @{ Label = '보통'; Class = 'importance-medium'; Count = 0; Definition = '방어 계층·탐지·감사·정책 운영을 보완하는 통제의 중요도' }
        Low = @{ Label = '낮음'; Class = 'importance-low'; Count = 0; Definition = '주로 편의 기능·정보 노출 축소 등 보조 통제의 중요도' }
        Unrated = @{ Label = '미분류'; Class = 'importance-unrated'; Count = 0; Definition = '지원되는 중요도 근거가 없어 추정하지 않음. 낮은 위험이나 안전을 뜻하지 않음' }
        Reference = @{ Label = '참고 기록'; Class = 'importance-reference'; Count = 0; Definition = '범위·실행·날짜 등 등급을 부여하지 않는 기록. 낮은 위험이나 보안 통과를 뜻하지 않음' }
    }
    $Priorities = [ordered]@{
        P1 = @{ Label = '낮은 영향 후보'; Class = 'priority-p1'; Count = 0; Definition = '빠르게 설정할 수 있고 기능 영향이 비교적 적은 후보. 로그 공간·운영 조건 확인은 필요하며 무위험을 뜻하지 않음' }
        P2 = @{ Label = '영향 확인 후'; Class = 'priority-p2'; Count = 0; Definition = '로그량·권한 요청·암호 변경·기능 사용 여부를 확인한 뒤 조치' }
        P3 = @{ Label = '계획 변경'; Class = 'priority-p3'; Count = 0; Definition = '인증·인쇄·스크립트·암호화 등에 영향을 줄 수 있어 호환성 테스트와 복구 준비 후 조치. 보안 중요도가 낮다는 뜻이 아님' }
        Review = @{ Label = '재확인'; Class = 'priority-review'; Count = 0; Definition = '수집 근거·유효 설정·적용 대상·권장값 또는 조치 영향 확인이 먼저이며 일괄 변경에서 제외' }
        None = @{ Label = '현재 조치 없음'; Class = 'priority-none'; Count = 0; Definition = '통과·참고·대상 아님에 대한 분류. 참고나 대상 아님을 보안 통과로 간주하지 않음' }
    }
    $Lanes = [ordered]@{
        Action = @{ Slug = 'action'; Label = '조치 후보 검토'; Count = 0; Description = '실제 조회된 Failed 중 P1·P2·P3. 기본값 대체는 제외하며 변경 전 영향을 검토합니다.' }
        Review = @{ Slug = 'review'; Label = '증거·적용 재확인'; Count = 0; Description = '나머지 Failed와 모든 Unknown·Error. 수집 근거와 적용 가능성을 먼저 확인합니다.' }
        Record = @{ Slug = 'record'; Label = '판정 기록 확인'; Count = 0; Description = 'Passed·Info·NotApplicable. 참고와 대상 아님은 통과가 아니며 기록을 보존합니다.' }
    }
    $ReviewWorkloads = [ordered]@{
        Default = @{ Label = '기본값 대체 · 실측과 분리'; Description = '현재 설정을 관측한 값으로 해석하지 않습니다.'; Rows = [Collections.Generic.List[Object]]::new() }
        Applicability = @{ Label = 'Failed 재확인 · 적용·기준 검토'; Description = '실제 조회된 Failed이지만 조치 후보가 아닙니다. 행별 조치 분류 근거를 확인하세요.'; Rows = [Collections.Generic.List[Object]]::new() }
        Evidence = @{ Label = '수집·판정 근거 재확인'; Description = '조회 오류와 불충분한 증거를 구분해 확인합니다. 모두를 설정 실패로 해석하지 않습니다.'; Rows = [Collections.Generic.List[Object]]::new() }
    }
    $ReasonLabels = @{
        Compared = '원본 비교 완료 · 행별 검토 근거 확인'
        MissingResult = '원본 결과 누락'
        DuplicateResult = '동일 ID의 원본 결과 중복'
        MissingResultColumn = '원본 Result 열 누락'
        InvalidEngineVerdict = '원본 판정 형식 오류'
        UnknownDefaultFlag = '기본값 대체 여부 미확인'
        DefaultSubstitution = '목록 기본값으로 대체'
        UnverifiedAsrDefault = 'ASR 기본값 가능성 · 실측 미확인'
        CollectorMarker = '직접 판정할 수 없는 수집기 표시값'
        UnverifiedEmptyExport = '빈 권한 내보내기의 성공 근거 없음'
        InvalidNumericEvidence = '수치 비교 근거 부족'
        EmptyValue = '조회값 없음'
        ExecutionError = '원본 엔진 실행 오류'
        ExecutionIncomplete = '원본 엔진 완료 미확인'
        CollectionError = '수집 오류로 관측 신뢰 미확인'
    }
    $ImportanceOrder = @{ High = 0; Medium = 1; Low = 2; Unrated = 3; Reference = 4 }
    $PriorityOrder = @{ P1 = 0; P2 = 1; P3 = 2; Review = 3; None = 4 }
    $ReviewOrder = @{ Error = 0; Failed = 1; Unknown = 2 }
    $RecordOrder = @{ Passed = 0; Info = 1; NotApplicable = 2 }
    ForEach ($Key in $ImportanceLevels.Keys) {
        $ImportanceLevels[$Key].Cells = @{ Failed = 0; Unresolved = 0; Passed = 0; Reference = 0 }
    }

    # Each occurrence gets its own identity, including repeated references to one object.
    # Only wrappers are sorted; neither the input array nor its finding objects are changed.
    $IndexedFindings = [Collections.Generic.List[Object]]::new()
    $HighUnresolved = 0
    For ($Index = 0; $Index -lt $Findings.Count; $Index++) {
        $Finding = $Findings[$Index]
        If (@($States.Keys) -cnotcontains [String]$Finding.TestResult) {
            Throw "Unsupported audit result: $($Finding.TestResult)"
        }
        If (@($Origins.Keys) -cnotcontains [String]$Finding.ValueOrigin) {
            Throw "Unsupported audit value origin: $($Finding.ValueOrigin)"
        }
        If (@($ImportanceLevels.Keys) -cnotcontains [String]$Finding.Importance) {
            Throw "Unsupported audit importance: $($Finding.Importance)"
        }
        If (@($Priorities.Keys) -cnotcontains [String]$Finding.RemediationPriority) {
            Throw "Unsupported audit remediation priority: $($Finding.RemediationPriority)"
        }
        $UsedDefault = $Finding.UsedDefault -eq $true
        $InconsistentPriority = $false
        If ($Finding.RemediationPriority -cin @('P1', 'P2', 'P3')) {
            $InconsistentPriority = $Finding.TestResult -cne 'Failed' -or $Finding.ValueOrigin -cne 'Observed' -or
                $UsedDefault -or $Finding.Scope -in @('Context', 'Execution')
        } ElseIf ($Finding.TestResult -cin @('Unknown', 'Error')) {
            $InconsistentPriority = $Finding.RemediationPriority -cne 'Review'
        } ElseIf ($Finding.TestResult -cin @('Passed', 'Info', 'NotApplicable')) {
            $InconsistentPriority = $Finding.RemediationPriority -cne 'None'
        } ElseIf ($Finding.TestResult -ceq 'Failed') {
            $InconsistentPriority = $Finding.RemediationPriority -ceq 'None'
        }
        If ($InconsistentPriority) {
            Throw "Inconsistent audit remediation priority: $($Finding.RemediationPriority) for $($Finding.TestResult), $($Finding.ValueOrigin), scope $($Finding.Scope)."
        }
        $States[$Finding.TestResult].Count++
        $ImportanceLevels[$Finding.Importance].Count++
        $Priorities[$Finding.RemediationPriority].Count++
        $StatusGroup = 'Reference'
        Switch -CaseSensitive ($Finding.TestResult) {
            'Failed' { $StatusGroup = 'Failed' }
            'Unknown' { $StatusGroup = 'Unresolved' }
            'Error' { $StatusGroup = 'Unresolved' }
            'Passed' { $StatusGroup = 'Passed' }
        }
        $ImportanceLevels[$Finding.Importance].Cells[$StatusGroup]++
        If ($Finding.Importance -ceq 'High' -and $Finding.TestResult -cin @('Failed', 'Unknown', 'Error')) {
            $HighUnresolved++
        }

        $Lane = 'Record'
        If ($Finding.TestResult -cin @('Failed', 'Unknown', 'Error')) {
            $Lane = 'Review'
            If ($Finding.TestResult -ceq 'Failed' -and $Finding.RemediationPriority -cin @('P1', 'P2', 'P3') -and
                $Finding.ValueOrigin -ceq 'Observed' -and -not $UsedDefault) {
                $Lane = 'Action'
            }
        }
        $Item = [PSCustomObject]@{ Index = $Index; Finding = $Finding; ReviewLane = $Lane; ShowTarget = $false }
        [void]$IndexedFindings.Add($Item)
        $Lanes[$Lane].Count++
        If ($Lane -ceq 'Review') {
            $Workload = 'Evidence'
            If ($UsedDefault -or $Finding.ValueOrigin -ceq 'Default' -or $Finding.ReasonCode -ceq 'DefaultSubstitution') {
                $Workload = 'Default'
            } ElseIf ($Finding.TestResult -ceq 'Failed' -and $Finding.ValueOrigin -ceq 'Observed') {
                $Workload = 'Applicability'
            }
            [void]$ReviewWorkloads[$Workload].Rows.Add($Item)
        }
    }
    # Repeated visible IDs need a target before expanding account-specific evidence.
    ForEach ($Group in @($IndexedFindings | Group-Object -Property { "$($_.Finding.Scope) / $($_.Finding.ID)" })) {
        If ($Group.Count -gt 1) {
            ForEach ($Item in $Group.Group) { $Item.ShowTarget = $true }
        }
    }

    $Summary = '자동 판정 대상이 없습니다.'
    If ($Findings.Count -eq 0) {
        $Summary = '점검 결과가 없습니다.'
    } ElseIf ($States.Failed.Count -gt 0 -or $States.Error.Count -gt 0) {
        $Summary = '개선 또는 재점검이 필요합니다.'
    } ElseIf ($States.Unknown.Count -gt 0) {
        $Summary = '확인되지 않은 항목이 있습니다.'
    } ElseIf ($States.Passed.Count -gt 0) {
        $Summary = '평가된 항목이 기준을 충족합니다.'
    }

    $ContextFinding = $Findings | Where-Object { $_.Scope -ceq 'Context' -and $_.ID -ceq 'CTX-01' } | Select-Object -First 1
    $Computer = '—'
    $User = '—'
    $CheckedAt = '—'
    $AuditScope = '—'
    If ($null -ne $ContextFinding) {
        $Computer = ConvertTo-SecurityAuditHtmlText -Value $ContextFinding.Result
        $User = ConvertTo-SecurityAuditHtmlText -Value $ContextFinding.Target
        $CheckedAt = ConvertTo-SecurityAuditHtmlText -Value $ContextFinding.CheckedAt
        $AuditScope = ConvertTo-SecurityAuditHtmlText -Value $ContextFinding.Details
    }
    $Html = New-Object Text.StringBuilder
    [void]$Html.AppendLine(@"
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'" />
<title>HardeningKitty 시스템 보안 점검 보고서</title>
<style>
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; background: #f1f5f9; color: #1e293b; font: 14px/1.65 system-ui, "Malgun Gothic", sans-serif; overflow-wrap: anywhere; }
main { max-width: 1180px; margin: 0 auto; padding: 24px; }
header, .report-section { min-width: 0; margin: 0 0 20px; padding: 24px; border: 1px solid #dce3ec; border-radius: 10px; background: #fff; }
header { border-top: 5px solid #142d4e; }
h1, h2, h3, h4 { color: #142d4e; line-height: 1.4; }
h1 { font-size: 28px; margin: 3px 0 18px; letter-spacing: -.03em; }
h2 { font-size: 21px; margin: 0 0 12px; }
h3 { font-size: 16px; margin: 22px 0 10px; }
h4 { font-size: 14px; margin: 0 0 8px; }
p { margin: 0 0 10px; }
a { color: #214f82; text-underline-offset: 3px; }
a:hover { color: #0b2c55; }
a:focus-visible, summary:focus-visible { outline: 3px solid #365f98; outline-offset: 3px; }
strong { font-weight: 700; font-variant-numeric: tabular-nums; }
.eyebrow { margin: 0; color: #52677e; font-size: 10px; font-weight: 700; letter-spacing: .13em; }
.metadata { display: grid; grid-template-columns: auto minmax(0, 1fr) auto minmax(0, 1fr); gap: 5px 16px; margin: 0; font-size: 12px; }
dt { color: #526175; font-weight: 600; }
dd { min-width: 0; margin: 0; }
.metadata dd:last-child { grid-column: span 3; }
.contents { display: flex; flex-wrap: wrap; gap: 8px 20px; margin-top: 18px; padding-top: 14px; border-top: 1px solid #e2e8f0; font-size: 13px; }
.section-intro, .section-count { color: #526175; }
.section-intro { font-size: 13px; }
.section-count { font-size: 13px; font-weight: 400; }
.review-lanes { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin: 18px 0 14px; }
.review-lane { min-width: 0; padding: 14px 16px; border: 1px solid #dce3ec; border-top: 3px solid #274969; border-radius: 6px; }
.review-lane > a { display: block; font-weight: 650; }
.review-lane > strong { display: block; color: #142d4e; font-size: 32px; line-height: 1.4; }
.review-lane > p { margin: 3px 0 0; color: #526175; font-size: 12px; }
.verdict-strip, .priority-totals { display: flex; flex-wrap: wrap; gap: 5px 12px; margin: 12px 0; padding: 10px 0; list-style: none; border-top: 1px solid #e2e8f0; border-bottom: 1px solid #e2e8f0; }
.verdict-strip li, .priority-totals li { display: flex; align-items: baseline; gap: 6px; min-width: 0; font-size: 12px; }
.verdict-strip strong, .priority-totals strong { color: #142d4e; font-size: 16px; }
.verdict-strip small { color: #526175; font-size: 10px; }
.high-unresolved { margin: 12px 0 0; padding: 10px 12px; border-left: 3px solid #815341; background: #faf7f4; font-size: 12px; }
.high-unresolved strong { color: #784331; font-size: 18px; }
.importance-matrix { width: 100%; table-layout: fixed; border-collapse: collapse; font-size: 13px; }
.importance-matrix caption { color: #526175; text-align: left; padding: 0 0 10px; font-size: 12px; }
.importance-matrix th, .importance-matrix td { padding: 10px 8px; border-bottom: 1px solid #e2e8f0; text-align: center; }
.importance-matrix thead th { background: #f4f7fb; color: #465971; font-size: 12px; }
.importance-matrix thead th:first-child { width: 32%; }
.importance-matrix th:first-child { text-align: left; }
.importance-matrix tbody th { font-weight: 400; }
.importance-matrix tbody th strong { margin-left: 8px; color: #142d4e; }
.importance-matrix td { font-variant-numeric: tabular-nums; }
.badge { display: inline-block; max-width: 100%; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; line-height: 1.6; }
.passed { color: #285744; background: #eef5f1; }
.failed { color: #913a37; background: #fbefed; }
.unknown { color: #755419; background: #faf4e5; }
.error { color: #794866; background: #f7eef4; }
.info { color: #345777; background: #edf3f9; }
.not-applicable { color: #596577; background: #f0f3f7; }
.importance-high { color: #863e35; background: #f8eeeb; }
.importance-medium { color: #6b561f; background: #f7f3e8; }
.importance-low { color: #345777; background: #eef3f9; }
.importance-unrated, .importance-reference { color: #596577; background: #f0f3f7; }
.priority-p1 { color: #285674; background: #edf4fa; }
.priority-p2 { color: #6f5525; background: #f7f2e8; }
.priority-p3 { color: #654b78; background: #f3eff8; }
.priority-review, .priority-none { color: #596577; background: #f0f3f7; }
.priority-totals { gap: 6px 20px; }
.priority-totals small { color: #526175; }
summary { cursor: pointer; }
summary::marker { color: #52677e; }
.action-group { margin: 8px 0; border: 1px solid #dce3ec; border-radius: 6px; }
.action-group > summary { padding: 12px 14px; color: #142d4e; font-weight: 650; }
.queue-count { margin-left: 8px; color: #526175; font-size: 12px; font-weight: 400; }
.action-list { margin: 0; padding: 0 16px 8px 36px; }
.action-list li { padding: 10px 0; border-top: 1px solid #e2e8f0; }
.queue-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 10px; align-items: start; text-decoration: none; }
.queue-text { min-width: 0; }
.queue-row:hover .queue-name { text-decoration: underline; }
.queue-id, .queue-target { display: block; color: #526175; font-size: 11px; }
.queue-name { font-weight: 600; }
.review-workloads { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; }
.review-workload { min-width: 0; padding: 12px; background: #f6f8fb; border-radius: 6px; }
.review-workload > p { color: #526175; font-size: 12px; }
.reason-list { list-style: none; margin: 0; padding: 0; font-size: 12px; }
.reason-list li { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; padding: 5px 0; border-top: 1px solid #e2e8f0; }
.reason-list li span { min-width: 0; }
.empty-state { margin: 10px 14px; color: #526175; font-size: 12px; }
.catalog-nav { display: flex; flex-wrap: wrap; gap: 8px 18px; font-size: 13px; }
.catalog-lane { min-width: 0; margin-top: 28px; }
.catalog-lane > h3 { padding-bottom: 9px; border-bottom: 2px solid #243e5b; }
.finding { min-width: 0; margin: 7px 0; border: 1px solid #dce3ec; border-radius: 6px; background: #fff; scroll-margin-top: 16px; }
.finding > summary { padding: 12px 14px; }
.finding-summary { display: inline-grid; width: calc(100% - 20px); grid-template-columns: minmax(0, 1fr) minmax(0, 390px); gap: 16px; vertical-align: top; }
.item-heading, .item-badges { min-width: 0; }
.item-id { display: block; color: #526175; font-size: 11px; }
.item-name { display: block; color: #142d4e; font-size: 14px; line-height: 1.5; }
.item-category { display: block; color: #526175; font-size: 11px; margin-top: 2px; }
.item-target { display: block; color: #345777; font-size: 11px; margin-top: 2px; }
.item-badges { display: flex; flex-wrap: wrap; align-content: center; justify-content: flex-end; align-items: flex-start; gap: 4px; }
.finding[open] > summary { background: #f6f8fb; border-bottom: 1px solid #dce3ec; }
.finding:target { border-color: #315f91; box-shadow: 0 0 0 2px #c2d5e9; }
.finding:target > summary { background: #eaf2fb; }
.finding-body { padding: 18px; }
.description, .importance-reason, .priority-reason, .collection-details, .target-value, .result-value, .criterion-value, .evidence dd { white-space: pre-wrap; overflow-wrap: anywhere; }
.field-label { display: block; color: #465971; font-size: 12px; font-weight: 650; }
.core-evidence, .evidence { display: grid; grid-template-columns: 128px minmax(0, 1fr); gap: 8px 16px; margin: 16px 0; }
.core-evidence dt, .evidence dt { font-size: 12px; }
.result-value { display: block; }
.value-origin { display: inline-block; margin: 6px 8px 0 0; padding: 2px 6px; border: 1px solid currentColor; border-radius: 4px; font-size: 11px; font-weight: 600; }
.origin-code { color: #526175; font-size: 11px; }
.origin-observed { color: #345777; background: #edf3f9; }
.origin-default, .origin-unverified { color: #755419; background: #faf4e5; }
.origin-unavailable, .origin-reference { color: #596577; background: #f0f3f7; }
.assessment-reasons { padding: 12px 0 0; border-top: 1px solid #e2e8f0; }
.assessment-reasons p { font-size: 13px; }
.evidence { font-size: 12px; }
.collection-evidence { margin-top: 14px; border-top: 1px solid #e2e8f0; }
.collection-evidence > summary { padding: 10px 0; color: #345777; font-size: 12px; font-weight: 600; }
.collection-body { min-width: 0; padding: 12px; background: #f6f8fb; }
.collection-details { margin: 0; font: 12px/1.75 ui-monospace, Consolas, "Malgun Gothic", monospace; }
.definitions > summary { color: #142d4e; font-weight: 700; font-size: 18px; }
.definitions-body { margin-top: 18px; font-size: 13px; }
.assessment-definitions { display: grid; grid-template-columns: 165px minmax(0, 1fr); gap: 8px 16px; margin: 12px 0; }
.scope-notes { padding-left: 20px; }
.scope-notes li { margin: 8px 0; }
footer { padding: 0 4px 16px; color: #526175; font-size: 11px; }
@media (max-width: 760px) {
    main { padding: 12px; }
    header, .report-section { padding: 18px; }
    h1 { font-size: 24px; }
    h2 { font-size: 19px; }
    .metadata { grid-template-columns: 76px minmax(0, 1fr); gap: 5px 10px; }
    .metadata dd:last-child { grid-column: auto; }
    .review-lanes, .review-workloads { grid-template-columns: minmax(0, 1fr); gap: 8px; }
    .review-lane { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: baseline; padding: 10px 12px; }
    .review-lane > strong { font-size: 26px; grid-column: 2; grid-row: 1; }
    .review-lane > p { grid-column: 1 / -1; }
    .finding-summary { grid-template-columns: minmax(0, 1fr); gap: 7px; }
    .item-badges { justify-content: flex-start; }
    .finding-body { padding: 14px; }
    .core-evidence, .evidence, .assessment-definitions { grid-template-columns: minmax(0, 1fr); gap: 3px; }
    .core-evidence dd, .evidence dd, .assessment-definitions dd { margin-bottom: 9px; }
    .importance-matrix th, .importance-matrix td { padding: 9px 4px; font-size: 12px; }
    .importance-matrix thead th { font-size: 11px; }
    .importance-matrix tbody th strong { display: block; margin: 2px 0 0; }
    .importance-matrix .badge { padding: 1px 4px; }
    .queue-row { grid-template-columns: minmax(0, 1fr); gap: 5px; }
    .queue-row > .badge { justify-self: start; }
}
@page { size: A4 portrait; margin: 14mm; }
@media print {
    body { background: #fff; color: #111827; font-size: 10pt; }
    main { max-width: none; padding: 0; }
    header, .report-section { margin: 0 0 12pt; padding: 10pt 0; border: 0; border-radius: 0; }
    h1 { font-size: 22pt; }
    h2 { font-size: 15pt; }
    h3 { font-size: 12pt; }
    h1, h2, h3, h4, dt { break-after: avoid; }
    .contents, .catalog-nav, .work-queues-screen, .screen-instruction { display: none !important; }
    .review-lanes { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .review-lane { display: block; padding: 8pt; }
    .review-lane > strong { font-size: 22pt; }
    .review-lane > p, .section-intro, .high-unresolved { font-size: 9pt; }
    a { color: inherit; text-decoration: none; }
    .catalog-lane, details, .finding-body, .collection-body, .assessment-reasons, .evidence, .evidence dd { break-inside: auto; page-break-inside: auto; }
    details { display: block !important; overflow: visible !important; }
    /* Modern closed-details content lives in this generated box. */
    details::details-content { display: block !important; content-visibility: visible !important; height: auto !important; block-size: auto !important; max-height: none !important; overflow: visible !important; }
    /* Direct-child fallback also covers engines without ::details-content. */
    details > :not(summary), details:not([open]) > :not(summary) { display: block !important; content-visibility: visible !important; height: auto !important; max-height: none !important; overflow: visible !important; }
    details > summary { display: block; cursor: default; break-after: avoid; }
    summary::marker, summary::-webkit-details-marker { display: none; }
    .finding { margin: 10pt 0; border: 0; border-top: 1pt solid #94a3b8; border-radius: 0; box-shadow: none; }
    .finding > summary, .finding[open] > summary, .finding:target > summary { padding: 8pt 0; background: #fff; border: 0; }
    .finding-summary { display: block; width: 100%; }
    .item-badges { justify-content: flex-start; margin-top: 5pt; }
    .item-target { display: none; }
    .finding-body { padding: 0 0 8pt; }
    .core-evidence, .evidence, .assessment-definitions { display: block; margin: 8pt 0; }
    .core-evidence dt, .evidence dt, .assessment-definitions dt { margin-top: 7pt; }
    .core-evidence dd, .evidence dd, .assessment-definitions dd { margin: 2pt 0 6pt; }
    .collection-body { background: #fff; padding: 0; }
    .collection-details, .evidence, .description, .assessment-reasons p { font-size: 9pt; }
    .collection-details { white-space: pre-wrap; overflow-wrap: anywhere; }
    .definitions-body { font-size: 9pt; }
    .importance-matrix tr, .review-lane { break-inside: avoid; }
}
</style>
</head>
<body>
<main>
<header>
<p class="eyebrow">HARDENINGKITTY / READ-ONLY SECURITY REVIEW</p>
<h1>시스템 보안 점검 보고서</h1>
<dl class="metadata">
<dt>컴퓨터</dt><dd>$Computer</dd>
<dt>점검 사용자</dt><dd>$User</dd>
<dt>점검 시작</dt><dd>$CheckedAt</dd>
<dt>점검 방식</dt><dd>읽기 전용 · 시스템 설정 및 비밀번호 변경 없음</dd>
<dt>점검 범위</dt><dd>$AuditScope</dd>
</dl>
<nav class="contents" aria-label="보고서 바로가기">
<a href="#summary-heading">검토 요약</a><a href="#importance-heading">중요도 × 판정</a><a href="#work-queues">검토 목록</a><a href="#catalog">전체 항목</a><a href="#definitions">정의·범위</a>
</nav>
</header>
<section class="report-section" aria-labelledby="summary-heading">
<h2 id="summary-heading">$Summary</h2>
<p class="section-intro">전체 <strong id="finding-total">$($Findings.Count)</strong>개 결과 행 · 범위·실행·참고 기록 포함. 아래 세 검토 흐름은 서로 겹치지 않으며 합계는 전체 행 수입니다.</p>
<div class="review-lanes">
"@)
    ForEach ($Key in $Lanes.Keys) {
        $Lane = $Lanes[$Key]
        [void]$Html.AppendLine("<div class=`"review-lane`" id=`"review-$($Lane.Slug)`"><a href=`"#catalog-$($Lane.Slug)`">$($Lane.Label)</a><strong>$($Lane.Count)</strong><p>$($Lane.Description)</p></div>")
    }
    [void]$Html.AppendLine('</div><ul class="verdict-strip" aria-label="전체 행의 판정별 수">')
    ForEach ($Key in $States.Keys) {
        $State = $States[$Key]
        [void]$Html.AppendLine("<li id=`"status-$($State.Class)`"><span class=`"badge $($State.Class)`">$($State.Label)</span><strong>$($State.Count)</strong><small>$Key</small></li>")
    }
    [void]$Html.AppendLine(@"
</ul>
<p class="high-unresolved">높은 중요도 미해결 <strong id="high-unresolved-count">$HighUnresolved</strong>개 · High이면서 Failed·Unknown·Error인 부분집합입니다. 위 흐름에 이미 포함된 중복 집계이며 높은 중요도 전체 수가 아닙니다.</p>
<p class="section-intro">Unknown·Error·기본값 대체는 통과나 자동 변경 후보가 아닙니다. 행 수는 반복 점검을 포함하므로 서로 다른 조치 작업 수가 아닙니다.</p>
</section>
<section class="report-section" aria-labelledby="importance-heading">
<h2 id="importance-heading">중요도 × 판정</h2>
<p class="section-intro">중요도는 보안 통제의 의미이고, 조치 우선순위는 변경 영향과 검토 순서입니다. 중요도가 높아도 재확인이나 계획 변경이 필요할 수 있습니다.</p>
<table class="importance-matrix">
<caption>전체 결과 행의 교차 집계 · 각 행의 네 판정 그룹 합계가 해당 중요도 전체 수입니다. 참고 기록과 미분류를 낮은 위험으로 해석하지 않습니다.</caption>
<thead><tr><th scope="col">중요도 / 전체 수</th><th scope="col">개선 필요<br />Failed</th><th scope="col">확인·오류<br />Unknown + Error</th><th scope="col">통과<br />Passed</th><th scope="col">참고·대상 아님<br />Info + NA</th></tr></thead>
<tbody>
"@)
    ForEach ($Key in $ImportanceLevels.Keys) {
        $Level = $ImportanceLevels[$Key]
        [void]$Html.AppendLine("<tr><th scope=`"row`" id=`"count-$($Level.Class)`"><span class=`"badge $($Level.Class)`">$($Level.Label) · $Key</span><strong>$($Level.Count)</strong></th>")
        ForEach ($Group in @('Failed', 'Unresolved', 'Passed', 'Reference')) {
            [void]$Html.AppendLine("<td data-status-group=`"$Group`">$($Level.Cells[$Group])</td>")
        }
        [void]$Html.AppendLine('</tr>')
    }
    [void]$Html.AppendLine(@'
</tbody></table>
</section>
<section class="report-section" id="work-queues" aria-labelledby="priority-heading">
<h2 id="priority-heading">조치 분류와 검토 목록</h2>
<p class="section-intro">아래 분류 합계는 <strong>전체 행</strong> 기준이며 공급된 조치 분류를 그대로 집계합니다. Failed 전용 목록이나 조치 후보 흐름의 수와 혼동하지 마세요.</p>
<ul class="priority-totals" aria-label="전체 행의 조치 분류별 수">
'@)
    ForEach ($Key in $Priorities.Keys) {
        $Priority = $Priorities[$Key]
        [void]$Html.AppendLine("<li id=`"count-$($Priority.Class)`"><span class=`"badge $($Priority.Class)`">$Key</span><strong>$($Priority.Count)</strong><small>$($Priority.Label)</small></li>")
    }
    [void]$Html.AppendLine(@"
</ul>
<div class="work-queues-screen">
<h3>Failed 전용 검토 목록 <span class="section-count">$($States.Failed.Count)개 행</span></h3>
<p class="section-intro">모든 Failed 행을 원래 조치 분류별로 한 번씩 표시합니다. Unknown·Error는 포함하지 않으며 같은 순위에서는 중요도순입니다. P1·P2·P3는 기본값이 아닌 실제 조회 근거가 있는 후보일 뿐 변경 승인이 아닙니다. 링크를 누른 뒤 항목 요약을 클릭해 근거를 펼치세요.</p>
"@)
    ForEach ($Key in @('P1', 'P2', 'P3', 'Review')) {
        $Priority = $Priorities[$Key]
        $Actions = @($IndexedFindings | Where-Object { $_.Finding.TestResult -ceq 'Failed' -and $_.Finding.RemediationPriority -ceq $Key } |
            Sort-Object @{ Expression = { $ImportanceOrder[$_.Finding.Importance] } }, Index)
        $Open = ''
        If ($Key -ceq 'P1') { $Open = ' open="open"' }
        [void]$Html.AppendLine("<details class=`"action-group`" id=`"actions-$Key`"$Open><summary>$Key · $($Priority.Label)<span class=`"queue-count`">Failed $($Actions.Count)개 행</span></summary><ol class=`"action-list`">")
        ForEach ($Item in $Actions) {
            $Finding = $Item.Finding
            $FindingIndex = $Item.Index
            $QueueID = [Net.WebUtility]::HtmlEncode("$($Finding.Scope) / $($Finding.ID)")
            $QueueName = [Net.WebUtility]::HtmlEncode([String]$Finding.Name)
            $QueueTarget = ConvertTo-SecurityAuditHtmlText -Value $Finding.Target
            $Importance = ConvertTo-SecurityAuditHtmlText -Value $Finding.Importance
            $Level = $ImportanceLevels[$Finding.Importance]
            [void]$Html.AppendLine("<li data-priority=`"$Key`" data-importance=`"$Importance`"><a class=`"queue-row`" href=`"#finding-$FindingIndex`"><span class=`"queue-text`"><span class=`"queue-id`">$QueueID</span><span class=`"queue-name`">$QueueName</span><span class=`"queue-target`">$QueueTarget</span></span><span class=`"badge $($Level.Class)`">중요도 $($Level.Label)</span></a></li>")
        }
        [void]$Html.AppendLine('</ol>')
        If ($Actions.Count -eq 0) { [void]$Html.AppendLine('<p class="empty-state">해당 Failed 행이 없습니다.</p>') }
        [void]$Html.AppendLine('</details>')
    }
    [void]$Html.AppendLine(@"
</div>
<h3>재확인 흐름의 사유별 업무량 <span class="section-count">$($Lanes.Review.Count)개 행</span></h3>
<p class="section-intro">위 Failed 재확인 목록과 모든 Unknown·Error 등을 합친 재확인 흐름을 세 업무로 나눴습니다. 서로 겹치지 않는 행 집계이며 독립적인 수정 작업 수는 아닙니다. 제품·백신 적용 여부를 추정하지 않습니다.</p>
<div class="review-workloads">
"@)
    ForEach ($Key in $ReviewWorkloads.Keys) {
        $Workload = $ReviewWorkloads[$Key]
        [void]$Html.AppendLine("<div class=`"review-workload`" data-review-workload=`"$Key`"><h4>$($Workload.Label) · $($Workload.Rows.Count)</h4><p>$($Workload.Description)</p><ul class=`"reason-list`">")
        $Reasons = @($Workload.Rows | Group-Object -Property { [String]$_.Finding.ReasonCode } | Sort-Object @{ Expression = { $_.Count }; Descending = $true }, Name)
        ForEach ($Reason in $Reasons) {
            $Code = [String]$Reason.Name
            $ReasonLabel = '사유 코드 없음 · 행별 근거 확인'
            If ($ReasonLabels.ContainsKey($Code)) {
                $ReasonLabel = $ReasonLabels[$Code]
            } ElseIf (-not [String]::IsNullOrWhiteSpace($Code)) {
                $ReasonLabel = "기타 사유 · $Code"
            }
            $ReasonLabel = ConvertTo-SecurityAuditHtmlText -Value $ReasonLabel
            [void]$Html.AppendLine("<li><span>$ReasonLabel</span><strong>$($Reason.Count)</strong></li>")
        }
        [void]$Html.AppendLine('</ul></div>')
    }
    [void]$Html.AppendLine(@'
</div>
<p class="section-intro"><a href="#catalog-review">재확인 전체 항목으로 이동</a> · 각 행의 원본 판정·수집 근거·조치 분류 근거에서 판단 이유를 확인하세요.</p>
</section>
<section class="report-section" id="catalog" aria-labelledby="catalog-heading">
<h2 id="catalog-heading">전체 점검 항목</h2>
<p class="section-intro">입력된 모든 행을 한 번씩 보존합니다. 같은 ID·대상 또는 같은 객체가 반복되어도 별도 항목입니다. 조치 후보는 P1→P2→P3 후 중요도순, 재확인은 중요도 후 Error→Failed→Unknown순, 기록은 Passed→Info→NotApplicable순입니다. 동률은 원래 행 순서입니다.</p>
<p class="section-intro screen-instruction">각 항목의 <strong>요약을 클릭하면 전체 근거가 펼쳐집니다.</strong> 링크로 이동한 항목은 테두리로 강조됩니다. 상세 수집 근거도 별도로 펼칠 수 있으며 원문을 생략하지 않습니다.</p>
<nav class="catalog-nav" aria-label="전체 항목 검토 흐름">
<a href="#catalog-action">조치 후보</a><a href="#catalog-review">재확인</a><a href="#catalog-record">판정 기록</a>
</nav>
'@)
    ForEach ($Key in $Lanes.Keys) {
        $Lane = $Lanes[$Key]
        $Items = @($IndexedFindings | Where-Object { $_.ReviewLane -ceq $Key })
        Switch -CaseSensitive ($Key) {
            'Action' { $Items = @($Items | Sort-Object @{ Expression = { $PriorityOrder[$_.Finding.RemediationPriority] } }, @{ Expression = { $ImportanceOrder[$_.Finding.Importance] } }, Index) }
            'Review' { $Items = @($Items | Sort-Object @{ Expression = { $ImportanceOrder[$_.Finding.Importance] } }, @{ Expression = { $ReviewOrder[$_.Finding.TestResult] } }, Index) }
            'Record' { $Items = @($Items | Sort-Object @{ Expression = { $RecordOrder[$_.Finding.TestResult] } }, Index) }
        }
        [void]$Html.AppendLine("<section class=`"catalog-lane`" id=`"catalog-$($Lane.Slug)`" aria-labelledby=`"catalog-$($Lane.Slug)-heading`"><h3 id=`"catalog-$($Lane.Slug)-heading`">$($Lane.Label) <span class=`"section-count`">$($Items.Count)개 행</span></h3>")
        If ($Items.Count -eq 0) { [void]$Html.AppendLine('<p class="empty-state">이 흐름에 해당하는 결과가 없습니다.</p>') }
        ForEach ($Item in $Items) {
            $Finding = $Item.Finding
            $FindingIndex = $Item.Index
            $State = $States[$Finding.TestResult]
            $Origin = $Origins[$Finding.ValueOrigin]
            $Level = $ImportanceLevels[$Finding.Importance]
            $Priority = $Priorities[$Finding.RemediationPriority]
            $Status = ConvertTo-SecurityAuditHtmlText -Value $Finding.TestResult
            $Importance = ConvertTo-SecurityAuditHtmlText -Value $Finding.Importance
            $RemediationPriority = ConvertTo-SecurityAuditHtmlText -Value $Finding.RemediationPriority
            $ValueOrigin = ConvertTo-SecurityAuditHtmlText -Value $Finding.ValueOrigin
            $ID = [Net.WebUtility]::HtmlEncode([String]$Finding.ID)
            $FindingScope = [Net.WebUtility]::HtmlEncode([String]$Finding.Scope)
            $Name = [Net.WebUtility]::HtmlEncode([String]$Finding.Name)
            $Category = [Net.WebUtility]::HtmlEncode([String]$Finding.Category)
            $Description = [Net.WebUtility]::HtmlEncode([String]$Finding.Description)
            $Target = ConvertTo-SecurityAuditHtmlText -Value $Finding.Target
            $Result = ConvertTo-SecurityAuditHtmlText -Value $Finding.Result
            If ($Finding.ValueOrigin -ceq 'Observed' -and $Finding.Result -is [String] -and $Finding.Result -eq '') {
                $Result = '(빈 값)'
            }
            $Recommended = ConvertTo-SecurityAuditHtmlText -Value $Finding.Recommended
            $Details = ConvertTo-SecurityAuditHtmlText -Value $Finding.Details
            $Source = ConvertTo-SecurityAuditHtmlText -Value $Finding.Source
            $Time = ConvertTo-SecurityAuditHtmlText -Value $Finding.CheckedAt
            $List = ConvertTo-SecurityAuditHtmlText -Value $Finding.List
            $Severity = ConvertTo-SecurityAuditHtmlText -Value $Finding.Severity
            $EngineStatus = ConvertTo-SecurityAuditHtmlText -Value $Finding.EngineTestResult
            $DefaultValue = ConvertTo-SecurityAuditHtmlText -Value $Finding.UsedDefault
            $ReasonCode = ConvertTo-SecurityAuditHtmlText -Value $Finding.ReasonCode
            $ImportanceReason = [Net.WebUtility]::HtmlEncode([String]$Finding.ImportanceReason)
            $PriorityReason = [Net.WebUtility]::HtmlEncode([String]$Finding.PriorityReason)
            $TargetPreview = ''
            If ($Item.ShowTarget) { $TargetPreview = "<span class=`"item-target`">$Target</span>" }
            [void]$Html.AppendLine(@"
<details class="finding" id="finding-$FindingIndex" data-status="$Status" data-importance="$Importance" data-priority="$RemediationPriority" data-origin="$ValueOrigin" data-review="$Key">
<summary><span class="finding-summary"><span class="item-heading"><span class="item-id">$FindingScope / $ID</span><strong class="item-name">$Name</strong><span class="item-category">$Category</span>$TargetPreview</span><span class="item-badges"><span class="badge $($State.Class)">판정 $($State.Label) ($Status)</span><span class="badge $($Level.Class)">중요도 $($Level.Label) ($Importance)</span><span class="badge $($Priority.Class)">조치 $RemediationPriority · $($Priority.Label)</span></span></span></summary>
<div class="finding-body">
<p class="description"><span class="field-label">점검 내용</span>$Description</p>
<dl class="core-evidence">
<dt>전체 대상</dt><dd class="target-value">$Target</dd>
<dt>원본 값</dt><dd><span class="result-value">$Result</span><span class="value-origin $($Origin.Class)">$($Origin.Label)</span><span class="origin-code">ValueOrigin: $ValueOrigin</span></dd>
<dt>판정 기준</dt><dd class="criterion-value">$Recommended</dd>
</dl>
<div class="assessment-reasons"><p class="importance-reason"><span class="field-label">중요도 근거</span>$ImportanceReason</p><p class="priority-reason"><span class="field-label">조치 분류 근거</span>$PriorityReason</p></div>
<dl class="evidence">
<dt>출처</dt><dd data-field="Source">$Source</dd>
<dt>점검 시각</dt><dd data-field="CheckedAt">$Time</dd>
<dt>기준 목록</dt><dd data-field="List">$List</dd>
<dt>원본 중요도</dt><dd data-field="Severity">$Severity</dd>
<dt>원본 판정</dt><dd data-field="EngineTestResult">$EngineStatus</dd>
<dt>기본값 대체</dt><dd data-field="UsedDefault">$DefaultValue</dd>
<dt>사유 코드</dt><dd data-field="ReasonCode">$ReasonCode</dd>
</dl>
<details class="collection-evidence"><summary>상세 수집 근거 · 원문 전체</summary><div class="collection-body"><p class="collection-details">$Details</p></div></details>
</div>
</details>
"@)
        }
        [void]$Html.AppendLine('</section>')
    }
    [void]$Html.AppendLine(@'
</section>
<section class="report-section" aria-label="정의와 점검 범위">
<details class="definitions" id="definitions">
<summary>판정 정의·집계 기준·점검 범위</summary>
<div class="definitions-body">
<h3>서로 다른 세 가지 판단</h3>
<p><strong>판정</strong>은 이번 수집 근거와 기준의 비교 결과, <strong>중요도</strong>는 통제의 보안상 의미, <strong>조치 분류</strong>는 변경 영향과 확인 순서입니다. 어떤 분류도 실제 침해 발생이나 자동 변경 승인을 뜻하지 않습니다. 준수율·위험 점수를 계산하지 않습니다.</p>
<p>Passed만 해당 기준의 통과입니다. Failed는 개선 필요, Unknown은 확인 필요, Error는 조회 오류이며 이들을 같은 실패로 합치지 않습니다. Info와 NotApplicable은 통과가 아닙니다. 높은 중요도 미해결은 High 중 Failed·Unknown·Error인 부분집합으로 다른 집계와 겹칩니다.</p>
<p>세 검토 흐름은 표시를 위한 분류일 뿐 원본 판정을 바꾸지 않습니다. 조치 후보는 Failed + P1/P2/P3 + Observed이며 UsedDefault=true인 행을 제외합니다. 나머지 Failed와 Unknown·Error는 재확인, Passed·Info·NotApplicable은 판정 기록입니다. 반복된 점검 행을 병합하거나 서로 다른 변경 작업으로 추정하지 않습니다.</p>
<h3>보안 중요도</h3>
<p>기준 목록 항목은 원본 Severity의 High / Medium / Low를 표시하며 목록 작성자의 판단을 호스트의 위험 점수로 재계산하지 않습니다. 보완 항목은 명시된 통제 목적을 따릅니다. 미분류와 참고 기록은 낮은 위험 등급이 아닙니다.</p>
<dl class="assessment-definitions">
'@)
    ForEach ($Key in $ImportanceLevels.Keys) {
        $Level = $ImportanceLevels[$Key]
        [void]$Html.AppendLine("<dt>$($Level.Label) ($Key)</dt><dd>$($Level.Definition)</dd>")
    }
    [void]$Html.AppendLine('</dl><h3>조치 분류</h3><dl class="assessment-definitions">')
    ForEach ($Key in $Priorities.Keys) {
        $Priority = $Priorities[$Key]
        [void]$Html.AppendLine("<dt>$Key · $($Priority.Label)</dt><dd>$($Priority.Definition)</dd>")
    }
    [void]$Html.AppendLine(@'
</dl>
<h3>수집 구분과 원본 근거</h3>
<p>‘실제 조회’(Observed)와 ‘목록 기본값 · 미조회’(Default)를 구분하세요. 기본값은 현재 설정을 조회한 값이 아니며 ‘조회 확인 안 됨’(Unverified)도 확인된 현재 설정으로 해석하지 않습니다. ‘값 없음’(Unavailable)은 누락, ‘참고 정보’(Reference)는 범위·실행 안내입니다. 기본값 대체 여부와 사유 코드는 각 행에 원문으로 남깁니다.</p>
<p>‘—’는 값이 없거나 비어 있음을 표시합니다. 실제 조회된 문자열의 빈 값은 ‘(빈 값)’으로 구별합니다. 원본 Result·판정 기준·판정·출처·수집 시각·기본값 여부·분류 근거는 표시를 위해 인코딩할 뿐 다시 판정하거나 덮어쓰지 않습니다.</p>
<h3>점검 범위와 해석의 한계</h3>
<ul class="scope-notes">
<li>머신·현재 사용자 기준 목록과 추가 화면 보호기·비밀번호 점검을 함께 표시합니다. 모든 보안 위협을 탐지하거나 OS 버전·업무 환경별 적용 가능성을 자동 확정하는 보고서는 아닙니다.</li>
<li>전체 목록 실행의 수집 오류로 비교를 신뢰할 수 없었던 항목은 같은 원본 Audit 엔진으로 ID별 재점검합니다. 오류·기본값 대체·ASR 모호성 없이 확인된 항목만 통과 또는 개선 필요로 판정하며 항목별 시각은 해당 수집 시점입니다. 원본 판정과 사유 코드는 상세 근거에 남습니다.</li>
<li>성공이 확인되지 않은 빈 권한 내보내기는 ‘권한 없음’으로 단정하지 않습니다. 정상 조회된 빈 Defender 제외 목록과 달리 확인 필요로 남깁니다.</li>
<li>적용 가능성·권장값 해석 문제와 수집 실패를 구분하세요. NOTSET 완화 설정의 유효 동작, Defender 실행 상태의 적용 여부, User / 4505의 DisableAutoplay = 0 기준 해석은 행별 근거를 먼저 확인해야 합니다. 자동재생 해제 지시로 바꾸지 않으며 호스트의 백신 제품이나 안전 여부를 추정하지 않습니다.</li>
<li>화면 보호기는 실행 사용자의 HKCU 설정을 점검합니다. 다른 사용자 프로필이나 실제 화면 잠금 동작까지 검증하지는 않습니다.</li>
<li>복잡도는 정책 설정 점검이며 기존 비밀번호의 강도나 Windows Hello PIN을 검사하지 않습니다.</li>
<li>Microsoft 계정·Entra ID·도메인 계정의 온라인 비밀번호 변경일과 정책은 해당 인증 공급자에서 별도로 확인해야 합니다.</li>
<li>헤더의 점검 시작은 Context / CTX-01의 기록입니다. 각 항목의 점검 시각은 개별 수집 기록이므로 같다고 가정하지 않습니다. 날짜는 기록된 시간대 오프셋을 유지합니다. 경과일은 호스트 시계 기준이며 인증된 사건 발생 시각을 의미하지 않습니다.</li>
<li>판정 기준은 이번 실행에 사용한 기준입니다. 조직 정책과 실제 운영 조건을 확인하고 확인되지 않은 값은 재점검하세요.</li>
</ul>
<h3>오프라인 열람과 인쇄</h3>
<p>외부 리소스나 스크립트 없이 열람할 수 있습니다. 인쇄 스타일은 접힌 항목과 중첩된 수집 근거, 이 정의를 모두 표시하고 중복 검토 목록·탐색 링크를 숨깁니다. 긴 진단 원문은 여러 페이지에 이어집니다. 브라우저별 details 인쇄 지원 차이가 있으므로 저장 전 인쇄 미리보기에서 전체 근거가 보이는지 확인하세요.</p>
</div>
</details>
</section>
<footer>계정 식별자와 보안 설정이 포함된 보고서입니다. 접근을 제한하여 보관하세요. 읽기 전용 점검 결과이며 변경 작업을 실행하지 않습니다.</footer>
</main>
</body>
</html>
'@)
    Return $Html.ToString()
}
