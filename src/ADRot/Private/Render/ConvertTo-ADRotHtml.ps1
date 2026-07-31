Set-StrictMode -Version Latest

function ConvertTo-ADRotHtml {
    <#
    .SYNOPSIS
        Renders a scan result as a single self-contained HTML document.
    .DESCRIPTION
        The output has no external references of any kind — no CDN, no webfont, no
        remote image. That is deliberate: the report describes the security posture of a
        domain, it gets emailed to auditors and opened on locked-down management
        workstations, and it must never phone home or leak the domain name through a
        font request.

        Every value interpolated from directory data is HTML-encoded. Directory
        attributes are attacker-influenceable (a samAccountName can contain markup), so
        encoding is a security control here, not cosmetics.
    .PARAMETER Result
        The scan result from Invoke-ADRotScan.
    .OUTPUTS
        System.String — the complete HTML document.
    .EXAMPLE
        ConvertTo-ADRotHtml -Result $result | Set-Content report.html
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $Result
    )

    function Protect-Html {
        param([AllowNull()] $Value)
        if ($null -eq $Value) { return '' }
        return [System.Net.WebUtility]::HtmlEncode([string] $Value)
    }

    $score = $Result.Score
    $gradeClass = "grade-$($score.Grade.ToLowerInvariant())"
    $domainName = Protect-Html $Result.Domain.dnsRoot
    if (-not $domainName) { $domainName = '(unknown domain)' }

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>ADRot report — $domainName</title>
<style>
  :root {
    --bg:#f7f8fa; --panel:#ffffff; --ink:#14161a; --muted:#5c6470; --line:#e3e6ea;
    --crit:#b3001b; --high:#d64500; --med:#a67500; --low:#0a6c9e;
    --ok:#1a7f45; --accent:#2d4a8a;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg:#111317; --panel:#181b21; --ink:#e8eaed; --muted:#98a1ae; --line:#2a2f38;
      --crit:#ff5f6d; --high:#ff9248; --med:#f0c04a; --low:#5cc2f0;
      --ok:#4ad98a; --accent:#7ea3ff;
    }
  }
  * { box-sizing:border-box; }
  body {
    margin:0; padding:2rem 1rem 4rem; background:var(--bg); color:var(--ink);
    font:15px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }
  .wrap { max-width:1080px; margin:0 auto; }
  header { display:flex; flex-wrap:wrap; gap:1.5rem; align-items:center; justify-content:space-between; margin-bottom:2rem; }
  h1 { font-size:1.5rem; margin:0 0 .25rem; letter-spacing:-.01em; }
  .sub { color:var(--muted); font-size:.875rem; }
  .gauge {
    display:flex; flex-direction:column; align-items:center; justify-content:center;
    width:120px; height:120px; border-radius:50%; border:6px solid var(--line);
    background:var(--panel); flex:none;
  }
  .gauge .n { font-size:2.1rem; font-weight:700; line-height:1; }
  .gauge .g { font-size:.75rem; color:var(--muted); text-transform:uppercase; letter-spacing:.08em; margin-top:.25rem; }
  .grade-a { border-color:var(--ok); } .grade-b { border-color:var(--ok); }
  .grade-c { border-color:var(--med); } .grade-d { border-color:var(--high); }
  .grade-f { border-color:var(--crit); }
  .tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:.75rem; margin-bottom:2rem; }
  .tile { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:.85rem 1rem; }
  .tile .k { font-size:.7rem; text-transform:uppercase; letter-spacing:.07em; color:var(--muted); }
  .tile .v { font-size:1.5rem; font-weight:650; margin-top:.15rem; }
  .v.crit { color:var(--crit); } .v.high { color:var(--high); }
  .v.med  { color:var(--med);  } .v.low  { color:var(--low);  } .v.ok { color:var(--ok); }
  details.finding {
    background:var(--panel); border:1px solid var(--line); border-left-width:4px;
    border-radius:10px; margin-bottom:.75rem; overflow:hidden;
  }
  details.sev-Critical { border-left-color:var(--crit); }
  details.sev-High     { border-left-color:var(--high); }
  details.sev-Medium   { border-left-color:var(--med);  }
  details.sev-Low      { border-left-color:var(--low);  }
  summary { cursor:pointer; padding:.85rem 1rem; display:flex; flex-wrap:wrap; gap:.6rem; align-items:baseline; }
  summary::-webkit-details-marker { display:none; }
  .badge {
    font-size:.66rem; font-weight:700; letter-spacing:.06em; text-transform:uppercase;
    padding:.2rem .45rem; border-radius:4px; color:#fff; flex:none;
  }
  .badge.Critical { background:var(--crit); } .badge.High { background:var(--high); }
  .badge.Medium   { background:var(--med); color:#1a1a1a; } .badge.Low { background:var(--low); }
  .rid { font:12px ui-monospace,SFMono-Regular,Consolas,monospace; color:var(--muted); flex:none; }
  .ftitle { font-weight:600; flex:1 1 20rem; }
  .count { color:var(--muted); font-size:.8rem; flex:none; }
  .body { padding:0 1rem 1rem; border-top:1px solid var(--line); }
  .body h4 { margin:1rem 0 .35rem; font-size:.72rem; text-transform:uppercase; letter-spacing:.07em; color:var(--muted); }
  .body p { margin:0; }
  .scroll { overflow-x:auto; }
  table { border-collapse:collapse; width:100%; font-size:.85rem; margin-top:.35rem; }
  th, td { text-align:left; padding:.4rem .6rem; border-bottom:1px solid var(--line); vertical-align:top; }
  th { font-size:.7rem; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); }
  td.dn { font:12px ui-monospace,SFMono-Regular,Consolas,monospace; color:var(--muted); word-break:break-all; }
  a { color:var(--accent); }
  .empty { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:2.5rem 1rem; text-align:center; }
  .empty .big { font-size:1.15rem; font-weight:600; color:var(--ok); }
  footer { margin-top:2.5rem; padding-top:1rem; border-top:1px solid var(--line); color:var(--muted); font-size:.78rem; }
  @media print { body { padding:0; } details { break-inside:avoid; } details[open] summary ~ * { display:block; } }
</style>
</head>
<body><div class="wrap">
<header>
  <div>
    <h1>Active Directory hygiene report</h1>
    <div class="sub">$domainName · captured $(Protect-Html $Result.CapturedAt)</div>
    <div class="sub">$(Protect-Html $Result.Stats.Users) users · $(Protect-Html $Result.Stats.Computers) computers · $(Protect-Html $Result.Stats.Groups) groups · $(Protect-Html $Result.Stats.RulesEvaluated)/$(Protect-Html $Result.Stats.RulesTotal) rules evaluated</div>
  </div>
  <div class="gauge $gradeClass">
    <div class="n">$(Protect-Html $score.Score)</div>
    <div class="g">grade $(Protect-Html $score.Grade)</div>
  </div>
</header>
<div class="tiles">
  <div class="tile"><div class="k">Critical</div><div class="v crit">$(Protect-Html $score.Critical)</div></div>
  <div class="tile"><div class="k">High</div><div class="v high">$(Protect-Html $score.High)</div></div>
  <div class="tile"><div class="k">Medium</div><div class="v med">$(Protect-Html $score.Medium)</div></div>
  <div class="tile"><div class="k">Low</div><div class="v low">$(Protect-Html $score.Low)</div></div>
  <div class="tile"><div class="k">Total findings</div><div class="v">$(Protect-Html $score.TotalFindings)</div></div>
</div>
"@)

    if ($Result.Findings.Count -eq 0) {
        $null = $sb.AppendLine(@"
<div class="empty">
  <div class="big">No findings</div>
  <p class="sub">Every rule in the catalogue passed against this snapshot.</p>
</div>
"@)
    }
    else {
        foreach ($f in $Result.Findings) {
            $sev = Protect-Html $f.Severity
            $null = $sb.AppendLine(@"
<details class="finding sev-$sev">
  <summary>
    <span class="badge $sev">$sev</span>
    <span class="rid">$(Protect-Html $f.RuleId)</span>
    <span class="ftitle">$(Protect-Html $f.Title)</span>
    <span class="count">$(Protect-Html $f.AffectedCount) affected</span>
  </summary>
  <div class="body">
    <h4>Why this matters</h4><p>$(Protect-Html $f.Rationale)</p>
    <h4>Remediation</h4><p>$(Protect-Html $f.Remediation)</p>
    <h4>Affected objects</h4>
    <div class="scroll"><table><thead><tr><th>Object</th><th>Detail</th><th>Distinguished name</th></tr></thead><tbody>
"@)
            foreach ($a in $f.Affected) {
                $null = $sb.AppendLine(
                    "      <tr><td>$(Protect-Html $a.Name)</td><td>$(Protect-Html $a.Detail)</td><td class=""dn"">$(Protect-Html $a.DistinguishedName)</td></tr>")
            }
            $null = $sb.AppendLine(@"
    </tbody></table></div>
    <h4>Reference</h4><p><a href="$(Protect-Html $f.Reference)" rel="noreferrer noopener">$(Protect-Html $f.Reference)</a></p>
  </div>
</details>
"@)
        }
    }

    $null = $sb.AppendLine(@"
<footer>
  Generated by <strong>ADRot</strong> $(Protect-Html $Result.ToolVersion) in $(Protect-Html $Result.DurationMs) ms.
  ADRot performs read-only LDAP searches and never modifies Active Directory.
  This report reflects one point in time and is not a substitute for a full security assessment.
</footer>
</div></body></html>
"@)

    return $sb.ToString()
}
