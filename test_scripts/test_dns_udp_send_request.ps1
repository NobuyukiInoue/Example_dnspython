param($dnsserver, $enable_output_logfile)

if (-Not $dnsserver) {
    Write-Host "Usage) "$MyInvocation.MyCommand.Name" [dnsserver] [TRUE | FALSE]"
    exit
}

if (-Not $enable_output_logfile) {
    $ENABLE_OUTPUT_LOG = $FALSE
}
else {
    if ($enable_output_logfile.ToUpper() -eq "TRUE") {
        $ENABLE_OUTPUT_LOG = $TRUE
    }
    else {
        $ENABLE_OUTPUT_LOG = $FALSE
    }
}

$target_program = "../dns_send_udp_request.py"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logfile = "./log/result_" + $timestamp + ".log"

if (Test-Path $logfile) {
    Write-Host "$lofile is exist."
    exit
}

$records = @( `
    @(".", "any"), `
    @(".", "ns"), `
    @("jp", "any"), `
    @("jp", "ns"), `
    @("jp", "soa"), `
    @("jp", "dnskey"), `
    @("jp", "ds"), `
    @("jp", "nsec3"), `
    @("jp", "nsec3param"), `
    @("freebsd.org", "any"), `
    @("_http._tcp.update.freebsd.org", "srv"), `
    @("freebsd.org", "caa") `
)

Write-Host "DNSSERVER = $dnsserver\n"

if ($ENABLE_OUTPUT_LOG) {
    Write-Host "LOGFILE = $logfile"

    foreach($record in $records) {
        Write-Host "Execute: python $target_program $dnsserver $record[0] $record[1] | Out-File -Append $logfile -Encoding ascii"
        python $target_program $dnsserver $record[0] $record[1] | Out-File -Append $logfile -Encoding ascii
    }
}
else {
    foreach($record in $records) {
        Write-Host "Execute: python $target_program $dnsserver $record[0] $record[1]"
        python $target_program $dnsserver $record[0] $record[1]
    }
}
