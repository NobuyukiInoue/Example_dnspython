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

$target_program = "..\dns_send_udp_request.py"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logfile = ".\log\result_" + $timestamp + ".log"

if (Test-Path $logfile) {
    Write-Host "$lofile is exist."
    exit
}

$records = @()
$records += ,@(".", "any")
$records += ,@(".", "ns")
$records += ,@("jp", "any")
$records += ,@("jp", "ns")
$records += ,@("jp", "soa")
$records += ,@("jp", "dnskey")
$records += ,@("jp", "ds")
$records += ,@("jp", "nsec3")
$records += ,@("jp", "nsec3param")
$records += ,@("freebsd.org", "any")
$records += ,@("_http._tcp.update.freebsd.org", "srv")
$records += ,@("freebsd.org", "caa")

if ($ENABLE_OUTPUT_LOG) {
    foreach($record in $records) {
        python $target_program $dnsserver $record[0] $record[1] | Out-File -Append $logfile -Encoding ascii
    }
}
else {
    foreach($record in $records) {
        python $target_program $dnsserver $record[0] $record[1]
    }
}
