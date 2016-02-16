$apiKey = "API"
$URLResource = "server"

$csv = Import-Csv c:\file.csv

foreach ($line in $csv)
{
    $Source = $line.Source
    $Description = $line.Description
    $User = $line.User
    $ProcessName = $line.'Process Name' 
    $Installer = $line.Installer
    $FilePath = $line.'File Path'
    $FileName = $line.'File Name'
    $Process = $line.Process
    $FileHash = $line.'File Hash'
    $fileSearch = $URLResource +"?q=sha256:$FileHash"
    $files = Invoke-RestMethod -Uri $fileSearch -Method Get -Header @{ "X-Auth-Token" = $apiKey } 
    foreach ($file in $files)
    {
        $Publisher = $file.publisher
        $PublisherState = $file.publisherState
        $events = @()
        $event = New-Object System.Object
        $event | Add-Member -MemberType NoteProperty -Name "Source" -Value $Source
        $event | Add-Member -MemberType NoteProperty -Name "Description" -Value $Description
        $event | Add-Member -MemberType NoteProperty -Name "User" -Value $User
        $event | Add-Member -MemberType NoteProperty -Name "Process Name" -Value $ProcessName
        $event | Add-Member -MemberType NoteProperty -Name "Installer" -Value $Installer
        $event | Add-Member -MemberType NoteProperty -Name "File Path" -Value $FilePath
        $event | Add-Member -MemberType NoteProperty -Name "File Name" -Value $FileName
        $event | Add-Member -MemberType NoteProperty -Name "Process" -Value $Process
        $event | Add-Member -MemberType NoteProperty -Name "File Hash" -Value $FileHash
        $event | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $Publisher
        $event | Add-Member -MemberType NoteProperty -Name "Publisher State" -Value $PublisherState
        $events += $event
        $events | Export-Csv -NoTypeInformation -Path "c:\files.csv" -Append
    }
}
