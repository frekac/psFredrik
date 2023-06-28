# Simple script to extract the player names from .wotreplay files
# Only tested with files created on 2023-June-28, using powershell 7.3.4
# Usage: PS C:\Temp>.\Get-WotPlayerInformation.ps1 -WotReplayPath .\20230628_2319_germany-G99_RhB_Waffentrager_35_steppes.wotreplay

param(
    [string]$WotReplayPath
)

function Get-PlayerNames {
    param (
        $ReplayContent
    )
    $findPatternStart = [regex]::Match($ReplayContent, "`"players`"")
    $indexStart = $findPatternStart.Index
    
    $findPatternEnd = [regex]::Match($ReplayContent, "}, `"vehicles`"")
    $indexEnd = $findPatternEnd.Index

    try {
        $json = "{" + ($ReplayContent[$indexStart..$indexEnd] -join "") + "}"
        $wotData = $json | ConvertFrom-Json -Depth 20
    } catch {
        Write-Output "[Error]: Something went wrong when extracting the player names"
        break;
    }

    $results = @()
    $counter = 1
    foreach($p in $wotData.players.psobject.Properties.Value) {
        $data = [PSCustomObject]@{
            PlayerNumber = $counter
            Clan = $p.clanAbbrev
            RealName = $p.realName
            Name = $p.name
        }
        $counter++
        $results += $data
    }
    $results
}

$fileContent = Get-Content $WotReplayPath -TotalCount 1 -Encoding UTF8

Get-PlayerNames -ReplayContent $fileContent