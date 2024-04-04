#!/usr/bin/pwsh

param (
    [Parameter(Mandatory=$true)]
    [String]$text
)

$bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
$EncodedText = [Convert]::ToBase64String($bytes)
$EncodedText
