#Credit to Lee Holmes
#https://www.leeholmes.com/searching-for-content-in-base-64-strings/

#Install-Script Get-Base64RegularExpression.ps1
param(
    ## The value that we would like to search for in Base64 encoded content
    [Parameter(Mandatory, ValueFromPipeline)]
    $Value,

    ## True if we should look for Unicode encodings of the string. Otherwise,
    ## assumed to be OEM / Default encoding
    [Parameter()]
    [Switch] $Unicode,

    ## True if we should emit the raw strings of each Base64 encoding
    [Parameter()]
    [Switch] $Raw
)

begin
{
    $base64sequences = @()
}

process
{
    ## Holds the various byte representations of what we're searching for
    $byteRepresentations = @()

    ## If we got a string, look for the representation of the string
    if($Value -is [String])
    {
        if($Unicode.IsPresent)
        {
            $byteRepresentations += 
                ,[Byte[]] [System.Text.Encoding]::Unicode.GetBytes($Value)
        }
        else
        {
            $byteRepresentations += 
                ,[Byte[]] [System.Text.Encoding]::Default.GetBytes($Value)        
        }
    }

    ## If it was a byte array directly, look for the byte representations
    if($Value -is [byte[]])
    {
        $byteRepresentations += ,$Value
    }

    ## Find the safe searchable sequences for each Base64 representation of input bytes
    $base64sequences += foreach($bytes in $byteRepresentations)
    {
        ## Offset 0. Sits on a 3-byte boundary so we can trust the leading characters.
        $offset0 = [Convert]::ToBase64String($bytes)

        ## Offset 1. Has one byte from preceeding content, so we need to throw away the
        ## first 2 leading characters
        $offset1 = [Convert]::ToBase64String( (New-Object 'Byte[]' 1) + $bytes ).Substring(2)

        ## Offset 2. Has two bytes from preceeding content, so we need to throw away the
        ## first 3 leading characters
        $offset2 = [Convert]::ToBase64String( (New-Object 'Byte[]' 2) + $bytes ).Substring(3)


        ## If there is any terminating padding, we must remove the characters mixed with that padding. That
        ## ends up being the number of equals signs, plus one.
        $base64matches = $offset0,$offset1,$offset2 | % {
            if($_ -match '(=+)$')
            {
                $_.Substring(0, $_.Length - ($matches[0].Length + 1))
            }
            else
            {
                $_
            }
        }

        $base64matches | ? { $_ }
    }
}

end
{
    if($Raw.IsPresent)
    {
        $base64sequences | Sort-Object -Unique
    }
    else
    {
        ## Output a regular expression for these sequences
        "(" + (($base64sequences | Sort-Object -Unique | % { [Regex]::Escape($_) }) -join "|") + ")"
    }
}