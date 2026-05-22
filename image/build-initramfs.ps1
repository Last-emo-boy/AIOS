param(
    [string]$OutDir = "image/out",
    [string]$SourceDir = "image/initramfs",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

function Convert-ToUnixPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = (Resolve-Path -LiteralPath $Path).Path
    if ($full -notmatch '^([A-Za-z]):\\(.*)$') {
        throw "Only local drive paths are supported: $full"
    }
    $drive = $Matches[1].ToLowerInvariant()
    $rest = $Matches[2] -replace '\\', '/'
    return "/mnt/$drive/$rest"
}

function Write-AgentdElf {
    param([Parameter(Mandatory = $true)][string]$Path)

    # x86_64 Linux static ELF. It writes AGENTD_HANDOFF_OK, then exits.
    $message = [Text.Encoding]::ASCII.GetBytes("AGENTD_HANDOFF_OK`n")
    $code = [byte[]]@(
        0x48, 0x31, 0xc0,                         # xor rax, rax
        0xb0, 0x01,                               # mov al, 1 ; write
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, # mov rdi, 1 ; stdout
        0x48, 0x8d, 0x35, 0x15, 0x00, 0x00, 0x00, # lea rsi, [rip + message]
        0x48, 0xc7, 0xc2, 0x12, 0x00, 0x00, 0x00, # mov rdx, 18
        0x0f, 0x05,                               # syscall
        0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, # mov rax, 60 ; exit
        0x48, 0x31, 0xff,                         # xor rdi, rdi
        0x0f, 0x05                                # syscall
    )

    $entryOffset = 0x78
    $fileSize = $entryOffset + $code.Length + $message.Length
    $entryAddress = 0x400000 + $entryOffset
    $bytes = New-Object byte[] $fileSize

    function Write-Bytes {
        param([int]$Offset, [byte[]]$Data)
        [Array]::Copy($Data, 0, $bytes, $Offset, $Data.Length)
    }

    function Write-U16 {
        param([int]$Offset, [UInt16]$Value)
        Write-Bytes $Offset ([BitConverter]::GetBytes($Value))
    }

    function Write-U32 {
        param([int]$Offset, [UInt32]$Value)
        Write-Bytes $Offset ([BitConverter]::GetBytes($Value))
    }

    function Write-U64 {
        param([int]$Offset, [UInt64]$Value)
        Write-Bytes $Offset ([BitConverter]::GetBytes($Value))
    }

    Write-Bytes 0x00 ([byte[]](0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00))
    Write-U16 0x10 2
    Write-U16 0x12 0x3e
    Write-U32 0x14 1
    Write-U64 0x18 ([UInt64]$entryAddress)
    Write-U64 0x20 0x40
    Write-U16 0x34 0x40
    Write-U16 0x36 0x38
    Write-U16 0x38 1

    Write-U32 0x40 1
    Write-U32 0x44 5
    Write-U64 0x48 0
    Write-U64 0x50 0x400000
    Write-U64 0x58 0x400000
    Write-U64 0x60 ([UInt64]$fileSize)
    Write-U64 0x68 ([UInt64]$fileSize)
    Write-U64 0x70 0x1000

    Write-Bytes $entryOffset $code
    Write-Bytes ($entryOffset + $code.Length) $message
    [IO.File]::WriteAllBytes($Path, $bytes)
}

function Invoke-Wsl {
    param([Parameter(Mandatory = $true)][string]$Command)
    $output = & wsl.exe -- bash -lc $Command 2>&1
    if ($LASTEXITCODE -ne 0) {
        $joined = $output -join [Environment]::NewLine
        throw "WSL command failed: $Command`n$joined"
    }
    return $output
}

function Write-Ascii {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][string]$Value
    )
    $bytes = [Text.Encoding]::ASCII.GetBytes($Value)
    $Stream.Write($bytes, 0, $bytes.Length)
}

function Write-NewcField {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][UInt64]$Value
    )
    Write-Ascii -Stream $Stream -Value ($Value.ToString("x8"))
}

function Write-Padding {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][UInt64]$Written
    )
    $pad = (4 - ($Written % 4)) % 4
    if ($pad -gt 0) {
        $zeros = New-Object byte[] $pad
        $Stream.Write($zeros, 0, $zeros.Length)
    }
}

function Write-NewcEntry {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][UInt32]$Mode,
        [byte[]]$Data = [byte[]]@(),
        [UInt32]$Inode = 1
    )
    $nameBytes = [Text.Encoding]::ASCII.GetBytes($Name)
    $nameSize = $nameBytes.Length + 1
    Write-Ascii -Stream $Stream -Value "070701"
    foreach ($value in @(
        $Inode,
        $Mode,
        0,
        0,
        1,
        0,
        $Data.Length,
        0,
        0,
        0,
        0,
        $nameSize,
        0
    )) {
        Write-NewcField -Stream $Stream -Value ([UInt64]$value)
    }
    $Stream.Write($nameBytes, 0, $nameBytes.Length)
    $Stream.WriteByte(0)
    Write-Padding -Stream $Stream -Written (110 + $nameSize)
    if ($Data.Length -gt 0) {
        $Stream.Write($Data, 0, $Data.Length)
        Write-Padding -Stream $Stream -Written $Data.Length
    }
}

function New-InitramfsArchive {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$ArchivePath
    )
    $rawStream = New-Object IO.MemoryStream
    $inode = 1
    $entries = Get-ChildItem -LiteralPath $SourceRoot -Recurse -Force | Sort-Object FullName
    foreach ($entry in $entries) {
        $relative = [IO.Path]::GetRelativePath($SourceRoot, $entry.FullName) -replace '\\', '/'
        $inode++
        if ($entry.PSIsContainer) {
            Write-NewcEntry -Stream $rawStream -Name $relative -Mode 0x41ed -Inode $inode
        } else {
            $data = [IO.File]::ReadAllBytes($entry.FullName)
            $mode = if ($relative -eq "sbin/agentd") { 0x81ed } else { 0x81a4 }
            Write-NewcEntry -Stream $rawStream -Name $relative -Mode $mode -Data $data -Inode $inode
        }
    }
    Write-NewcEntry -Stream $rawStream -Name "TRAILER!!!" -Mode 0 -Inode ($inode + 1)
    $rawBytes = $rawStream.ToArray()
    $rawStream.Dispose()

    $fileStream = [IO.File]::Create($ArchivePath)
    try {
        $gzip = New-Object IO.Compression.GzipStream($fileStream, [IO.Compression.CompressionLevel]::SmallestSize)
        try {
            $gzip.Write($rawBytes, 0, $rawBytes.Length)
        } finally {
            $gzip.Dispose()
        }
    } finally {
        $fileStream.Dispose()
    }
}

$repoRoot = (Resolve-Path -LiteralPath ".").Path
$sourceRoot = Join-Path $repoRoot $SourceDir
$outRoot = Join-Path $repoRoot $OutDir

if ($Clean -and (Test-Path -LiteralPath $outRoot)) {
    Remove-Item -LiteralPath $outRoot -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $sourceRoot, $outRoot | Out-Null
foreach ($dir in @("bin", "dev", "etc", "proc", "sbin", "sys", "tmp")) {
    New-Item -ItemType Directory -Force -Path (Join-Path $sourceRoot $dir) | Out-Null
}

$agentdPath = Join-Path $sourceRoot "sbin/agentd"
Write-AgentdElf -Path $agentdPath

$archivePath = Join-Path $outRoot "agentos-initramfs.cpio.gz"
New-InitramfsArchive -SourceRoot $sourceRoot -ArchivePath $archivePath
$hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
$agentdHash = (Get-FileHash -LiteralPath $agentdPath -Algorithm SHA256).Hash.ToLowerInvariant()

$manifest = [ordered]@{
    artifact = "agentos-initramfs.cpio.gz"
    artifact_sha256 = $hash
    source_dir = $SourceDir
    generated_agentd = "sbin/agentd"
    generated_agentd_sha256 = $agentdHash
    boot_args = "console=ttyS0 rdinit=/sbin/agentd panic=-1"
    handoff_marker = "AGENTD_HANDOFF_OK"
    constraints = @(
        "Developer VM first, Cloud VM compatible",
        "x86_64 Linux VM",
        "no Firecracker required",
        "no remote LLM required",
        "no native GUI required",
        "no arbitrary root shell in normal mode"
    )
    built_at = (Get-Date).ToString("o")
    builder = "image/build-initramfs.ps1"
}

$manifestPath = Join-Path $outRoot "agentos-initramfs.manifest.json"
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host "Built $archivePath"
Write-Host "SHA256 $hash"
