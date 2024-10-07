# 定义平台和输出文件
$platforms = @{
    "linux"   = "test_linux"
    "darwin"  = "test_darwin"
    "windows" = "test_windows.exe"
}

foreach ($os in $platforms.Keys) {
    if ($os -eq "windows") {
        $env:GOOS = "windows"
        $env:GOARCH = "amd64"
    } elseif ($os -eq "linux") {
        $env:GOOS = "linux"
        $env:GOARCH = "amd64"
    } elseif ($os -eq "darwin") {
        $env:GOOS = "darwin"
        $env:GOARCH = "amd64"
    }

    $outputFile = $platforms[$os]
    Write-Host "Building for $os..."
    go build -o $outputFile

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Successfully built $outputFile"
    } else {
        Write-Host "Failed to build $outputFile"
    }
}