## Get ora/hydra
```powershell
curl.exe -L https://github.com/ory/hydra/releases/download/v1.8.5/hydra_1.8.5_windows_64-bit.zip -O
Expand-Archive .\hydra_1.8.5_windows_64-bit.zip
Copy-Item hydra_1.8.5_windows_64-bit\hydra.exe .\
Remove-Item -Recurse .\hydra_1.8.5_windows_64-bit\
Remove-Item .\hydra_1.8.5_windows_64-bit.zip
```

## Launch hydra
```powershell
.\hydra.exe serve all --dangerous-force-http --config=hydra.yaml
```

```powershell
go run .\mock.go
```

## Add test client to hydra
```powershell
$env:HYDRA_URL="http://localhost:4445/"
.\hydra.exe clients create --id test --secret 123456 --callbacks http://localhost:4447/callback --response-types code,token,id_token
```
