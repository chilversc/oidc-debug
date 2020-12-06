# Get ora/hydra
```powershell
curl.exe -L https://github.com/ory/hydra/releases/download/v1.8.5/hydra_1.8.5_windows_64-bit.zip -O
Expand-Archive .\hydra_1.8.5_windows_64-bit.zip
Copy-Item hydra_1.8.5_windows_64-bit\hydra.exe .\
Remove-Item -Recurse .\hydra_1.8.5_windows_64-bit\
Remove-Item .\hydra_1.8.5_windows_64-bit.zip
```

## Launch hydra

### Running hydra with HTTP

```powershell
.\hydra.exe serve all --dangerous-force-http --config=hydra.yaml
```

```powershell
$env:HYDRA_URL="http://localhost:4445/"
.\hydra.exe clients create --id test --secret 123456 --callbacks http://localhost:4447/callback --response-types code,token,id_token
go run .\mock.go
```

#### Running hydra with TLS (self-signed)

NOTE: this will cause warnings in the browser, primary use of this is for testing the `--insecure` and `--ca` options.

```powershell
.\hydra.exe serve all --config=hydra-tls.yaml
```

```powershell
$env:HYDRA_URL="https://localhost:4445/"
.\hydra.exe clients create --skip-tls-verify --id test --secret 123456 --callbacks http://localhost:4447/callback --response-types code,token,id_token
go run .\mock.go
```
