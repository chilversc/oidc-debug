```powershell
.\hydra.exe serve all --dangerous-force-http --config=hydra.yaml
```

```powershell
$env:HYDRA_URL="http://localhost:4445/"
.\hydra.exe clients create --id test --secret 123456 --callbacks http://localhost:4446/callback --response-types code,token,id_token
```
