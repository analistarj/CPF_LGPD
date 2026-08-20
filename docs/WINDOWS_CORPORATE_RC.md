# Candidata corporativa Windows, versão 2.2.0rc1

## Objetivo e estado

Esta versão candidata adiciona controles específicos para estações Windows, servidores de arquivos
e compartilhamentos SMB. Ela deve passar por homologação técnica, de Privacidade e de Segurança
antes de uso em produção. O programa continua somente leitura sobre os arquivos examinados.

Versões que identificam o comportamento:

| Componente | Versão |
|---|---|
| Aplicação | `2.2.0rc1` |
| Perfil corporativo | `windows-corporate-1.0-rc1` |
| Regras sensíveis | `lgpd-br-1.0.0` |
| Score | `1.1` |
| Caminhos | `windows-path-1.0` |
| Permissões | `windows-acl-1.0` |

## Arquitetura de segurança

1. A autenticação ocorre no Windows, fora da ferramenta.
2. A raiz deve ser absoluta ou UNC e ter autorização formal.
3. Links simbólicos e reparse points não são seguidos por padrão.
4. Cada arquivo é resolvido para caminho canônico e comparado à raiz antes e depois da leitura.
5. Alteração de identidade, tamanho ou modificação durante a leitura invalida o achado.
6. A DACL NTFS e o proprietário são lidos pela API nativa por meio de `pywin32`.
7. Em UNC, a ACL do compartilhamento é consultada uma vez e reutilizada durante a execução.
8. O relatório não contém CPF, nome, valor, célula nem trecho do documento.
9. O relatório técnico recebe caminho completo e metadados de ACL.
10. O relatório executivo recebe `root_id`, caminho relativo e metadados minimizados.

As APIs de auditoria de criação e modificação não fazem parte desta candidata. `created_by` e
`last_modified_by` continuam `unknown`. Proprietário NTFS, data de criação e data de modificação não
são usados para inferir autoria.

## Modelo de ACL

A avaliação usa identificadores SID bem conhecidos, sem depender do idioma do Windows ou analisar
a saída textual do `icacls`.

| Evidência de leitura | Classificação | Pontos |
|---|---|---:|
| somente proprietário, SYSTEM ou Administradores | `owner_restricted` | 0 |
| outro usuário ou grupo específico | `internal_limited` | 5 |
| Authenticated Users, Users ou Domain Users | `internal_all` | 22 |
| Everyone, Anonymous ou Guests | `public` | 30 |
| DACL complexa, consulta parcial ou falha | `unknown` | 10 ou maior evidência conhecida |

Uma DACL nula representa acesso amplo. Uma DACL vazia representa ausência de concessão. ACE de
negação, ACE condicional e tipo não reconhecido tornam a avaliação desconhecida, pois a expansão
correta exige token efetivo, ordem das ACEs e associação a grupos.

Quando NTFS e SMB são conhecidos, o alcance mais restritivo representa a interseção das duas
camadas. Quando uma camada não pode ser consultada, o relatório registra a fonte parcial e não
afirma que o acesso efetivo foi confirmado.

## Conta de execução

Use uma conta de serviço dedicada, sem privilégio administrativo e com:

- leitura e listagem somente nas raízes aprovadas;
- `READ_CONTROL` para consultar proprietário e DACL quando a política permitir;
- gravação somente no repositório protegido de relatórios;
- login interativo negado quando a execução for agendada;
- senha ou certificado gerenciado por cofre corporativo;
- nenhuma credencial em argumentos, arquivos de configuração, caminhos ou logs.

Não execute como Domain Admin. Não altere ACL para permitir a varredura sem aprovação do
proprietário, Segurança e Privacidade.

## Instalação e preflight

```powershell
py -m venv C:\ProgramData\CPF-LGPD\venv
C:\ProgramData\CPF-LGPD\venv\Scripts\python.exe -m pip install .

C:\ProgramData\CPF-LGPD\venv\Scripts\cpf-lgpd.exe `
  '\\filesrv01\rh-controlado' `
  --root-id rh-controlado `
  --config C:\ProgramData\CPF-LGPD\config.json `
  --preflight-only
```

O preflight valida sintaxe, existência, listagem e fonte de permissões. Ele não examina conteúdo.
Use caminho UNC, não letra mapeada, quando a ACL do compartilhamento precisar integrar o score.

Exemplo de configuração:

```json
{
  "mode": "cpf-anchor",
  "context_window": 500,
  "max_file_size_mb": 50,
  "max_processing_seconds": 3600,
  "extensions": ["txt", "csv", "json", "xml", "pdf", "docx", "xlsx"],
  "permission_mode": "strict",
  "include_share_acl": true,
  "report_protection_mode": "strict",
  "require_absolute_root": true,
  "allow_reports_inside_root": false,
  "governance": {
    "purpose": "inventario corporativo autorizado",
    "legal_basis": "validar com o encarregado",
    "origin": "compartilhamento corporativo autorizado",
    "retention_deadline": "unknown"
  }
}
```

## Execução controlada

```powershell
$ReportDirectory = 'D:\LGPD-Reports\execucao-001'
New-Item -ItemType Directory -Path $ReportDirectory -ErrorAction Stop | Out-Null

C:\ProgramData\CPF-LGPD\venv\Scripts\cpf-lgpd.exe `
  '\\filesrv01\rh-controlado' `
  --root-id rh-controlado `
  --config C:\ProgramData\CPF-LGPD\config.json `
  --report "$ReportDirectory\tecnico.json" `
  --csv-report "$ReportDirectory\tecnico.csv" `
  --executive-report "$ReportDirectory\executivo.json" `
  --executive-csv-report "$ReportDirectory\executivo.csv"
```

Proteja o diretório de relatórios antes da execução. A aplicação restringe cada arquivo publicado,
mas não modifica a ACL do diretório corporativo existente. Mantenha BitLocker ou criptografia do
volume, backup controlado e prazo de retenção aprovado.

## Códigos de saída

| Código | Significado |
|---:|---|
| 0 | execução concluída sem achados, ou preflight aprovado |
| 1 | execução concluída com pelo menos um arquivo com achado |
| 2 | erro operacional, de caminho, dependência, permissão ou proteção do relatório |

Mensagens de erro mostram somente a classe do erro. Caminho, conteúdo e mensagem original não são
enviados à saída padrão ou de erro.

## Critérios de homologação

- validar em Windows 10, Windows 11 e versões de Windows Server realmente utilizadas;
- testar NTFS local, SMB com domínio, share sem permissão e caminho UNC longo;
- testar junction, link simbólico, reparse point e alteração concorrente de arquivo;
- validar ACL efetiva com matrizes sintéticas de allow e deny;
- confirmar que relatório técnico e executivo chegam ao repositório correto;
- confirmar que o relatório executivo não contém caminho completo nem proprietário;
- executar busca automatizada por CPF, nomes e valores sintéticos em relatórios e logs;
- comparar duas execuções sobre a mesma fixture e confirmar score e confiança idênticos;
- executar análise de dependências, antivírus e revisão do pacote gerado;
- obter aceite de Segurança, Privacidade, Jurídico e proprietário da informação.

## Limitações da candidata

- grupos aninhados e token efetivo do usuário não são expandidos;
- ACE de negação ou tipo não suportado resulta em `unknown`;
- DFS e permissões dinâmicas podem exigir validação externa;
- letra de unidade mapeada não é convertida automaticamente em UNC;
- a consulta de ACL do share pode ser bloqueada pelo servidor;
- a ferramenta não lê auditoria do Windows para identificar criador ou último modificador;
- arquivos abertos, alterados ou bloqueados durante a execução podem falhar e ser contabilizados;
- a ausência de achado não comprova ausência de dado pessoal ou conformidade com a LGPD.

## Aprovação para produção

A promoção de `2.2.0rc1` para versão estável deve ocorrer somente após a matriz de homologação ser
concluída, as limitações serem aceitas e os controles de operação serem documentados. Não habilite
remoção, movimentação, quarentena ou alteração de ACL nesta etapa.
