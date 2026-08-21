# CPF LGPD

Ferramenta local para localizar CPFs matematicamente válidos, registrar a localização estrutural
dos achados e classificar indicadores de dados pessoais sensíveis com regras determinísticas,
explicáveis e versionadas.

Versão candidata corporativa atual: `2.2.0rc1`, perfil `windows-corporate-1.0-rc1`.

O número encontrado, o nome da pessoa, o valor sensível, a célula e o trecho do documento nunca
são gravados nos relatórios ou logs. O resultado apoia inventário e revisão, mas não determina
sozinho conformidade, licitude ou violação da LGPD.

## Versões metodológicas

- regras sensíveis: `lgpd-br-1.0.0`;
- score de risco: `1.1`;
- fundamento das regras: `LGPD_ART_5_II`.
- política de caminhos: `windows-path-1.0`;
- política de permissões: `windows-acl-1.0`.

A taxonomia, fórmulas, indicadores, negativas e processo de revisão estão em
[Regras de dados pessoais sensíveis](docs/SENSITIVE_DATA_RULES.md). A composição completa do risco
está em [Metodologia](docs/METODOLOGIA.md).
O roteiro de homologação Windows está em
[Candidata corporativa Windows](docs/WINDOWS_CORPORATE_RC.md).

## Requisitos

- Python 3.10 ou superior;
- leitura autorizada somente nas raízes aprovadas;
- autenticação prévia do sistema operacional para compartilhamentos UNC;
- Windows 10/11 ou Windows Server suportado, com `pywin32`, instalado automaticamente no Windows;
- Tesseract OCR para imagens;
- `antiword` para Word binário `.doc`.

Não passe credenciais de rede, LDAP, HMAC ou armazenamento pela linha de comando. Use autenticação
integrada e cofre corporativo com privilégio mínimo.

## Instalação

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install .
```

No Windows, a ativação usual é `.venv\Scripts\activate`.

Para a candidata corporativa no PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
cpf-lgpd '\\servidor\compartilhamento' --preflight-only --root-id area-autorizada
```

## Uso

```bash
cpf-lgpd /dados/autorizados --root-id area-controlada
cpf-lgpd '\\servidor\compartilhamento' --root-id compartilhamento-rh
cpf-lgpd /dados --report /relatorios/tecnico.json --executive-report /relatorios/executivo.json
cpf-lgpd /dados --csv-report tecnico.csv --executive-csv-report executivo.csv
cpf-lgpd /dados --mode cpf-anchor --extension csv --extension xlsx
cpf-lgpd /dados --config configuracao.json
cpf-lgpd '\\servidor\compartilhamento' --permission-mode strict --share-acl --preflight-only
```

O perfil padrão é estrito. A raiz deve ser absoluta ou UNC, a fonte de ACL nativa é obrigatória no
Windows e os relatórios devem ficar fora da árvore examinada. `--allow-report-inside-root` é uma
exceção explícita para compatibilidade, não uma configuração recomendada.

`cpf-anchor` é o modo padrão. Uma classificação sensível só é confirmada quando um CPF válido,
uma evidência explícita e um vínculo forte aparecem na mesma unidade verificável.

`full-discovery` aceita outro identificador pessoal explícito como âncora. Indicador sem âncora ou
sem vínculo permanece `possivel_ocorrencia`, exige revisão e adiciona zero ao risco.

## Rastreabilidade

O inventário registra, para cada arquivo analisado:

- `root_id`;
- caminho original;
- caminho absoluto ou UNC;
- caminho canônico;
- caminho relativo à raiz;
- nome, extensão e tamanho;
- data de criação quando o sistema realmente a fornece;
- data da última modificação;
- proprietário técnico quando disponível;
- fonte das permissões;
- `created_by` e `last_modified_by` como `unknown` sem fonte confiável de auditoria.

O scanner resolve os caminhos antes da leitura e impede saída da raiz por link simbólico, junction
ou caminho relativo. Credenciais incorporadas em URL ou caminho são removidas dos metadados. O
próprio caminho deve ser tratado como informação confidencial.

No Windows, a candidata lê proprietário e DACL NTFS pela API de segurança do sistema. Para uma
raiz UNC, também consulta a ACL do compartilhamento SMB e calcula o alcance efetivo usando a
camada mais restritiva quando ambas são conhecidas. DACL com `deny`, ACE não suportada ou consulta
parcial fica `unknown`, sem tentar adivinhar acesso efetivo. Somente categoria de exposição, fonte,
estado de herança e resultado da avaliação são persistidos, nunca a lista de trustees.

## Localização por formato

| Formato | Localização produzida |
|---|---|
| CSV | linha, coluna e cabeçalho |
| XLSX e XLS | planilha, linha, coluna e cabeçalho |
| JSON | JSONPath e objeto do registro |
| XML | XPath e elemento do registro |
| PDF | página e linha da camada textual |
| DOCX | parágrafo ou tabela, linha e coluna |
| TXT e outros textos | número da linha |
| SQLite | tabela, linha e coluna |
| compactados | membro e localização do formato interno |
| imagens | linha de OCR, com penalidade de ambiguidade |

Formatos suportados: CSV, HTML, JSON, LOG, Markdown, RTF, SQL, TXT, XML, YAML, PDF, DOCX, DOC,
XLSX, XLS, imagens comuns, ZIP, TAR e variantes, DB, DB3, SQLITE e SQLITE3.

Arquivos maiores que 50 MiB são ignorados por padrão. Compactados têm limites de profundidade,
membros e tamanho descompactado para reduzir risco de zip bomb. Arquivos criptografados não são
quebrados.

## Confiança e risco

`confidence_score` mede evidência e vínculo. `risk_score` prioriza o arquivo. Um não é somado ao
outro.

- confiança de 85 a 100: alta;
- confiança de 70 a 84: média;
- abaixo de 70: possível ocorrência, zero ponto sensível;
- uma categoria sensível média: 15 pontos;
- uma categoria sensível alta: 20 pontos;
- duas ou mais categorias médias ou altas: 25 pontos no total;
- parcela sensível: máximo 25;
- dimensão de conteúdo: máximo 40.

A quantidade de palavras não altera essa pontuação. O número de titulares é representado pela
dimensão de volume.

## Relatórios

O relatório técnico contém os caminhos completos. O executivo contém `root_id` e caminho relativo.
JSON e CSV incluem, quando aplicável:

```text
file_path, relative_path, root_id, location, rule_id, legal_category, subtype,
confidence_score, confidence_level, risk_points, match_count, requires_human_review,
ruleset_version, score_version
```

O técnico também inclui `permission_level`, `permissions_assessed`, `acl_inheritance`,
`share_acl_evaluated`, `permissions_source` e as versões das políticas operacionais.

Os arquivos são gravados atomicamente. Em POSIX recebem modo `0600`. No Windows recebem DACL
protegida para o operador atual, `SYSTEM` e `Administrators`. Se essa proteção falhar, o modo
`strict` remove o temporário e encerra sem publicar o relatório. O diretório de destino também deve
ser previamente controlado, com criptografia em repouso e retenção curta.

O relatório executivo omite caminho completo, proprietário técnico e detalhes de ACL. Esses dados
permanecem somente no relatório técnico protegido.

HMAC é opcional para deduplicação sem persistir o CPF:

```bash
export CPF_LGPD_HMAC_SECRET="valor-obtido-de-cofre"
cpf-lgpd /dados --report tecnico.json
```

Sem segredo, nenhum identificador persistente é produzido.

## Configuração

```json
{
  "mode": "cpf-anchor",
  "context_window": 500,
  "max_file_size_mb": 50,
  "max_processing_seconds": 3600,
  "max_age_days": 1825,
  "extensions": ["txt", "csv", "pdf", "docx", "xlsx"],
  "permission_mode": "strict",
  "include_share_acl": true,
  "report_protection_mode": "strict",
  "require_absolute_root": true,
  "allow_reports_inside_root": false,
  "weights": {"cpf": 5, "content_cap": 40},
  "governance": {"purpose": "unknown", "legal_basis": "unknown"}
}
```

Um arquivo completo está em
[examples/windows-corporate.json](examples/windows-corporate.json).

## Desenvolvimento

```bash
python -m pip install -e '.[dev]'
ruff check .
python -m unittest discover -v
coverage run -m unittest discover
coverage report
python -m build
```

Use somente dados artificiais em testes, fixtures, commits e issues.

## Limitações

- PDF digitalizado depende de OCR em fluxo separado ou de imagem suportada;
- OCR e extração de PDF podem gerar falsos positivos ou negativos;
- bancos não SQLite e formatos proprietários não são lidos;
- unidade de rede mapeada não identifica com segurança o compartilhamento de origem, use UNC para
  combinar ACL NTFS e SMB;
- ACL com negação, ACE condicional ou tipo não suportado é marcada como desconhecida;
- DFS, permissões dinâmicas, grupos aninhados e acesso efetivo por token não são expandidos nesta
  candidata;
- a conta de execução pode não ter `READ_CONTROL` ou permissão para consultar a ACL do share, nesse
  caso a fonte parcial é registrada e a exposição permanece desconhecida;
- ausência de achado não comprova ausência de dado pessoal;
- a ferramenta não infere atributo sensível por nome, fotografia, endereço ou estatística;
- nenhuma ação de exclusão, movimentação, criptografia ou quarentena é executada.

## Segurança e licença

Consulte [SECURITY.md](SECURITY.md) para comunicar vulnerabilidades sem divulgar dados pessoais.
Distribuído sob a [GNU General Public License v3.0](LICENSE).
