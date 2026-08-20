# CPF LGPD

Ferramenta local para localizar CPFs matematicamente válidos, registrar a localização estrutural
dos achados e classificar indicadores de dados pessoais sensíveis com regras determinísticas,
explicáveis e versionadas.

O número encontrado, o nome da pessoa, o valor sensível, a célula e o trecho do documento nunca
são gravados nos relatórios ou logs. O resultado apoia inventário e revisão, mas não determina
sozinho conformidade, licitude ou violação da LGPD.

## Versões metodológicas

- regras sensíveis: `lgpd-br-1.0.0`;
- score de risco: `1.1`;
- fundamento das regras: `LGPD_ART_5_II`.

A taxonomia, fórmulas, indicadores, negativas e processo de revisão estão em
[Regras de dados pessoais sensíveis](docs/SENSITIVE_DATA_RULES.md). A composição completa do risco
está em [Metodologia](docs/METODOLOGIA.md).

## Requisitos

- Python 3.10 ou superior;
- leitura autorizada somente nas raízes aprovadas;
- autenticação prévia do sistema operacional para compartilhamentos UNC;
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

## Uso

```bash
cpf-lgpd /dados/autorizados --root-id area-controlada
cpf-lgpd '\\servidor\compartilhamento' --root-id compartilhamento-rh
cpf-lgpd /dados --report tecnico.json --executive-report executivo.json
cpf-lgpd /dados --csv-report tecnico.csv --executive-csv-report executivo.csv
cpf-lgpd /dados --mode cpf-anchor --extension csv --extension xlsx
cpf-lgpd /dados --config configuracao.json
```

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

Os arquivos são gravados atomicamente com permissão `0600`. Em Windows e armazenamentos remotos,
o operador também deve configurar ACLs adequadas. Grave os relatórios fora da árvore examinada,
restrinja o acesso, use criptografia em repouso e aplique retenção curta.

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
  "weights": {"cpf": 5, "content_cap": 40},
  "governance": {"purpose": "unknown", "legal_basis": "unknown"}
}
```

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
- ACL de Windows ainda exige adaptador específico e aparece como desconhecida;
- ausência de achado não comprova ausência de dado pessoal;
- a ferramenta não infere atributo sensível por nome, fotografia, endereço ou estatística;
- nenhuma ação de exclusão, movimentação, criptografia ou quarentena é executada.

## Segurança e licença

Consulte [SECURITY.md](SECURITY.md) para comunicar vulnerabilidades sem divulgar dados pessoais.
Distribuído sob a [GNU General Public License v3.0](LICENSE).
