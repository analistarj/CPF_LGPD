# CPF LGPD

Ferramenta local para descobrir **CPFs validos**, classificar indicadores contextuais de dados
pessoais, calcular risco explicavel e recomendar revisao e remediacao. A implementacao aplica
minimizacao: o numero encontrado nunca e exibido nem armazenado no relatorio.

> Esta ferramenta apoia inventario e remediacao; ela nao determina, sozinha, conformidade com
> a LGPD. Toda execucao deve ter finalidade, escopo, autorizacao e retencao definidos pelo
> controlador, com participacao das areas de privacidade e seguranca.

## Requisitos

- Python 3.10 ou superior;
- permissao de leitura apenas no escopo aprovado;
- no Windows, acesso previamente autenticado ao compartilhamento UNC, quando aplicavel.

Para OCR de imagens, instale tambem o **Tesseract OCR** e o pacote de idioma desejado (por
padrao, `por`). Para arquivos Word binarios `.doc`, instale o executavel **antiword**. Essas
ferramentas externas nao sao instaladas pelo `pip`.

O scanner nao recebe nem armazena credenciais de LDAP. Prefira autenticacao integrada ou um
cofre corporativo e uma conta de servico com privilegio minimo.

## Instalacao

Em um ambiente virtual:

```bash
python -m venv .venv
. .venv/bin/activate             # Windows: .venv\Scripts\activate
python -m pip install .
```

As bibliotecas Python para PDF, imagens, OCR e planilhas legadas sao instaladas automaticamente.

## Uso

```bash
cpf-lgpd /dados/aprovados
cpf-lgpd '\\servidor\compartilhamento' --report ./resultado.json
cpf-lgpd /dados --extension txt --extension csv --max-file-size-mb 25
cpf-lgpd /dados --ocr-language por
cpf-lgpd /dados --mode cpf-anchor --report resultado.json --csv-report resultado.csv
cpf-lgpd /dados --config configuracao.json
```

### Formatos examinados

| Categoria | Formatos | Metodo e observacoes |
|---|---|---|
| Texto | CSV, HTML, JSON, LOG, Markdown, RTF, SQL, TXT, XML e YAML | leitura UTF-8 em blocos |
| PDF | PDF | extracao da camada de texto com `pypdf`; PDF apenas com imagem requer OCR separado |
| Word | DOCX e DOC | XML interno para DOCX; `antiword` externo para DOC |
| Planilhas | XLSX e XLS | XML interno para XLSX; `xlrd` para XLS |
| Imagens/OCR | BMP, GIF, JPEG, PNG, TIFF e WebP | Pillow, `pytesseract` e Tesseract externo |
| Compactados | ZIP, TAR, TAR.GZ/TGZ, TAR.BZ2 e TAR.XZ | membros em memoria, sem extracao no disco |
| Bancos | DB, DB3, SQLITE e SQLITE3 | somente SQLite, aberto em modo somente leitura |

Outros formatos sao ignorados. Arquivos maiores que 50 MiB sao ignorados por padrao. Arquivos
compactados possuem limites adicionais de profundidade, numero de membros, tamanho individual
e tamanho descompactado total para reduzir risco de zip bomb.

Codigos de saida:

| Codigo | Significado |
|---:|---|
| `0` | varredura concluida sem CPF valido |
| `1` | varredura concluida com ao menos um CPF valido |
| `2` | configuracao, caminho ou escrita de relatorio falhou |

Falhas isoladas de leitura nao interrompem o restante do trabalho. Elas aparecem de forma
agregada no resumo e no relatorio.

## Modos e classificacao

`cpf-anchor` e o modo padrao e somente classifica arquivos com pelo menos um CPF valido.
`full-discovery` e uma estrutura experimental para evolucao: atualmente pode registrar regras
contextuais mesmo sem CPF, sempre como indicador sujeito a revisao, e nao como conclusao sobre
ilicitude ou violacao da LGPD.

Cada achado inclui score total, nivel, metodologia `1.0`, confianca separada, dimensoes,
categorias, contagens, informacoes desconhecidas e recomendacoes. Consulte
[a metodologia completa](docs/METODOLOGIA.md).

Para deduplicar CPFs entre ocorrencias sem persisti-los, defina um segredo forte em variavel de
ambiente. Sem segredo, nenhum identificador persistente e produzido:

```bash
export CPF_LGPD_HMAC_SECRET="valor-longo-obtido-de-um-cofre"
cpf-lgpd /dados --report resultado.json
```

Nao passe o segredo na linha de comando nem o coloque no arquivo de configuracao.

Exemplo de configuracao local:

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

## Saida e privacidade

O terminal apresenta apenas contagens. O JSON opcional inclui caminhos e contagens por arquivo,
classificacao e recomendacoes, mas **nao inclui CPFs**. O CSV oferece uma visao tabular resumida.
Ambos sao criados atomicamente com permissao `0600`; ACLs em Windows e
armazenamentos remotos ainda devem ser configuradas pelo operador.

Como caminhos podem revelar nomes de pessoas, departamentos ou casos, trate o relatorio como
informacao confidencial:

1. grave-o fora da arvore examinada;
2. limite acesso e habilite criptografia em repouso;
3. nao envie o arquivo a logs, tickets ou canais publicos;
4. defina e cumpra um prazo curto de retencao;
5. registre aprovacao, responsavel, escopo e descarte da execucao.

O scanner nao segue links simbolicos. Texto simples e lido em blocos; formatos que dependem de
bibliotecas de terceiros podem ser carregados em memoria, sempre sujeitos ao limite por arquivo.
Somente UTF-8 e aceito para texto simples; arquivos com outra codificacao sao contabilizados
como falha, evitando interpretacao silenciosamente incorreta.

## Desenvolvimento

```bash
python -m pip install -e '.[dev]'
ruff check .
python -m unittest discover -v
coverage run -m unittest discover
coverage report
```

Use apenas CPFs sintéticos validos destinados a testes. Nunca inclua dados pessoais reais em
fixtures, commits, issues ou pull requests.

## Limitacoes

- bancos que nao sejam SQLite, arquivos criptografados e formatos proprietarios nao sao lidos;
- PDF digitalizado nao passa automaticamente por OCR nesta versao; converta suas paginas em
  imagens dentro de um fluxo aprovado se essa cobertura for necessaria;
- OCR pode produzir falsos positivos e falsos negativos e exige revisao humana;
- arquivos protegidos por senha sao registrados como falha, sem tentativa de quebra de senha;
- a presenca de um CPF nao demonstra uso indevido: o contexto deve ser revisado por pessoa
  autorizada;
- o relatorio indica onde revisar, mas nao deve ser usado para republicar o dado encontrado;
- varreduras em grande escala devem ser planejadas para evitar impacto em rede e armazenamento.
- as regras deterministicas podem produzir falsos positivos e falsos negativos;
- nenhum resultado afirma automaticamente ilegalidade ou violacao da LGPD e toda classificacao
  exige validacao humana pelo responsavel apropriado.

## Seguranca

Consulte [SECURITY.md](SECURITY.md) para comunicar vulnerabilidades sem divulgar dados pessoais.

## Licenca

Distribuido sob a [GNU General Public License v3.0](LICENSE).
