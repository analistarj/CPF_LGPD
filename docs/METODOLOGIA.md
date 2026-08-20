# Metodologia de descoberta e risco, versão 1.1

## Princípios

A ferramenta produz indicadores técnicos para revisão humana. O processamento é local,
determinístico, sem telemetria e sem modelos externos. Valores pessoais, nomes, células e trechos
dos documentos não integram resultados nem logs.

O motor separa três conceitos:

- detecção, que localiza uma regra em uma unidade estrutural;
- confiança, que mede a força da evidência e do vínculo;
- risco, que prioriza o arquivo após deduplicação por categoria.

O conjunto de regras sensíveis é `lgpd-br-1.0.0`. A metodologia do score é `1.1`.

## Rastreabilidade

Cada arquivo analisado recebe `root_id`, caminhos original, absoluto ou UNC, canônico e relativo,
nome, extensão, tamanho, datas disponíveis, proprietário técnico e fonte das permissões.

No Linux, `ctime` não é tratado como data de criação. Quando não existe `birthtime`, `created_at`
fica `unknown`. `created_by` e `last_modified_by` ficam sempre `unknown` sem fonte confiável de
auditoria.

As ocorrências guardam somente localização estrutural:

| Formato | Localização |
|---|---|
| CSV | linha, coluna e cabeçalho |
| XLSX e XLS | planilha, linha, coluna e cabeçalho |
| JSON | JSONPath e objeto do registro |
| XML | XPath e elemento do registro |
| PDF | página e linha extraída |
| DOCX | parágrafo ou tabela, linha e coluna |
| TXT e texto | número da linha |
| outros | posição, membro ou unidade contextual disponível |

## Confiança

A confiança segue a fórmula documentada em
[SENSITIVE_DATA_RULES.md](SENSITIVE_DATA_RULES.md). A confirmação exige pessoa, evidência e vínculo
forte. No modo `cpf-anchor`, a pessoa deve estar ancorada por CPF matematicamente válido na mesma
unidade verificável.

Faixas de confiança:

- 85 a 100: `alta`;
- 70 a 84: `media`;
- abaixo de 70: `possivel_ocorrencia`.

Possíveis ocorrências recebem zero ponto de risco.

## Fórmula do risco

```text
risk_score = min(100, conteudo + exposicao + volume + governanca)
```

`confidence_score` nunca é somado ao `risk_score`.

### Conteúdo, máximo 40

- CPF válido presente no arquivo: 5;
- identificadores adicionais: 2 por categoria, máximo 10;
- alto impacto operacional: 10 para uma categoria ou 15 para duas ou mais;
- uma categoria sensível com confiança média: 15;
- uma categoria sensível com confiança alta: 20;
- duas ou mais categorias sensíveis com confiança média ou alta: 25 no total;
- parcela sensível limitada a 25;
- dimensão de conteúdo limitada a 40.

Repetições não ampliam a parcela sensível. A quantidade de titulares afeta somente volume.

### Exposição, máximo 30

| Sinal técnico | Pontos |
|---|---:|
| proprietário restrito | 0 |
| grupo interno limitado | 5 |
| todos os usuários internos | 22 |
| externo, público ou anônimo | 30 |
| desconhecido | 10 |

O adaptador POSIX usa bits de modo e declara a fonte. Ele não presume que leitura por outros seja
publicação externa. Windows retorna desconhecido enquanto não houver adaptador de ACL configurado.

### Volume, máximo 15

| CPFs únicos | Pontos |
|---:|---:|
| 1 | 1 |
| 2 a 9 | 3 |
| 10 a 99 | 7 |
| 100 a 999 | 11 |
| 1.000 ou mais | 15 |

### Governança, máximo 15

- proprietário técnico desconhecido: 5;
- origem, finalidade ou base legal não informada: 5 no conjunto;
- retenção desconhecida ou vencida: 5.

## Faixas do risco

| Risk score | Nível |
|---:|---|
| 0 a 19 | baixo |
| 20 a 39 | moderado |
| 40 a 59 | alto |
| 60 a 79 | muito alto |
| 80 a 100 | crítico |

## Exemplo minimizado

```json
{
  "root_id": "root-synthetic",
  "relative_path": "area/controlada/exemplo.xlsx",
  "location": {"sheet": "Titulares", "row": 2, "column": 4, "header": "Diagnostico"},
  "rule_id": "LGPD-SENS-009",
  "legal_category": "health",
  "subtype": "health",
  "confidence_score": 100,
  "confidence_level": "alta",
  "risk_points": 20,
  "match_count": 1,
  "requires_human_review": true,
  "ruleset_version": "lgpd-br-1.0.0",
  "score_version": "1.1"
}
```

O exemplo não contém identificador, nome, trecho ou valor sensível.

## Segurança de caminhos e relatórios

Antes da leitura, o caminho é resolvido e comparado à raiz canônica. Links simbólicos, junctions e
segmentos relativos não podem escapar da raiz autorizada. Credenciais em URLs e parâmetros comuns
de segredo são removidos dos metadados. Sequências com formato de CPF são mascaradas mesmo quando
falham na validação matemática.

O relatório técnico contém caminhos completos. O executivo contém raiz lógica e caminho relativo.
Os dois usam escrita atômica e modo `0600`. ACLs de Windows e controles do armazenamento remoto
continuam sob responsabilidade do operador.

## Revisão e remediação

1. validar a localização sem republicar valores;
2. confirmar categoria, vínculo e confiança;
3. identificar finalidade, base legal, proprietário e retenção;
4. revisar acesso e necessidade;
5. avaliar mascaramento, pseudonimização ou repositório controlado;
6. executar quarentena ou eliminação somente com aprovação;
7. iniciar triagem de incidente quando houver evidência de divulgação não autorizada.

O programa não move, exclui, criptografa, coloca em quarentena nem altera arquivos.
