# Regras de dados pessoais sensíveis

## Fundamento legal e escopo

O motor implementa uma taxonomia operacional baseada no art. 5º, II, da Lei nº 13.709/2018.
Todas as regras usam `legal_basis: LGPD_ART_5_II` e o conjunto de regras tem versão
`lgpd-br-1.0.0`.

O resultado é um indicador técnico para revisão. Ele não conclui que o tratamento é lícito ou
ilícito, não substitui análise jurídica e não infere atributo sensível a partir de nome,
fotografia, endereço, localização ou estatística.

## Taxonomia legal

As únicas categorias legais produzidas pelo motor são:

| Categoria | Significado operacional |
|---|---|
| `racial_ethnic_origin` | origem racial ou étnica declarada em campo ou afirmação explícita |
| `religious_belief` | convicção, crença, religião ou credo de pessoa identificável |
| `political_opinion` | opinião política declarada e vinculada a pessoa |
| `union_membership` | filiação ou condição de membro de sindicato |
| `religious_philosophical_political_organization_membership` | filiação a organização religiosa, filosófica ou política |
| `health` | diagnóstico, doença, tratamento, prontuário ou condição de saúde |
| `sexual_life` | vida, comportamento ou orientação sexual |
| `genetic` | dado, teste, perfil ou sequenciamento genético |
| `biometric` | dado biométrico usado para identificação, reconhecimento ou autenticação |

## Subtipos operacionais

`orientation_sexual` é subtipo de `sexual_life`.

`political_position`, `political_preference` e `voting_intention` são subtipos de
`political_opinion`. Eles só são confirmados quando existe pessoa identificada ou identificável e
vínculo verificável com a evidência.

Cada regra contém e publica estes metadados:

```text
rule_id
legal_category
legal_basis
subtype
ruleset_version
positive_indicators
negative_indicators
required_person_anchor
required_link_method
confidence_calculation
risk_points
```

## Condições de confirmação

Uma ocorrência confirmada exige simultaneamente:

1. pessoa identificada ou identificável;
2. evidência sensível explícita;
3. vínculo estrutural verificável entre a pessoa e a evidência.

No modo `cpf-anchor`, a âncora deve ser um CPF matematicamente válido. Um número com onze dígitos
que falhe nos dígitos verificadores não serve como âncora.

São vínculos fortes: mesma linha ou registro estruturado, mesmo objeto JSON, mesmo elemento XML,
campo sensível ligado ao registro da pessoa, declaração textual direta e mesma linha de tabela em
DOCX ou PDF. Proximidade entre linhas, objetos ou parágrafos diferentes não confirma a ocorrência.

No modo `full-discovery`, outro identificador pessoal explícito pode servir de âncora. A regra
continua exigindo o vínculo forte. Evidência sem âncora fica como `possivel_ocorrencia` e não pontua.

## Fórmula de confiança

O cálculo é determinístico e limitado ao intervalo de 0 a 100. Em cada eixo, o motor usa a
evidência aplicável e registra o método utilizado.

| Evidência | Pontos |
|---|---:|
| CPF matematicamente válido como âncora | 20 |
| mesma linha, registro ou objeto | 40 |
| declaração direta no mesmo período | 35 |
| mesmo parágrafo ou janela contextual | 20 |
| cabeçalho sensível explícito com valor | 40 |
| declaração textual explícita | 35 |
| palavra apenas indicativa | 15 |
| ambiguidade | menos 20 a menos 60 |
| regra negativa confirmada | confiança zero |

Faixas:

| Score | Nível de máquina |
|---:|---|
| 85 a 100 | `alta` |
| 70 a 84 | `media` |
| 0 a 69 | `possivel_ocorrencia` |

Palavra isolada não é uma ocorrência. A proximidade simples não fornece vínculo. Uma ocorrência
possível sempre exige revisão humana e acrescenta zero ao `risk_score`.

## Indicadores positivos

O motor procura cabeçalhos com valor ou declarações explícitas, por exemplo:

| Categoria | Exemplo sintético de estrutura |
|---|---|
| `racial_ethnic_origin` | colunas `CPF` e `Raça` na mesma linha |
| `religious_belief` | objeto com `cpf` e `religiao` |
| `political_opinion` | registro com `CPF` e `Intenção de voto` |
| `union_membership` | campos `CPF` e `Filiação sindical` |
| organização | afirmação de que a pessoa é membro de organização filosófica |
| `health` | campos `CPF` e `Diagnóstico` |
| `sexual_life` | campos `CPF` e `Orientação sexual` |
| `genetic` | campos `CPF` e `Teste genético` |
| `biometric` | reconhecimento facial destinado a autenticação da pessoa |

Os exemplos de teste usam somente dados artificiais e não são copiados para relatórios.

## Regras negativas obrigatórias

As expressões abaixo não são classificadas automaticamente:

- política de privacidade;
- política de segurança;
- política comercial;
- saúde financeira;
- saúde do sistema;
- raça de cachorro;
- partido ao meio;
- DNA da empresa;
- impressão digital de documento no sentido de cópia;
- assinatura digital;
- sindicato mencionado genericamente;
- igreja mencionada como endereço ou local;
- fotografia comum sem processamento biométrico.

Fotografia só pode participar de uma regra biométrica quando houver evidência de extração de
características, template, reconhecimento, identificação ou autenticação biométrica.

## Pontuação de risco sensível

Confiança e risco são grandezas independentes:

- uma categoria com confiança média adiciona 15 pontos;
- uma categoria com confiança alta adiciona 20 pontos;
- duas ou mais categorias com confiança média ou alta adicionam 25 pontos no total;
- a parcela sensível tem limite de 25 pontos;
- a dimensão completa de conteúdo permanece limitada a 40 pontos;
- repetições da mesma palavra ou da mesma categoria não aumentam essa parcela;
- quantidade de titulares é representada exclusivamente pela dimensão de volume.

O campo `risk_points` de uma ocorrência mostra a contribuição potencial de sua categoria antes da
deduplicação por categoria e da aplicação do limite de 25. O `score_breakdown.content` mostra o
valor efetivamente usado no score do arquivo.

## Saídas e minimização

O JSON e o CSV publicam caminho, localização estrutural, regra, categoria, subtipo, contagem,
confiança, pontos e versões. Nunca publicam CPF completo, nomes extraídos, valores de campos ou
trechos do documento.

O relatório técnico inclui caminho original, absoluto ou UNC e canônico. O relatório executivo
inclui `root_id` e caminho relativo. Ambos são gravados atomicamente com permissão `0600` quando o
sistema operacional oferece bits POSIX.

`created_by` e `last_modified_by` permanecem `unknown`. Proprietário técnico e timestamps do
sistema de arquivos não são usados para inferir autoria. Uma integração futura só poderá preencher
esses campos com uma fonte confiável de auditoria.

## Limitações

- extração de PDF depende da qualidade da camada textual;
- OCR recebe penalidade de ambiguidade e exige revisão;
- cabeçalhos não padronizados podem causar falso negativo;
- ausência de achado não comprova ausência de dado sensível;
- ACLs, junctions e datas de criação variam entre sistemas e armazenamentos;
- o relatório técnico pode revelar contexto pelo próprio caminho e deve permanecer protegido;
- o programa não move, exclui, altera, descriptografa nem envia arquivos.

## Processo de revisão humana

1. confirmar que a localização aponta para o registro esperado sem copiar o valor para tickets;
2. validar pessoa, evidência e vínculo;
3. revisar finalidade, base legal, necessidade, acesso e retenção;
4. corrigir falso positivo ou propor nova regra com teste sintético;
5. aprovar eventual restrição, quarentena ou eliminação pelo fluxo corporativo competente;
6. registrar a decisão sem CPF, nome, trecho ou valor sensível.
