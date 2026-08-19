# Metodologia de descoberta e risco — versão 1.0

## Escopo e princípios

A ferramenta produz **indicadores técnicos de risco**, não uma conclusão jurídica. Todo achado
requer validação humana pelo proprietário, encarregado, Segurança da Informação ou Jurídico.
O processamento é local, determinístico, sem telemetria, APIs ou modelos externos, e nenhum
trecho original é persistido.

## Categorias

- **Dado pessoal:** CPF, nome, e-mail, telefone, endereço, nascimento, documento e informação
  profissional.
- **Alto impacto operacional:** informação financeira, autenticação e informação relacionada a
  criança ou adolescente. Essa expressão organiza a priorização e não cria categoria jurídica.
- **Dado pessoal sensível:** origem racial ou étnica, convicção religiosa, opinião política,
  filiação sindical, filiação a organização religiosa/filosófica/política, saúde, vida sexual,
  dado genético e biometria vinculada a pessoa.

As regras exigem rótulos ou padrões explícitos. Nome, fotografia ou endereço nunca são usados
para inferir características sensíveis. Palavra genérica isolada não basta.

## Associação e confiança

- **Alta (90):** rótulo ou padrão no mesmo registro/linha do CPF.
- **Média (70):** regra dentro da janela contextual configurável antes ou depois do CPF.
- **Baixa (30):** rótulo isolado ou ambíguo, registrado como `possible_occurrence`.

Sensível de confiança baixa não pontua conteúdo. `confidence_score` é a média das confianças das
categorias, incluindo o CPF validado com confiança alta, e permanece separado do risco.

## Fórmula do score

`risco = min(100, conteúdo + exposição + volume + governança)`.

### Conteúdo — máximo 40

- CPF válido: 5;
- identificadores adicionais: 2 por categoria, máximo 10;
- alto impacto: 10 para uma categoria ou 15 para duas ou mais;
- sensível vinculado com confiança média/alta: 20 para uma categoria ou 25 para duas ou mais;
- o subtotal é truncado em 40.

### Exposição — máximo 30

- proprietário/restrito: 0;
- grupo interno limitado: 5;
- grupo interno amplo: 15;
- todos os usuários internos ou equivalente: 22;
- externo/público/anônimo: 30;
- desconhecido: 10 e marcação para revisão.

O adaptador POSIX diferencia proprietário, grupo e outros. Ele não presume que leitura por
“outros” prove publicação externa. Windows e armazenamentos cuja ACL não possa ser interpretada
retornam `unknown` sem interromper a varredura.

### Volume — máximo 15

| CPFs únicos | Pontos |
|---:|---:|
| 1 | 1 |
| 2–9 | 3 |
| 10–99 | 7 |
| 100–999 | 11 |
| 1.000 ou mais | 15 |

### Governança — máximo 15

- proprietário desconhecido: 5;
- origem, finalidade ou base legal não informada: 5 no conjunto;
- retenção desconhecida, vencida ou arquivo obsoleto: 5.

Assim, o exemplo conceitual anterior com governança `16` era inconsistente. Um exemplo corrigido
é conteúdo 40 + exposição 15 + volume 7 + governança 15 = **77, muito alto**.

## Faixas

- 0–19: baixo;
- 20–39: moderado;
- 40–59: alto;
- 60–79: muito alto;
- 80–100: crítico.

## HMAC e minimização

CPFs únicos são deduplicados em memória durante cada arquivo. Quando há segredo configurado, o
relatório pode conter HMAC-SHA-256 determinístico; sem segredo, não produz identificador. Hash
simples não é usado. Os valores originais, contextos e trechos não são gravados.

Exemplo sintético e mascarado:

```json
{
  "file_path": "/repositorio/controlado/exemplo.xlsx",
  "cpf_count": 12,
  "unique_cpf_count": 12,
  "risk_score": 77,
  "risk_level": "muito_alto",
  "score_version": "1.0",
  "confidence_score": 90,
  "score_breakdown": {"content": 40, "exposure": 15, "volume": 7, "governance": 15},
  "requires_human_review": true
}
```

## Fluxo de remediação

1. validar o achado e a finalidade;
2. identificar proprietário e base legal;
3. revisar acesso e retenção;
4. avaliar repositório controlado, mascaramento ou pseudonimização;
5. somente após aprovação, avaliar quarentena ou eliminação;
6. acionar triagem de incidente se houver evidência externa de acesso ou divulgação não
   autorizada.

O programa não move, exclui, criptografa, quarentena nem altera o arquivo.

## Limitações

Regras e OCR podem errar; formatos protegidos ou não suportados reduzem cobertura; ACLs podem ser
desconhecidas; ausência de achado não comprova ausência de dados pessoais. Configuração de pesos
altera priorização, mas os limites fixos de 40/30/15/15 e 100 sempre são aplicados.
