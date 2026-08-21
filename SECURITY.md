# Politica de seguranca

## Comunicacao responsavel

Nao abra uma issue publica quando a falha puder expor CPFs, credenciais, caminhos internos ou
outros dados pessoais. Use o recurso **Private vulnerability reporting** do GitHub. Se ele nao
estiver disponivel, contate o mantenedor por um canal privado previamente verificado.

Inclua versao, impacto e passos minimos para reproducao. Substitua nomes, caminhos, dominios e
CPFs por valores sinteticos. Nao anexe arquivos corporativos nem evidencias com dados pessoais.

## Escopo operacional

- execute somente em diretorios expressamente autorizados;
- use conta de leitura com privilegio minimo;
- no Windows, use caminho UNC e conta dedicada, sem Domain Admin, para que ACL NTFS e SMB sejam
  avaliadas no contexto operacional autorizado;
- proteja e descarte relatorios segundo a politica do controlador;
- interrompa a execucao e acione seguranca/privacidade diante de exposicao inesperada;
- nunca publique resultados em issues, logs de CI ou pull requests.
- mantenha limites de arquivos compactados para evitar zip bombs e nao processe arquivos nao
  confiaveis fora de um ambiente isolado;
- trate OCR e parsers de documentos como superficie de ataque e mantenha Python, Tesseract,
  antiword e dependencias atualizados.
- no modo corporativo, mantenha `permission_mode` e `report_protection_mode` como `strict`;
- proteja previamente o diretorio de relatorios, pois a ferramenta restringe os arquivos gerados,
  mas nao altera a ACL do diretorio existente;
- trate `unknown` em ACL como pendencia de validacao, nunca como confirmacao de acesso restrito.

Versoes sem suporte de Python e commits fora da branch principal nao recebem atualizacoes de
seguranca garantidas.
