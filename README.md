# CPF_LGPD

Script em Python para identificar compartilhamentos indevidos de números de CPF em um domínio do Active Directory, auxiliando na conformidade com a Lei Geral de Proteção de Dados (LGPD).

## Visão geral

Este projeto contém um script que utiliza a biblioteca `pyad` para se conectar ao Active Directory e percorrer unidades organizacionais e compartilhamentos de arquivos em busca de sequências de 11 dígitos que correspondam a números de CPF. Ao final da varredura, ele informa quantos CPFs foram encontrados e em quantos arquivos distintos esses dados estavam presentes. A ferramenta destina-se a apoiar equipes de segurança da informação e compliance na identificação de documentos que armazenam dados pessoais sensíveis.

## Requisitos

- Python 3.8 ou superior
- Biblioteca `pyad`
- Permissões de leitura em compartilhamentos e objetos de diretório que serão analisados
- Acesso de rede ao domínio do Active Directory

Instale as dependências com:

    pip install pyad

## Uso

Clone este repositório e execute o script com as credenciais e parâmetros apropriados. Exemplo:

    python CPF_indevidos.py --dominio MEU.DOMINIO.LOCAL --usuario usuario@dominio.local --senha MinhaSenhaSecreta --pasta \\servidor\compartilhamento

O script irá:

1. Conectar ao domínio usando as credenciais fornecidas.
2. Percorrer pastas e arquivos acessíveis a partir do caminho especificado.
3. Procurar sequências numéricas de 11 dígitos utilizando expressões regulares.
4. Registrar a quantidade total de CPFs encontrados e de arquivos que os contêm.

Para domínios grandes, considere executar fora do horário comercial e monitorar o uso de rede.

## Aviso importante

Você deve ter autorização explícita para acessar e varrer os arquivos do domínio. O tratamento de dados pessoais deve seguir as disposições da LGPD e demais normas aplicáveis. Os desenvolvedores não se responsabilizam por eventuais usos indevidos deste script. Caso encontre dados sensíveis, trate-os de forma segura e, se necessário, remova ou restrinja o acesso conforme as políticas da organização.

## Contribuição

Contribuições são bem-vindas! Relate problemas ou envie solicitações de pull com melhorias. Ao contribuir, siga o estilo de código existente e descreva claramente as alterações.

## Licença

Este projeto está licenciado sob os termos da [GNU GPL versão 3.0](LICENSE).
