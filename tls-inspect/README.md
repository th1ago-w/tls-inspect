# TLS Inspect

Ferramenta de terminal em Python para consultar certificados TLS, mostrar emissor e validade e sinalizar vencimento próximo. Complementa o HTTP Inspect: este projeto inspeciona a conexão TLS, sem fazer requisições HTTP.

Projeto educacional. Usa somente a biblioteca padrão do Python.

## Executar

Requer Python 3.10 ou superior, com suporte a SSL. Baixe e extraia os arquivos, abra um terminal na pasta e execute:

```bash
python tls_inspect.py --demo
```

A demonstração funciona sem internet. Todos os dados e o resultado da conexão são fictícios, identificados como simulados. O certificado de exemplo vence em 14 dias a partir da execução.

Para uma consulta real:

```bash
python tls_inspect.py example.com
python tls_inspect.py example.com --json relatorio.json
python tls_inspect.py example.com --warn-days 15 --timeout 10
python tls_inspect.py example.com --port 8443
```

Informe apenas o domínio ou IP, sem `https://`, caminho ou porta. No Windows, tente `py` no lugar de `python` se necessário. Não precisa instalar pacotes.

## Informações apresentadas

- Destino e porta consultados.
- Resultado da validação TLS pelo ambiente Python.
- Titular, emissor e nomes alternativos do certificado.
- Início e fim da validade em UTC.
- Dias completos restantes e alerta de vencimento.
- Versão TLS e cifra negociadas naquela conexão.
- Relatório JSON opcional, sem sobrescrever um arquivo existente.

Exemplo parcial do modo offline:

```text
DEMONSTRAÇÃO OFFLINE: certificado e conexão fictícios.

TLS Inspect
Destino: exemplo.test:443
Validação TLS: simulada
Situação: vence em breve
Dias restantes (completos): 14
```

## Validação e códigos de saída

As consultas reais usam `ssl.create_default_context()`, com verificação da cadeia de confiança, datas e nome do destino. O domínio também é usado no handshake para seleção do certificado (SNI, quando aplicável). Não há opção para desativar a verificação.

Quando a validação falha, a conexão é recusada e o programa apresenta um erro em vez de exibir o certificado como confiável. Certificados expirados ou ainda não válidos normalmente seguem esse caminho; os estados de data também existem na função de análise para dados de teste.

| Código | Significado |
| --- | --- |
| 0 | Consulta concluída, validade além do limiar de alerta |
| 1 | Consulta concluída com alerta de prazo; também é o resultado padrão de `--demo` |
| 2 | Erro de argumentos, conexão, certificado ou gravação |

O limiar padrão é 30 dias, configurável por `--warn-days`. A comparação usa segundos; a apresentação dos dias arredonda para baixo. Um resultado de zero dias pode significar menos de 24 horas restantes.

## Testes

```bash
python -m unittest -v
```

Os testes não dependem da internet. Cobrem validação de entradas, datas, SNI, configuração de confiança, falhas de certificado, demonstração e exportação. A conexão é simulada nos testes de unidade.

## Limitações

- Inspeciona o certificado final do servidor, não lista toda a cadeia.
- Usa as autoridades e a configuração TLS disponíveis no ambiente Python; pode diferir de um navegador.
- Não faz consulta explícita de revogação OCSP/CRL nem auditoria de Certificate Transparency.
- Mostra somente a versão e a cifra negociadas; não enumera todas as configurações aceitas pelo servidor.
- Não segue redirecionamentos HTTP nem suporta STARTTLS.
- O timeout se aplica às operações de conexão e handshake, não é um prazo global de execução incluindo DNS.
- Uma conexão validada não comprova que o site seja legítimo ou livre de vulnerabilidades.

## Arquivos

```text
tls_inspect.py        Programa principal
test_tls_inspect.py   Testes automatizados
README.md            Instruções e limitações
```

## Referência

[Documentação oficial do módulo ssl do Python](https://docs.python.org/3/library/ssl.html).

## Próximas melhorias

- Consultar uma lista de domínios com limite de concorrência.
- Comparar resultados com relatórios anteriores.
- Adicionar testes de integração com certificados de uma autoridade local de teste.

## Demonstração

<img width="1650" height="1050" alt="image" src="https://github.com/user-attachments/assets/b5ae1796-2991-4a5d-a623-329dd7048493" />
