# Relatório de Revisão de Código - Juice Shop


- [Relatório de Revisão de Código - Juice Shop](#relatório-de-revisão-de-código---juice-shop)
  - [Introdução](#introdução)
  - [Escopo](#escopo)
  - [Metodologia](#metodologia)
    - [1. Planejamento](#1-planejamento)
    - [2. Execução Automatizada](#2-execução-automatizada)
    - [3. Análise Manual](#3-análise-manual)
    - [4. Consolidação dos Resultados](#4-consolidação-dos-resultados)
  - [Ferramentas](#ferramentas)
    - [1. Dependency Check](#1-dependency-check)
    - [2. Gitleaks](#2-gitleaks)
    - [3. Horusec](#3-horusec)
    - [4. Bearer](#4-bearer)
    - [5. Snyk](#5-snyk)
    - [6. Semgrep](#6-semgrep)
- [Achados](#achados)
  - [1. Vulnerabilidades Críticas em Dependências](#1-vulnerabilidades-críticas-em-dependências)
  - [2. Leaks de Segredos no Código](#2-leaks-de-segredos-no-código)
  - [2. Hardcoded Credentials](#2-hardcoded-credentials)
  - [3. SQL Injection](#3-sql-injection)
  - [4. NoSQL Injection](#4-nosql-injection)
  - [5. Path Traversal](#5-path-traversal)
  - [6. Server-Side Request Forgery (SSRF)](#6-server-side-request-forgery-ssrf)
  - [7. Cross-site Scripting (XSS)](#7-cross-site-scripting-xss)
  - [8. Arbitrary File Write via Archive Extraction](#8-arbitrary-file-write-via-archive-extraction)
  - [9. Observable Timing Discrepancy](#9-observable-timing-discrepancy)
  - [10. Denial-of-Service (DoS) via ReDoS](#10-denial-of-service-dos-via-redos)


## Introdução

Este relatório documenta a análise de segurança realizada no projeto **Juice Shop**, como parte da disciplina **Revisão de Código e Análise Estática Automatizada** da pós-graduação em **Cibersegurança** na **CESAR School**, sob a orientação do professor **Eduardo Santos**. O trabalho foi desenvolvido pelos alunos **XXX** e **XXX**.

O objetivo principal desta análise é identificar vulnerabilidades no código-fonte e nas dependências do projeto, utilizando ferramentas automatizadas e complementando os resultados com uma revisão manual. O relatório propõe soluções práticas para mitigar os riscos identificados, priorizando vulnerabilidades mais críticas.


## Escopo

O escopo deste trabalho abrange o projeto **Juice Shop**, disponível no repositório oficial:
- **Repositório GitHub**: [https://github.com/juice-shop/juice-shop](https://github.com/juice-shop/juice-shop)

O **Juice Shop** é uma aplicação vulnerável, projetada para fins educacionais em segurança de software. Neste trabalho, a análise incluiu:
- Código-fonte da aplicação.
- Dependências listadas nos arquivos de gerenciamento de pacotes (`package-lock.json`, entre outros).
- Identificação de segredos (chaves, tokens, etc.) expostos no código.


## Metodologia

### 1. Planejamento
O planejamento consistiu na definição do escopo, ferramentas e preparação do ambiente para a execução da análise. As ferramentas foram instaladas e configuradas para atender aos objetivos da análise, priorizando vulnerabilidades críticas.

### 2. Execução Automatizada
As ferramentas automatizadas foram executadas para realizar três tipos de análises principais:

- *SAST (Static Application Security Testing)*: Detecção de vulnerabilidades diretamente no código-fonte.
- *SCA (Software Composition Analysis)*: Identificação de vulnerabilidades em dependências de software.
- *Secrets Scanning*: Busca de chaves, senhas e outros segredos expostos no código.
  
Os resultados foram exportados em formatos como `json`, `csv`, `txt`e `html` e processados em *Jupyter Notebooks* para exploração de dados, geração de gráficos e identificação de padrões. Essa análise de dados exploratória foi fundamental para organizar os achados e direcionar as etapas seguintes.

### 3. Análise Manual
A análise manual foi conduzida com foco nas vulnerabilidades críticas identificadas na execução automatizada. Foram avaliados os seguintes aspectos:

- Validações de entrada e saída: Identificação de falhas de sanitização e exposição de dados.
- Autenticação e autorização: Revisão de práticas inseguras.
- Dependências vulneráveis: Avaliação da necessidade de atualização ou substituição de bibliotecas.
  
Esta etapa complementou a análise automatizada, reduzindo falsos positivos e aprofundando a investigação de vulnerabilidades específicas.

### 4. Consolidação dos Resultados
Na etapa final, os achados foram agrupados e classificados com base em suas características, como tipo, gravidade e impacto. Recomendações específicas para mitigação foram desenvolvidas para os grupos de vulnerabilidades mais relevantes, priorizando soluções práticas e eficazes.


## Ferramentas

### 1. Dependency Check
[Dependency Check](https://github.com/jeremylong/DependencyCheck) detecta vulnerabilidades públicas em dependências de um projeto, gerando relatórios vinculados.

Relatórios disponíveis nos formatos [JSON](reports/dependency-check/dependency-check-report.json), [CSV](reports/dependency-check/dependency-check-report.csv).

- [Análise Exploratória](reports/dependency-check/notebook.ipynb)

### 2. Gitleaks
[Gitleaks](https://github.com/gitleaks/gitleaks) verifica segredos expostos, como chaves de API, tokens e senhas, em repositórios git e arquivos locais.

Relatórios disponíveis nos formatos [JSON](reports/gitleaks/gitleaks-report.json).  
- [Análise Exploratória](reports/gitleaks/notebook.ipynb)

### 3. Horusec
[Horusec](https://github.com/ZupIT/horusec) realiza análise estática do código e busca por segredos em múltiplas linguagens, integrando SAST e secrets scanning.

Relatórios disponíveis nos formatos [JSON](reports/horusec/horusec-report.json) e [TXT](reports/horusec/horusec-report.txt).  
- [Análise Exploratória](reports/horusec/notebook.ipynb)


### 4. Bearer
[Bearer](https://github.com/Bearer/bearer) realiza análise estática do código-fonte para detectar vulnerabilidades, além de riscos relacionados à privacidade e segurança, gerando relatórios com descrições e remediações.

Relatórios disponíveis nos formatos [JSON](reports/bearer/prettified-medium-high-critical-report.json) e HTML.
- [Relatório HTML](https://htmlpreview.github.io/?https://raw.githubusercontent.com/pedro-coelho-dr/code-review-exercise/refs/heads/main/reports/bearer/medium-high-critical-report.html?token=GHSAT0AAAAAAC2MHWZTTGOGIVWUG5CV6VISZ327CDQ)  
- [Análise Exploratória](reports/bearer/notebook.ipynb)


### 5. Snyk
[Snyk](https://snyk.io) identifica vulnerabilidades no código e dependências com sugestões de remediação.

Relatórios disponíveis nos formatos [JSON](reports/snyk/snyk-report.json) [CSV](reports/snyk/rule_summary.csv) e HTML.

- [Relatório HTML](https://htmlpreview.github.io/?https://raw.githubusercontent.com/pedro-coelho-dr/code-review-exercise/refs/heads/main/reports/snyk/snyk-report.html?token=GHSAT0AAAAAAC2MHWZSB7Q4P4N47EDO3LAIZ327CBQ)
  
- [Análise Exploratória](reports/snyk/notebook.ipynb)

### 6. Semgrep
[Semgrep](https://github.com/semgrep/semgrep) identifica padrões inseguros e vulnerabilidades em diversas linguagens com uma análise estática rápida e personalizável.

Relatórios disponíveis nos formatos [JSON](reports/semgrep/prettified-semgrep-results.json) e [TXT](reports/semgrep/semgrep-results.txt).

- [Análise Exploratória](reports/semgrep/notebook.ipynb)


# Achados

## 1. Vulnerabilidades Críticas em Dependências

Utilizando a ferramenta Dependency Check, foram identificadas **156 vulnerabilidades**, das quais **22 são críticas**. Os gráficos apresentados abaixo ilustram a distribuição das vulnerabilidades por severidade e destacam a quantidade de vulnerabilidades críticas por dependência.

![Distribuição de Severidade](img/dc-severity.png)

![Vulnerabilidades Críticas por Dependência](img/dc-crit.png)

A análise a seguir foca exclusivamente nas vulnerabilidades críticas, agrupando-as em categorias para facilitar a priorização e entendimento dos problemas detectados.


**1. Criptografia Fraca**

Problemas relacionados ao uso de algoritmos de criptografia fracos, inseguros ou mal implementados.
Dependências Afetadas:

- `crypto-js:3.3.0`
  - CWE: CWE-327 (Broken/Risky Cryptographic Algorithm), CWE-328 (Weak Hash), CWE-916 (Password Hash With Insufficient Computational Effort)
  - Descrição: Biblioteca de padrões criptográficos com algoritmos de hash e criptografia inseguros.
- `elliptic:6.5.4`
  - CWE: CWE-347 (Improper Verification of Cryptographic Signature)
  - Descrição: Problema na verificação de assinaturas criptográficas.

**2. Autorização e Validação Improprias**

Falhas de autorização e validação de entradas que podem expor o sistema a ataques.
Dependências Afetadas:
- `express-jwt:0.1.3`
  - CWE: CWE-863 (Incorrect Authorization), CWE-285 (Improper Authorization)
  - Descrição: Middleware de autenticação JWT com validação insuficiente.
- `jsonwebtoken:0.1.0 / 0.4.0`
  - CWE: CWE-20 (Improper Input Validation), CWE-327 (Broken Cryptographic Algorithm)
  - Descrição: Implementação de JWT com falhas de validação de entrada.

**3. Pollution de Prototype**

Vulnerabilidades que permitem manipulação insegura de atributos do protótipo em JavaScript.
Dependências Afetadas:
- `lodash.js, lodash.min.js, lodash:2.4.2`
  - CWE: CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
  - Descrição: Uso inadequado do protótipo pode levar à execução não autorizada de código.
- `minimist:0.2.4`
  - CWE: CWE-1321
  - Descrição: Opções de argumento parseadas de maneira insegura.
- `tough-cookie:2.5.0`
  - CWE: CWE-1321
  - Descrição: Implementação insegura de RFC6265 Cookies and Cookie Jar para Node.js.

**4. Injeção de Código e Dados**
Falhas que permitem a execução de comandos maliciosos ou injeção de código.
Dependências Afetadas:
- `vm2:3.9.17`
  - CWE: CWE-74 (Improper Neutralization of Special Elements in Output), CWE-94 (Improper Control of Code Generation), CWE-78 (OS Command Injection)
  - Descrição: Sandbox inseguro permite a execução de código malicioso.
  

**5. Escrita Fora dos Limites**
Vulnerabilidades que podem causar comportamentos inesperados e comprometer a segurança de memória.
Dependências Afetadas:
- `opener:1.5.2`
  - CWE: CWE-787 (Out-of-bounds Write)
  - Descrição: Executáveis abertos de forma insegura podem comprometer a aplicação.


**Recomendações:**

1. Atualização de Dependências: Atualizar para versões seguras das bibliotecas listadas, priorizando aquelas com vulnerabilidades críticas.
   
1. Revisão de Implementações: Verificar pontos críticos do sistema onde as dependências afetadas são utilizadas para minimizar o impacto de vulnerabilidades não corrigidas.

1. Adoção de Ferramentas de SCA Contínuas: Integrar ferramentas como Dependency Check ou Snyk no pipeline de CI/CD para detecção precoce de vulnerabilidades em dependências.

2. Hardening do Código: Adotar padrões de desenvolvimento seguro, incluindo a validação de entradas e a utilização de algoritmos criptográficos recomendados.

3. Monitoramento Contínuo: Acompanhar atualizações de segurança em dependências críticas e garantir que versões vulneráveis sejam rapidamente substituídas.

## 2. Leaks de Segredos no Código

Durante a análise com ferramentas como Gitleaks e Horusec, foram identificados *leaks* de segredos em diversos arquivos do projeto. Esses segredos incluem **API Keys**, **JWTs** e **chaves privadas**. O gráfico abaixo ilustra a distribuição desses achados entre os arquivos analisados.


![alt text](img/gl-leaks.png)

**Exemplos de Leaks Identificados**

**1. API Key**

- Arquivo: `test/api/basketApiSpec.js`  
- Linha 95-103:
  ```typescript
  describe('/rest/basket/:id', () => {
  it('GET existing basket of another user', () => {
    return frisby.post(REST_URL + '/user/login', {
      headers: jsonHeader,
      body: {
        email: 'bjoern.kimminich@gmail.com',
        password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
      }
    })
  ```

- Impacto: A exposição de uma chave de API permite que um atacante acesse recursos protegidos ou interfira no funcionamento do sistema associado à API.

- Recomendação:
   - Não incluir chaves diretamente no código-fonte. Utilize variáveis de ambiente para armazená-las.
  - Revogar e substituir chaves comprometidas imediatamente.

**2. JWT (JSON Web Token)**

- Arquivo: `/frontend/src/app/app.guard.spec.ts`
- Linha 40:
  ```typescript
    localStorage.setItem('token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')
  ```

- Impacto: Tokens JWT expostos podem ser usados por atacantes para realizar ações autenticadas como outro usuário.
  
- Recomendação:

  - Nunca expor tokens diretamente no código ou logs.
  - Implementar um curto período de validade para os tokens e utilizar refresh tokens.
  - Rotacionar chaves secretas utilizadas para assinar os tokens regularmente.

**3. Private Key**

- Arquivo: `/lib/insecurity.ts`
- Linha 23:
  ```typescript
  const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'
  ```

- Impacto: A exposição de chaves privadas compromete a segurança da comunicação criptografada e pode permitir o acesso não autorizado a sistemas.
  
- Recomendação:

  - Nunca incluir chaves privadas no repositório de código.
  - Armazenar chaves privadas em cofres de segredos ou sistemas de gerenciamento de credenciais.
  - Revogar e substituir chaves comprometidas imediatamente.


## 2. Hardcoded Credentials

Durante a análise, foram detectadas múltiplas credenciais codificadas diretamente no código, o que representa um risco significativo à segurança. Esses dados incluem informações como senhas base64 codificadas diretamente nos métodos de autenticação.

- Arquivo:`frontend/src/app/oauth/oauth.component.spec.ts`

- Linha 85:
  ```typescript
  expect(userService.save).toHaveBeenCalledWith({ email: 'test@test.com', password: 'bW9jLnRzZXRAdHNldA==', passwordRepeat: 'bW9jLnRzZXRAdHNldA==' })
  ```

- Impacto:

    - Expõe as credenciais diretamente no código, facilitando ataques de engenharia reversa.
    - Permite que um invasor extraia credenciais por meio do repositório de código ou de builds da aplicação.
  
- Recomendações:

  - Armazenamento Seguro: Use soluções como variáveis de ambiente ou cofres de segredos (AWS Secrets Manager, HashiCorp Vault).
  - Remoção de Credenciais: Substitua as credenciais hardcoded por referências dinâmicas que busquem os valores em tempo de execução.
  - Validação em CI/CD: Configure ferramentas como Gitleaks para detectar automaticamente credenciais codificadas nos pipelines de build.


## 3. SQL Injection

## 4. NoSQL Injection

## 5. Path Traversal

## 6. Server-Side Request Forgery (SSRF)


## 7. Cross-site Scripting (XSS)


## 8. Arbitrary File Write via Archive Extraction


## 9. Observable Timing Discrepancy
Filename: frontend/src/app/forgot-password/forgot-password.component.ts:118


## 10. Denial-of-Service (DoS) via ReDoS

A vulnerabilidade identificada está relacionada ao uso de expressões regulares dinâmicas construídas com entradas potencialmente controladas por usuários, que podem ser exploradas para causar um **Regular Expression Denial of Service (ReDoS)**. Isso ocorre quando expressões regulares ineficientes bloqueiam o thread principal, consumindo recursos excessivos do sistema.

- Arquivo: `lib/codingChallenges.ts`
- Linha: 76
  ```typescript
  if (new RegExp(`vuln-code-snippet vuln-line.*${challengeKey}`).exec(lines[i]) != null) {
  ```
- CWE: CWE-1333 (Complexidade Ineficiente em Expressão Regular)

- Impacto: Essa prática pode causar uma negação de serviço, impedindo o funcionamento normal da aplicação.


- Recomendações

  - Evitar RegEx Dinâmico: Substituir expressões regulares dinâmicas por expressões estáticas, sempre que possível.
  - Validação de Entrada: Adicionar validação robusta para qualquer entrada de usuário antes de usá-la em expressões regulares.
  - Monitoramento e Limite de Recursos: Configurar limites de tempo para a execução de expressões regulares usando bibliotecas como safe-regex.