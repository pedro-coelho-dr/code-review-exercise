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
  - [3. Hardcoded Credentials](#3-hardcoded-credentials)
  - [4. SQL Injection](#4-sql-injection)
  - [5. NoSQL Injection](#5-nosql-injection)
  - [6. Cross-site Scripting (XSS)](#6-cross-site-scripting-xss)
  - [7. Server-Side Request Forgery (SSRF)](#7-server-side-request-forgery-ssrf)
  - [8. Path Traversal](#8-path-traversal)
  - [9. Arbitrary File Write via Archive Extraction](#9-arbitrary-file-write-via-archive-extraction)
  - [10. Observable Timing Discrepancy](#10-observable-timing-discrepancy)
  - [11. Denial-of-Service (DoS) via ReDoS](#11-denial-of-service-dos-via-redos)


## Introdução

Este relatório documenta a análise de segurança realizada no projeto **Juice Shop**, como parte da disciplina **Revisão de Código e Análise Estática Automatizada** da pós-graduação em **Cibersegurança** na **CESAR School**, sob a orientação do professor **Eduardo Santos**. O trabalho foi desenvolvido pelos alunos **Francisco Moura Fé**, **Pedro Coelho**, **Rivaldo Junior** e **Valdenir Junior**.

O objetivo principal desta análise foi identificar e classificar vulnerabilidades no código-fonte e nas dependências do projeto, utilizando ferramentas automatizadas e complementando os resultados com uma revisão manual. As vulnerabilidades foram organizadas por tipo, com exemplos representativos destacados e recomendações práticas para mitigação.


## Escopo

O escopo deste trabalho abrange o projeto **Juice Shop**, disponível no repositório oficial:

- **Repositório GitHub**: [https://github.com/juice-shop/juice-shop](https://github.com/juice-shop/juice-shop)

O **Juice Shop** é uma aplicação vulnerável, projetada para fins educacionais em segurança de software. Neste trabalho, a análise incluiu:

- Código-fonte da aplicação.
- Dependências listadas nos arquivos de gerenciamento de pacotes (`package-lock.json`, entre outros).
- Identificação de segredos (chaves, tokens, etc.) expostos no código e repositório.


## Metodologia

### 1. Planejamento
O planejamento envolveu a definição do escopo e a configuração das ferramentas automatizadas. Priorizou-se a detecção de vulnerabilidades críticas e de maior impacto.

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
Os achados foram agrupados por tipo de vulnerabilidade (e.g., SQL Injection, XSS, SSRF), abrangendo diferentes áreas do código. Exemplos representativos foram extraídos para ilustrar as falhas, seguidos por recomendações práticas para correção e prevenção. A abordagem focou em fornecer uma visão detalhada e orientada para ação.


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

Relatórios disponíveis nos formatos [JSON](reports/bearer/prettified-medium-high-critical-report.json) e [HTML](reports/bearer/medium-high-critical-report.html).
- [Análise Exploratória](reports/bearer/notebook.ipynb)


### 5. Snyk
[Snyk](https://snyk.io) identifica vulnerabilidades no código e dependências com sugestões de remediação.

Relatórios disponíveis nos formatos [JSON](reports/snyk/snyk-report.json) [CSV](reports/snyk/rule_summary.csv) e [HTML](reports/snyk/snyk-report.html).
  
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


- **Recomendações**
  
  - Atualização de Dependências: Atualizar para versões seguras das bibliotecas listadas, priorizando aquelas com vulnerabilidades críticas.
   
  - Revisão de Implementações: Verificar pontos críticos do sistema onde as dependências afetadas são utilizadas para minimizar o impacto de vulnerabilidades não corrigidas.

  - Adoção de Ferramentas de SCA Contínuas: Integrar ferramentas como Dependency Check ou Snyk no pipeline de CI/CD para detecção precoce de vulnerabilidades em dependências.

  - Hardening do Código: Adotar padrões de desenvolvimento seguro, incluindo a validação de entradas e a utilização de algoritmos criptográficos recomendados.


## 2. Leaks de Segredos no Código

Durante a análise com ferramentas como Gitleaks e Horusec, foram identificados *leaks* de segredos em diversos arquivos do projeto. Esses segredos incluem **API Keys**, **JWTs** e **chaves privadas**. O gráfico abaixo ilustra a distribuição desses achados entre os arquivos analisados.


![alt text](img/gl-leaks.png)


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

- **Impacto**: 
  - A exposição de uma chave de API permite que um atacante acesse recursos protegidos ou interfira no funcionamento do sistema associado à API.

- Recomendação:
  - Não incluir chaves diretamente no código-fonte. Utilize variáveis de ambiente para armazená-las.
  - Revogar e substituir chaves comprometidas imediatamente.

**2. JWT (JSON Web Token)**

- Arquivo: `/frontend/src/app/app.guard.spec.ts`
- Linha 40:
  ```typescript
    localStorage.setItem('token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')
  ```

- **Impacto**
  - Tokens JWT expostos podem ser usados por atacantes para realizar ações autenticadas como outro usuário.
  
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

- **Impacto**
  - A exposição de chaves privadas compromete a segurança da comunicação criptografada e pode permitir o acesso não autorizado a sistemas.
  
- Recomendação:

  - Nunca incluir chaves privadas no repositório de código.
  - Armazenar chaves privadas em cofres de segredos ou sistemas de gerenciamento de credenciais.
  - Revogar e substituir chaves comprometidas imediatamente.


## 3. Hardcoded Credentials

Durante a análise, foram detectadas múltiplas credenciais codificadas diretamente no código, o que representa um risco significativo à segurança. Esses dados incluem informações como senhas `base64` codificadas diretamente nos métodos de autenticação.

- Arquivo:`frontend/src/app/oauth/oauth.component.spec.ts`

- Linha: 85
  ```typescript
  expect(userService.save).toHaveBeenCalledWith({ email: 'test@test.com', password: 'bW9jLnRzZXRAdHNldA==', passwordRepeat: 'bW9jLnRzZXRAdHNldA==' })
  ```

- **Impacto**

    - Expõe as credenciais diretamente no código, facilitando ataques de engenharia reversa.
    - Permite que um invasor extraia credenciais por meio do repositório de código ou de builds da aplicação.
  
- **Recomendações**:

  - Armazenamento Seguro: Use soluções como variáveis de ambiente ou cofres de segredos (AWS Secrets Manager, HashiCorp Vault).
  - Remoção de Credenciais: Substitua as credenciais hardcoded por referências dinâmicas que busquem os valores em tempo de execução.
  - Validação em CI/CD: Configure ferramentas como Gitleaks para detectar automaticamente credenciais codificadas nos pipelines de build.

## 4. SQL Injection

Durante a análise, foram identificadas vulnerabilidades do tipo **SQL Injection** em múltiplas consultas ao banco de dados, tanto em arquivos localizados no diretório `/routes` quanto em `/data`. Essas vulnerabilidades decorrem do uso de entradas não validadas ou sanitizadas diretamente em instruções SQL, permitindo que atacantes manipulem consultas de forma maliciosa.

- **Arquivo:** `/routes/search.ts`
- **Linha:** 23
  
  ```typescript
  models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
  ```
- **Impacto**

  - Exposição de Dados Sensíveis: Atacantes podem extrair informações confidenciais diretamente do banco de dados.
  - Alteração de Dados: Modificações não autorizadas podem ser realizadas no banco de dados.
  - Execução de Comandos Perigosos: Dependendo do privilégio da conta de banco de dados, comandos arbitrários podem ser executados, impactando a integridade da aplicação.
  - Comprometimento Completo do Sistema: Em casos extremos, o acesso ao banco de dados pode ser utilizado para escalar privilégios e comprometer outros componentes do sistema.

- **Recomendações**
  - Utilizar Consultas Parametrizadas: Substituir a interpolação de variáveis diretamente na query por bind parameters ou prepared statements. Por exemplo:

    ```typescript
    models.sequelize.query('SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name', {
        replacements: { criteria: `%${criteria}%` }
    })
    ```

  - Sanitização de Entradas: Adicionar uma camada de validação e sanitização para todas as entradas do usuário antes de utilizá-las em consultas SQL.

  - Utilizar ORMs com Funções Seguras: Quando possível, utilize funções de abstração fornecidas por ORMs, como findAll ou where do Sequelize, que previnem injeções de SQL automaticamente.

  - Implementar WAF (Web Application Firewall): Ferramentas como o ModSecurity podem identificar e bloquear ataques de SQL Injection em tempo de execução.

  - Práticas de Least Privilege: As credenciais de banco de dados usadas pela aplicação devem ter privilégios mínimos necessários para operar, reduzindo o impacto de ataques bem-sucedidos.


## 5. NoSQL Injection
Durante a análise, foram identificadas vulnerabilidades do tipo NoSQL Injection no uso de consultas MongoDB no código. A vulnerabilidade ocorre quando entradas controladas por usuários são utilizadas diretamente nas consultas sem validação ou sanitização, permitindo que atacantes manipulem os critérios de consulta e realizem ações não autorizadas. 

- Arquivo: `/routes/likeProductReviews.ts`
- Linha: 18
  ```typescript
  db.reviewsCollection.findOne({ _id: id })
  ```
Neste exemplo, o valor de id é obtido diretamente do corpo da requisição `req.body.id` e usado sem validação em uma consulta ao MongoDB. Um atacante pode manipular a entrada para injetar objetos maliciosos no lugar de valores esperados, comprometendo a integridade e segurança do sistema.

- **Impacto**

  - Exposição de Dados Sensíveis: Consultas injetadas podem ser manipuladas para retornar dados não autorizados, violando as políticas de acesso.
  - Alteração de Dados: Atacantes podem modificar, excluir ou adicionar registros ao banco de dados, afetando a integridade dos dados.
  - Comprometimento do Sistema: Em ataques mais sofisticados, a exploração dessa vulnerabilidade pode levar à escalada de privilégios, comprometendo outras partes do sistema.
  - Denial of Service (DoS): Consultas ineficientes podem ser criadas para sobrecarregar o banco de dados, causando uma negação de serviço.

- **Recomendações**
  - Validação e Sanitização de Entrada: Verifique se as entradas fornecidas pelo usuário estão no formato esperado antes de utilizá-las em consultas. Por exemplo:
    ``` typescript
    const id = req.body.id;
    if (typeof id !== 'string' || !id.match(/^[a-f\d]{24}$/i)) {
      return res.status(400).json({ error: 'Invalid ID format' });
    }
    ```

  - Uso de ObjectId para Campos de ID: Converta os valores de ID para o tipo esperado pelo MongoDB:

    ```typescript
    const { ObjectId } = require('mongodb');
    const id = new ObjectId(req.body.id);
    db.reviewsCollection.findOne({ _id: id });
    ```
  - Utilização de Bibliotecas de Sanitização: Empregue bibliotecas específicas para sanitizar entradas antes de utilizá-las, como o express-validator para validações em APIs Express.
  - Restrições no Banco de Dados: Configure o banco de dados para limitar permissões de consulta e evitar execução de comandos perigosos.

## 6. Cross-site Scripting (XSS)

Durante a análise, foram identificadas vulnerabilidades do tipo Cross-site Scripting (XSS) em múltiplos locais no projeto, especialmente em arquivos localizados nos diretórios `frontend/`, `routes/` e `data/`. Essas vulnerabilidades decorrem do uso inadequado de entradas controladas por usuários, que são refletidas na saída sem a devida sanitização, permitindo a injeção de scripts maliciosos. 


  Exemplo 1
- Arquivo: `frontend/src/app/search-result/search-result.component.ts`
- Linha: 151

  ```typescript
  this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
  ```
  Neste caso, a vulnerabilidade ocorre porque o valor de `queryParam`, controlado pelo usuário, é processado diretamente pelo método `bypassSecurityTrustHtml`. Este tipo de **Local XSS** permite que um atacante explore scripts maliciosos injetados diretamente na interface do usuário, manipulando os dados locais apresentados ao cliente.

Exemplo 2
- Arquivo: `frontend/src/app/search-result/search-result.component.ts`
- Linha: 125
  ```typescript
  tableData[i].description = this.sanitizer.bypassSecurityTrustHtml(tableData[i].description)
  ```

  Aqui, a vulnerabilidade ocorre porque a descrição dos produtos (`description`) é processada como HTML confiável sem validação adequada. Neste caso, a vulnerabilidade é classificada como **Restful XSS**, pois envolve dados oriundos de uma API ou serviço backend que são processados de forma insegura no frontend.

- **Impacto**


  - Roubo de Credenciais e Cookies: Captura de tokens de autenticação e cookies de sessão por meio de scripts injetados.

  - Redirecionamento para Sites Maliciosos: Execução de scripts que redirecionam usuários para páginas de phishing ou baixam malware.
  
  - Alteração Não Autorizada da Interface: Manipulação de elementos da interface do usuário para realizar ações maliciosas.
  
  - Escalada de Privilégios: Uso do XSS como vetor para comprometer APIs ou servidores, potencializando ataques.

- **Recomendações**
  - Evitar Uso de `bypassSecurityTrustHtml`:Evite esta função sempre que possível. Utilize sanitizadores mais seguros e restritivos.
  
    ```typescript
    this.searchValue = this.domSanitizer.sanitize(SecurityContext.HTML, queryParam)
    ```


  - Sanitização Adequada de Entrada: Use bibliotecas como `DOMPurify` para limpar entradas antes de processá-las.


    ```typescript
    tableData[i].description = DOMPurify.sanitize(tableData[i].description)
    ```

  - Validação de Entrada: Valide todas as entradas do usuário, assegurando que estejam no formato esperado.
  
  - Encoding de Saída: Encode todas as saídas dinâmicas antes de renderizá-las no DOM.


## 7. Server-Side Request Forgery (SSRF)
Durante a análise, foi identificada vulnerabilidades de Server-Side Request Forgery (SSRF) no código da aplicação. Essas vulnerabilidades permitem que um atacante manipule requisições feitas pelo servidor, potencialmente acessando recursos internos ou não autorizados. No código analisado, essas vulnerabilidades estão relacionadas ao uso inseguro da biblioteca request para realizar requisições HTTP.


- Arquivo: `routes/profileImageUrlUpload.ts`
- Linha: 22-23
  ```typescript
  const imageRequest = request.get(url);
  ```
Nesse trecho, o código permite que uma URL arbitrária, fornecida pelo usuário em `req.body.imageUrl`, seja utilizada diretamente em uma requisição `GET` feita pelo servidor. Isso abre a aplicação para ataques SSRF, onde um atacante pode forçar o servidor a:

- 
  - Fazer requisições para redes internas, acessando serviços não expostos.
  - Exfiltrar dados de serviços internos ou realizar ações não autorizadas.
  - Usar o servidor como um proxy para realizar ataques contra terceiros.

- **Impacto**
  - Exposição de Recursos Internos: Um atacante pode explorar serviços internos, como bancos de dados, APIs de configuração, ou outros sistemas críticos, que deveriam estar protegidos por firewalls.

  - Escalada de Privilégios: SSRF pode ser usado para acessar endpoints internos de autenticação e autorização, escalando privilégios.

  - Uso Malicioso do Servidor: O servidor pode ser utilizado como proxy para lançar ataques contra sistemas externos, mascarando a origem do ataque.

- **Recomendações**
  - Validação e Sanitização de Entradas: Adicionar uma validação rigorosa para URLs fornecidas pelo usuário, permitindo apenas domínios confiáveis.

    ```typescript
    const allowedDomains = ['example.com', 'trusted.com']
    const url = new URL(req.body.imageUrl)
    if (!allowedDomains.includes(url.hostname)) {
      throw new Error('URL não permitida.')
    }
    ```
  - Restrições na Rede: Configure regras de firewall para bloquear requisições de saída para endereços internos e portas não utilizadas.
  
  - Evitar Uso Direto de URLs Controladas pelo Usuário: Ao invés de confiar diretamente em entradas de usuários, implemente intermediários seguros para validar e realizar requisições.


## 8. Path Traversal
Durante a análise, foram identificadas vulnerabilidades do tipo Path Traversal em múltiplas partes do código, incluindo rotas (`/routes`), bibliotecas (`/lib`) e dados (`/data`). Essas vulnerabilidades ocorrem devido ao uso inadequado de entradas de usuários para formar caminhos de arquivos, permitindo que atacantes acessem arquivos arbitrários no sistema do servidor.

- Arquivo: `/routes/fileServer.ts`
- Linha: 33
  ```typescript
  res.sendFile(path.resolve('ftp/', file));
  ```

  Neste exemplo, o valor de `params.file` é utilizado diretamente para formar o caminho de um arquivo. Apesar de algumas verificações, como a restrição ao uso de `/` e a validação de extensões permitidas, o uso de `path.resolve` combinado com entradas não totalmente sanitizadas permite ataques de Path Traversal.

- **Impacto**
  - Exposição de Arquivos Sensíveis: Atacantes podem acessar arquivos confidenciais, como Arquivos de configuração, Logs contendo informações sensíveis, Credenciais armazenadas localmente
  - Comprometimento da Aplicação: anipulação de arquivos sensíveis pode levar à execução de códigos maliciosos ou escalada de privilégios.


- **Recomendações**
  - Sanitização Estrita das Entradas: Verificar e sanitizar todas as entradas fornecidas pelo usuário antes de usá-las para formar caminhos de arquivos.


  - Uso de Caminhos Restritos: Limitar os caminhos permitidos a diretórios específicos e pré-definidos.
    ```typescript
    const allowedPath = path.join(__dirname, 'ftp', sanitizedFile);
    if (!allowedPath.startsWith(path.resolve(__dirname, 'ftp'))) {
      return res.status(403).send('Acesso negado.');
    }
    ```
  - Validação Rigorosa de Extensões: Permitir apenas extensões previamente autorizadas.

  - Restrições no Servidor: Configurar permissões para limitar o acesso a arquivos sensíveis e isolar o ambiente da aplicação por meio de contêineres.


## 9. Arbitrary File Write via Archive Extraction
Durante a análise, foi identificada uma vulnerabilidade do tipo Arbitrary File Write via Archive Extraction (também conhecida como Zip Slip) no código responsável por lidar com uploads de arquivos compactados. Essa vulnerabilidade ocorre quando o sistema extrai arquivos compactados sem validar adequadamente seus caminhos internos, permitindo que atacantes sobrescrevam arquivos arbitrários no servidor.

- Arquivo: `routes/fileUpload.ts`
- Linha: 39-42

  ```typescript
  typescript

  const absolutePath = path.resolve('uploads/complaints/' + fileName)
                challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return absolutePath === path.resolve('ftp/legal.md') })
                if (absolutePath.includes(path.resolve('.'))) {
                  entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName).on('error', function (err) { next(err) }))
  ```
  No trecho acima, o caminho do arquivo é gerado diretamente a partir do nome do arquivo extraído do arquivo ZIP (fileName), sem sanitização adequada. Isso permite que arquivos compactados contendo caminhos relativos (../) sejam extraídos para locais fora do diretório esperado, sobrescrevendo arquivos importantes no sistema.

- **Impacto**
  - Sobrescrita de Arquivos Sensíveis: Um atacante pode sobrescrever arquivos críticos, como configurações, logs ou scripts do sistema.
  - Execução de Código Malicioso: Arquivos executáveis maliciosos podem ser colocados em locais estratégicos, permitindo a execução remota de código.
  - Comprometimento do Sistema: O acesso a arquivos sensíveis ou a execução de código pode levar ao controle completo do servidor.
  
- **Recomendações**
  - Sanitização de Caminhos: Certifique-se de que os caminhos dos arquivos extraídos permaneçam dentro do diretório permitido. Use path.resolve e valide o caminho final contra o diretório base.

    ```typescript
    const uploadPath = path.resolve('uploads/complaints')
    const extractedPath = path.resolve(uploadPath, fileName)
    if (!extractedPath.startsWith(uploadPath)) {
      throw new Error('Tentativa de Path Traversal detectada!')
    }
    ```
  - Restrições de Permissões: Configure o servidor para que o processo de upload tenha permissões mínimas no sistema de arquivos, impedindo a sobrescrita de arquivos críticos.

  - Validação Estrita de Entradas: Valide os nomes dos arquivos antes de processá-los. Permita apenas extensões e formatos confiáveis.

  - Uso de Bibliotecas Seguras: Considere utilizar bibliotecas que lidem automaticamente com a sanitização de caminhos durante a extração de arquivos compactados, como adm-zip ou unzipper com configurações adequadas.


## 10. Observable Timing Discrepancy
Durante a análise do código, foram identificadas diversas vulnerabilidade de *Observable Timing Discrepancy* no componente de "Forgot Password". Essa vulnerabilidade ocorre quando um atacante pode medir o tempo de resposta do sistema para inferir informações confidenciais, como a existência de registros no banco de dados. No exemplo analisado, a vulnerabilidade é evidente na maneira como o sistema lida com o retorno das perguntas de segurança.

- Arquivo: `frontend/src/app/forgot-password/forgot-password.component`

- Linha: 118

  ```typescript
  function matchValidator (passwordControl: AbstractControl) {
    return function matchOtherValidate (repeatPasswordControl: UntypedFormControl) {
      const password = passwordControl.value
      const passwordRepeat = repeatPasswordControl.value
      if (password !== passwordRepeat) {
        return { notSame: true }
      }
      return null
    }
  }
  ```
- **Impacto**
  - Exposição de Informações Confidenciais: Um atacante pode determinar a existência de registros no sistema (como e-mails de usuários) medindo a diferença nos tempos de resposta.
  - Escalada de Ataques: Após determinar a existência de um registro, o atacante pode utilizar essas informações para iniciar ataques direcionados, como brute force ou phishing.

- **Recomendações**
  - Uniformizar Tempos de Resposta: Adicionar atrasos artificiais para uniformizar o tempo de resposta, independentemente do resultado da consulta.
    ```typescript
    Copy code
    setTimeout(() => {
      // lógica de retorno
    }, fixedDelay);
    ```

  - Validação de Entrada: Certifique-se de validar e sanitizar as entradas do usuário antes de utilizá-las em operações críticas.
  
  - Respostas Genéricas: Evitar mensagens de erro ou respostas que indiquem diretamente a existência ou inexistência de registros.

## 11. Denial-of-Service (DoS) via ReDoS

A vulnerabilidade identificada está relacionada ao uso de expressões regulares dinâmicas construídas com entradas potencialmente controladas por usuários, que podem ser exploradas para causar um **Regular Expression Denial of Service (ReDoS)**. Isso ocorre quando expressões regulares ineficientes bloqueiam o thread principal, consumindo recursos excessivos do sistema.

- Arquivo: `lib/codingChallenges.ts`
- Linha: 76
  ```typescript
  if (new RegExp(`vuln-code-snippet vuln-line.*${challengeKey}`).exec(lines[i]) != null) {
  ```

- **Impacto**
  - Essa prática pode causar uma negação de serviço, impedindo o funcionamento normal da aplicação.


- **Recomendações**
  - Evitar RegEx Dinâmico: Substituir expressões regulares dinâmicas por expressões estáticas, sempre que possível.
  - Validação de Entrada: Adicionar validação robusta para qualquer entrada de usuário antes de usá-la em expressões regulares.
  - Monitoramento e Limite de Recursos: Configurar limites de tempo para a execução de expressões regulares usando bibliotecas como safe-regex.