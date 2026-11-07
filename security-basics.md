# Fundamentos de Segurança da Informação e AppSec

Contexto essencial para o agente orientar estudantes sobre segurança cibernética, desenvolvimento seguro (*secure coding*) e análise defensiva de vulnerabilidades.

---

## 1. Os Pilares da Segurança da Informação

### A Tríade CIA
- **Confidencialidade (Confidentiality):** A informação só pode ser acessada por quem tem autorização explícita.
  - *Exemplo de falha:* Vazamento de credenciais, dados expostos sem criptografia.
- **Integridade (Integrity):** A informação e os sistemas devem permanecer exatos, completos e protegidos contra modificações não autorizadas.
  - *Exemplo de falha:* Injeção de código ou SQL que altera registros no banco de dados.
- **Disponibilidade (Availability):** O sistema e os dados devem estar acessíveis aos usuários autorizados sempre que necessário.
  - *Exemplo de falha:* Ataques de negação de serviço (DoS/DDoS) ou travamento de serviços por falha de memória.

### Pilares Complementares
- **Autenticidade:** Garantia da identidade de quem enviou ou gerou uma informação.
- **Não-repúdio (Irretratabilidade):** Impossibilidade de negar a autoria de uma ação realizada.

---

## 2. Diferenças entre Termos-Chave

Muitos estudantes confundem os termos básicos. Mantenha essa distinção clara:

- **Vulnerabilidade:** Uma fraqueza, falha de projeto ou erro de implementação no software ou sistema que pode ser explorada.
- **Ameaça (Threat):** Um agente ou evento potencial com capacidade de causar dano aproveitando-se de uma vulnerabilidade.
- **Risco:** A probabilidade de uma ameaça explorar uma vulnerabilidade combinada com o impacto potencial resultante ($Risco = Probabilidade \times Impacto$).
- **Exploit:** O método, técnica ou código utilizado para aproveitar uma vulnerabilidade e obter um comportamento não intencional.

---

## 3. Princípios Fundamentais de Arquitetura Segura

1. **Princípio do Menor Privilégio (*Least Privilege*):** Cada usuário, processo ou componente deve ter apenas o nível mínimo de acesso necessário para desempenhar sua função.
2. **Defesa em Profundidade (*Defense in Depth*):** Não confiar em uma única camada de segurança. Combinar firewall, validação no código, controle de acesso e criptografia.
3. **Falha Segura (*Fail-Safe Defaults*):** Se um erro acontecer, o sistema deve bloquear o acesso por padrão, e não liberar.
4. **Nunca Confie na Entrada do Usuário (*Never Trust User Input*):** Toda entrada externa (formulários, URLs, cabeçalhos, arquivos) deve ser tratada como potencialmente hostil.
5. **Separação de Privilégios (*Separation of Concerns*):** Isolar funções críticas para que o comprometimento de uma parte não dê acesso total ao sistema.

---

## 4. Padrões, Taxonomias e Frameworks do Setor

- **OWASP Top 10:** Relatório da *Open Web Application Security Project* que lista as 10 falhas de segurança mais críticas e recorrentes em aplicações web (como *Broken Access Control*, *Cryptographic Failures* e *Injection*).
- **CWE (Common Weakness Enumeration):** Catálogo formal mantido pela MITRE que classifica e enumera tipos de fraquezas de software e hardware (ex: CWE-89 para SQL Injection, CWE-79 para XSS).
- **CVE (Common Vulnerabilities and Exposures):** Identificador público único para vulnerabilidades específicas conhecidas em produtos de software/hardware (ex: CVE-2021-44228 para o Log4Shell).
- **CVSS (Common Vulnerability Scoring System):** Escala de 0.0 a 10.0 usada para medir a severidade técnica de uma vulnerabilidade (Baixa, Média, Alta, Crítica).
- **MITRE ATT&CK:** Matriz global de táticas, técnicas e procedimentos (TTPs) usados por adversários reais no ciclo de vida de um ataque cibernético.

---

## 5. Boas Práticas de Segurança e Desenvolvimento Seguro (*AppSec*)

- **Manter Sistemas Atualizados:** Implementar rotinas regulares de atualização (*patch management*) em sistemas operacionais, bibliotecas, frameworks e dependências. Ambientes desatualizados são alvos fáceis para exploração de vulnerabilidades públicas catalogadas (CVEs).
- **Utilizar Autenticação Forte:** Adotar autenticação multifator (MFA/2FA), políticas seguras de expiração e rotação de credenciais, além de funções robustas de derivação criptográfica (Argon2, PBKDF2 ou bcrypt com salt exclusivo) para senhas, protegendo também cookies de sessão com atributos `HttpOnly`, `Secure` e `SameSite`.
- **Aplicar Menor Privilégio (*Least Privilege*):** Garantir que usuários, microsserviços, processos e contas de banco de dados tenham apenas os privilégios estritamente necessários para executar suas tarefas, evitando o uso de privilégios de administrador/root no ciclo normal da aplicação.
- **Monitorar Eventos e Realizar Backups:** Manter logs auditáveis e centralizados (SIEM) para monitoramento de eventos críticos (falhas de login, acessos anômalos, alterações de permissões), sem armazenar dados sensíveis ou PII nos registros. Executar rotinas regulares e testadas de backup (como a regra 3-2-1), com cópias imutáveis para garantir resiliência contra incidentes e ransomware.
- **Corrigir Vulnerabilidades Conhecidas:** Realizar análises contínuas de segurança (SAST, DAST e SCA) no fluxo de CI/CD para detectar e corrigir falhas de código e dependências vulneráveis antes de subirem para produção, priorizando a remediação pela severidade (CVSS) e pelo risco de exploração ativa.
- **Consultas Parametrizadas (*Prepared Statements*):** Neutralizar injeções (como SQL Injection) separando a instrução SQL dos parâmetros do usuário, garantindo que qualquer entrada seja interpretada pelo interpretador exclusivamente como dado literal.
- **Validação e Sanitização de Entradas:** Validar todos os dados recebidos com listas de permissão (*allowlists* / tipagem rigorosa) e aplicar codificação de saída apropriada ao contexto (*output encoding*) para mitigar Cross-Site Scripting (XSS).
- **Gestão Segura de Segredos:** Nunca expor chaves de API, senhas, certificados ou tokens *hardcoded* no código ou em repositórios Git. Utilizar variáveis de ambiente (`.env`) ou cofres de segredos (*Key Vaults*).
- **Tratamento Seguro de Exceções:** Tratar erros sem expor *stack traces*, nomes de tabelas ou detalhes de infraestrutura para o usuário final, prevenindo vazamento de informações sensíveis (*Information Disclosure* / CWE-209).

---

## 6. Como Orientar Estudantes na DIO

- **Postura Defensiva:** Foco absoluto na proteção, auditoria e correção. Explique a lógica dos ataques apenas como motivação pedagógica para entender a defesa.
- **Incentivo a Laboratórios:** Incentive a prática em ambientes controlados, testes locais e desafios de laboratório.
- **Conexão com a Prática:** Conecte os conceitos teóricos aos Desafios de Código, Desafios de Projeto e Bootcamps de Cibersegurança da DIO.
