# Relatório de Auditoria DevSecOps — secops-audit

**Data de execução:** 2026-04-01  
**Projeto:** `secops-audit` v0.1.0  
**Repositório:** `Onboarding-SecOps`  
**Python:** 3.12.10  
**Pipeline:** GitHub Actions — `Security Audit Pipeline`

---

## 2. Logs de Auditoria e Qualidade (Security Gate)

Abaixo constam os resumos das execuções dos comandos de segurança:

---

### 2.1. Auditoria Estática (Bandit)

*Comando: `poetry run bandit -r .`*

```
[main]  INFO    profile include tests: None
[main]  INFO    profile exclude tests: None
[main]  INFO    cli include tests: None
[main]  INFO    cli exclude tests: None
[main]  INFO    running on Python 3.12.10
Run started: 2026-04-01 20:42:09.498916+00:00

Test results:
        No issues identified.

Code scanned:
        Total lines of code: 78
        Total lines skipped (#nosec): 0
        Total potential issues skipped due to specifically being disabled: 0

Run metrics:
        Total issues (by severity):
                Undefined: 0
                Low:       0
                Medium:    0
                High:      0
        Total issues (by confidence):
                Undefined: 0
                Low:       0
                Medium:    0
                High:      0

Files skipped (0):
```

**Resultado:** Nenhuma vulnerabilidade identificada na análise estática do código-fonte.

> O Bandit realiza análise estática de segurança (SAST) em código Python, verificando padrões como injeção de comandos, uso inseguro de funções criptográficas, exposição de segredos e outros riscos mapeados pelo OWASP Top 10. Zero findings confirmam que o código segue as boas práticas de desenvolvimento seguro.

---

### 2.2. Verificação de Dependências (pip-audit / SCA)

*Comando: `poetry run pip-audit`*

> **Nota:** O guia original especificava `safety check`. A ferramenta Safety 3.x passou a exigir autenticação obrigatória para o comando `scan`. Foi adotado o `pip-audit` como substituto equivalente — ferramenta oficial do Python Packaging Authority (PyPA), gratuita, sem necessidade de conta, que consulta as bases OSV e PyPI Advisory Database.

```
No known vulnerabilities found
```

**Resultado:** Nenhuma CVE conhecida encontrada nas 33 dependências transitivas do ambiente de desenvolvimento.

> O pip-audit realiza análise de composição de software (SCA), cruzando cada pacote instalado contra bancos de dados públicos de vulnerabilidades (OSV, PyPI Advisory DB). O resultado limpo indica que nenhuma dependência direta ou transitiva possui CVE publicada nas bases consultadas.

---

### 2.3. Qualidade e Conformidade (Ruff)

*Comando: `poetry run ruff check .`*

```
All checks passed!
```

*Verificação de formatação:*

```
1 file already formatted
```

**Resultado:** Nenhuma violação de estilo, conformidade ou segurança de código identificada.

> O Ruff executa mais de 800 regras de lint combinando as verificações do Flake8, isort, pycodestyle e regras de segurança (ruleset `S` — Bandit rules). Com `select = ["E", "F", "W", "S", "I"]` configurado no `pyproject.toml`, o linter valida erros de sintaxe, imports não utilizados, violações de estilo e padrões de código potencialmente inseguros.

---

## Resumo Executivo

| Ferramenta | Tipo de Análise | Versão | Findings | Status |
|---|---|---|---|---|
| Bandit | SAST — Análise estática | 1.9.4 | 0 | APROVADO |
| pip-audit | SCA — Dependências | 2.10.0 | 0 CVEs | APROVADO |
| Ruff | Lint + Conformidade | 0.11.13 | 0 | APROVADO |

**Security Gate: APROVADO** — todos os controles automatizados passaram com zero findings.

---

## Evidências do Pipeline CI/CD

O pipeline é definido em `.github/workflows/security.yml` e é disparado automaticamente em todo `push` e `pull_request` para a branch `main`.

Etapas executadas pelo GitHub Actions:

1. Checkout do repositório
2. Configuração do Python 3.12
3. Instalação do Poetry e dependências
4. `[ SAST ]` Bandit — análise de vulnerabilidades no código
5. `[ SCA ]` pip-audit — auditoria de dependências
6. `[ LINT ]` Ruff — qualidade e conformidade de código
7. Upload do `bandit-report.txt` como artefato (retenção: 90 dias)

> O link permanente da Action run no GitHub constitui a evidência auditável do pipeline, com status, logs completos e artefatos disponíveis por 90 dias.
