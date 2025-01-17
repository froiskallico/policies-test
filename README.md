# Goardian OPA Policy

Este repositório contém as políticas OPA (Open Policy Agent) para o projeto Goardian. As políticas definem as permissões e regras de acesso para os usuários e recursos do sistema.

## Estrutura do Repositório

- `policy.rego`: Contém as políticas principais que definem as permissões de acesso baseadas em usuários, unidades e recursos.
- `utils.rego`: Contém funções utilitárias usadas pelas políticas.
- `data.json`: Arquivo de dados de exemplo que pode ser usado para testar as políticas.
- `.manifest`: Lista os arquivos de políticas que devem ser carregados pelo OPA.
- `README.md`: Este arquivo de documentação.

## Políticas

### policy.rego

O arquivo `policy.rego` define várias regras para verificar permissões de usuários, incluindo:

- **Permissões Default (Com unidade especificada)**:
  - `user_allow`: Define se um usuário tem permissão com base em várias condições, como se é sysadmin, se tem permissões de papel ou permissões customizadas.

- **Permissões/Proibições custom**:
  - `user_has_custom_permission`: Verifica se o usuário tem uma permissão customizada específica.
  - `user_has_custom_disallowance`: Verifica se o usuário tem uma proibição customizada específica.

- **Permissões Default (Sem unidade especificada)**:
  - `user_has_role_permission_in_any_unit`: Verifica se o usuário tem uma permissão de papel em qualquer unidade.
  - `user_has_custom_permission_in_any_unit`: Verifica se o usuário tem uma permissão customizada em qualquer unidade.
  - `user_has_custom_disallowance_in_any_unit`: Verifica se o usuário tem uma proibição customizada em qualquer unidade.

- **Permissões por Resource ID**:
  - `resource_allow`: Define se um usuário tem permissão para acessar um recurso específico.
  - `user_access_resource`: Verifica se o usuário tem permissão para executar uma ação em um recurso específico.
  - `user_groups_access_resource`: Verifica se o usuário pertence a um grupo que tem permissão para executar uma ação em um recurso específico.

- **Lista Resources IDs para input.action**:
  - `user_accessible_resources`: Lista os recursos acessíveis para uma ação específica.

- **Permissões por unidade**:
  - `user_unit_permissions`: Retorna um mapa das permissões por unidade.
  - `check_permissions`: Verifica as permissões baseadas em papéis, permissões customizadas e proibições customizadas.

- **Display Map**:
  - `display_map`: Retorna um mapa de permissões para exibição.

### utils.rego

O arquivo `utils.rego` contém funções utilitárias usadas pelas políticas, como a função `hasPermission` que verifica se um conjunto de permissões inclui um determinado papel.

## Como Usar

1. Clone este repositório.
2. Carregue os arquivos de políticas no OPA usando o arquivo `.manifest`.
3. Use o arquivo `data.json` como exemplo de dados para testar as políticas.

## Contribuição

Sinta-se à vontade para abrir issues e pull requests para melhorias e correções.
