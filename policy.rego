package goapice.check_user

import rego.v1

######################################################################################################
#                                           Utils Functions                                          #
######################################################################################################

customer_data(customerUuid) := result if {
	customer := data.customers[customerUuid]
	result := customer
}

user_data(userUuid) := result if {
	customer := data.customers[input.customer]
	user := customer.users[userUuid]
	result := user
}

action_data(action_uuid) := result if {
	result := data.actions[action_uuid]
}

customer_available_actions(customerUuid) := result if {
	customer := customer_data(customerUuid)
    result := customer.availableActions
}

# Verifica se o usuário tem uma permissão específica baseada no seu papel na unidade (role permission)
check_user_has_role_permission(userUuid, action) if {
	user := user_data(userUuid)
	role := user.role
	role_permission := customer_data(input.customer).rolePermissions[role]
	action in role_permission.permissions
}

######### CAN PERFORM #########
can_user_perform_action_via_role(userUuid, action) if {
	check_user_has_role_permission(userUuid, action)
	not check_user_has_custom_disallowance(userUuid, action)
}

can_user_perform_action_via_custom(userUuid, action) if {
	check_user_has_custom_permission(userUuid, action)
	not check_user_has_custom_disallowance(userUuid, action)
}

can_user_perform_action(userUuid, action) if {
	can_user_perform_action_via_role(userUuid, action)
}

can_user_perform_action(userUuid, action) if {
	can_user_perform_action_via_custom(userUuid, action)
}

can_user_perform_action(user_id, action_id) if {
	check_user_is_sysadmin(user_id)
	action_id in customer_available_actions(input.customer)
}

# Regra para verificar se o usuário é sysadmin
check_user_is_sysadmin(userUuid) if {
	user := user_data(userUuid)
	user.sysadmin == true
}

################################################
#        Permissões/Proibições custom          #
################################################
# Verifica se o usuário tem uma permissão customizada em uma action específica
check_user_has_custom_permission(userUuid, action) if {
	user := user_data(userUuid)
	permission := user.directPermissions[action]
	permission.effect == "allow"
}

# Verifica se o usuário tem uma proibição customizada em uma action específica
check_user_has_custom_disallowance(userUuid, action) if {
	user := user_data(userUuid)
	permission := user.directPermissions[action]
	permission.effect == "deny"
}

######################################################################################################
#                                         Permissões Default                                         #
######################################################################################################
default user_allow := false

user_allow if {
	input.user
	check_user_is_sysadmin(input.user)
	input.action in customer_available_actions(input.customer)
}

user_allow if {
	input.user
	can_user_perform_action(input.user, input.action)
}

user_is_sysadmin := check_user_is_sysadmin(input.user)

user_has_role_permission if check_user_has_role_permission(input.user, input.action)
user_has_custom_permission if check_user_has_custom_permission(input.user, input.action)
user_has_custom_disallowance if check_user_has_custom_disallowance(input.user, input.action)

# ######################################################################################################
# #                                        Unidades habilitadas                                        #
# ######################################################################################################

is_unit_requested if {
    input.units == true
}

# Verifica se a unidade está habilitada na solução
unit_enabled_in_solution(solution_id, customer_id, unit_id) if {
    data.solutionUnits[solution_id].customers[customer_id][unit_id]
}

# [DEBUG] Lista as unidades habilitadas para a solução
units_enabled_in_solution := units if {
    is_unit_requested
    action := action_data(input.action)
    units := object.keys(data.solutionUnits[action.solution].customers[input.customer])
}

# [DEBUG] Unidades habilitadas para o módulo
# Unidades Habilitadas para o usuário, para o módulo da ação
# Quais unidades estão habilitadas para o módulo da ação para o usuário
module_units := units if {
    is_unit_requested
    action := action_data(input.action)
    user := user_data(input.user)

    units := [uid |
        user.unitAccess.modules[action.module].units[uid]
    ]
}

# [DEBUG] Unidades habilitadas para a solução (mesmo de cima mas pra solução inves de módulo)
solution_units := units if {
    is_unit_requested
    action := action_data(input.action)
    solution_id := action.solution
    user := user_data(input.user)

    units := [uid |
        user.unitAccess.solutions[solution_id].units[uid]
    ]
}

sysadmin_units := units if {
    is_unit_requested
    user_is_sysadmin
    customer := customer_data(input.customer)
    units := customer.units
}

# [DEBUG] Identifica de onde as unidades vieram
units_read_from := source if {
    is_unit_requested
    action := action_data(input.action)
    not is_null(action.module)
    source := concat(": ", ["Module", action.module])
}

units_read_from := source if {
    is_unit_requested
    action := action_data(input.action)
    is_null(action.module)
    source := concat(": ", ["Solution", action.solution])
}

# Retorna todas as unidades DA SOLUÇÃO se o usuário for sysadmin
user_units_for_action := result if {
    user_is_sysadmin
    action_data(input.action)
    result := units_enabled_in_solution
}

# Retorna todas as unidades DO CLIENTE se o usuário for sysadmin e não houver ação especificada
user_units_for_action := result if {
    user_is_sysadmin
    not action_data(input.action)
    result := sysadmin_units
}

# Retorna todas as unidades DO USUÁRIO se o mesmo NÃO FOR sysadmin e não houver ação especificada
user_units_for_action := result if {
    not user_is_sysadmin
    not action_data(input.action)
    user := user_data(input.user)
    result := user_all_units(user)
}

# Retorna as unidades válidas para a ação considerando MÓDULO
user_units_for_action := result if {
    not user_is_sysadmin
    action := action_data(input.action)
    action.module != ""
    result := [uid |
        uid := module_units[_]
        unit_enabled_in_solution(action.solution, input.customer, uid)
    ]
}

# Retorna as unidades válidas para a ação considerando SOLUÇÃO
user_units_for_action := result if {
    not user_is_sysadmin
    action := action_data(input.action)
    action.module == ""
    result := [uid |
        uid := solution_units[_]
        unit_enabled_in_solution(action.solution, input.customer, uid)
    ]
}

# Função para iterar entre as unidades liberadas para soluções e módulos do usuário e retornar a lista completa
user_all_units(user) = result if {
    all_units := {unit_id |
        some id
        source := ["solutions", "modules"][_]
        user.unitAccess[source][id].units[unit_id]
    }

    result := sort([unit_id | unit_id := all_units[_]])
}

# ######################################################################################################
# #                                        Permissões do Usuário                                       #
# ######################################################################################################
user_allowed_actions := result if {
	not input.usersList
    not is_unit_requested
	input.user
	result := check_user_allowed_actions(input.user)
}

check_user_allowed_actions(userUuid) := [action |
	action := [uuid | uuid := key; _ := data.actions[key]][_]
    action in customer_available_actions(input.customer)
	can_user_perform_action(userUuid, action)
]
# ######################################################################################################
# #                                       Display Map                                                  #
# ######################################################################################################
display_map := result if {
	not input.usersList
    not is_unit_requested
	input.user
	result := get_display_map(input.user)
}

get_display_map(userUuid) := {action: allowed |
	action := [uuid | uuid := key; _ := data.actions[key]][_]
	allowed := action in check_user_allowed_actions(userUuid)
}

######################################################################################################
#                          Regras Relacionadas a Compartilhamento de Objetos                         #
######################################################################################################
sharing := result if {
	input.object
	result := {
		"user_allow": user_can_perform_action_in_shared_object(input.user, input.object),
		"user_direct_accessible_objects": user_direct_accessible_objects(input.user),
		"user_group_accessible_objects": user_group_accessible_objects(input.user),
		"user_role_group_accessible_objects": user_role_group_accessible_objects(input.user),
		"all_user_accessible_objects": all_user_accessible_objects(input.user),
		"user_accessible_objects_ids": {x | x := all_user_accessible_objects(input.user)[_].objectId},
	}
}

# Valor padrão da regra é false
default user_can_perform_action_in_shared_object(_, _) := false

# Usuario pode executar ação em objeto compartilhado se
user_can_perform_action_in_shared_object(userUuid, objectId) if {
	user_allow
	objectId in {x | x := all_user_accessible_objects(userUuid)[_].objectId}
}

# Quais objetos um usuário tem acesso direto
user_direct_accessible_objects(userUuid) := {sharing_key: obj |
	customer_sharing := customer_data(input.customer).sharing[sharing_key]
	userUuid in customer_sharing.users
	obj := customer_sharing
}

# Quais objetos o usuário tem acesso através de grupos
user_group_accessible_objects(userUuid) := {sharing_key: obj |
	user_group := user_data(userUuid).groups[_]
	customer := customer_data(input.customer)
	some sharing_key
	sharing := customer.sharing[sharing_key]
	user_group in sharing.groups
	not userUuid in sharing.groupExceptions
	obj := sharing
}

user_role_group_accessible_objects(userUuid) := {sharing_key: obj |
	user_role := user_data(userUuid).role
	customer := customer_data(input.customer)
	some sharing_key
	sharing := customer.sharing[sharing_key]
	some group_key
	group := customer.groups[group_key]
	user_role in group.roles
	group_key in sharing.groups
	not userUuid in sharing.groupExceptions
	obj := sharing
}

direct_and_group_accessible_objects(userUuid) := object.union(
	user_direct_accessible_objects(userUuid),
	user_group_accessible_objects(userUuid),
)

# Todos objetos aos quais o usuário tem acesso
all_user_accessible_objects(userUuid) := object.union(
	direct_and_group_accessible_objects(userUuid),
	user_group_accessible_objects(userUuid),
)

######################################################################################################
#                                              UsersList                                             #
######################################################################################################
allowed_users_list := result if {
	input.usersList
	not input.user
	result := {userUuid |
		userUuid := input.usersList[_]
		can_user_perform_action(userUuid, input.action)
	}
}


# Criar debug para verificar se a ação está habilitada na subscription do cliente
