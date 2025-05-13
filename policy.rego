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

# Verifica se o usuário tem uma permissão específica baseada no seu papel na unidade (role permission)
check_user_has_role_permission(action) if {
	user := user_data(input.user)
	role := user.role
	role_permission := customer_data(input.customer).rolePermissions[role]
	action in role_permission.permissions
}


######### CAN PERFORM #########
can_user_perform_action_via_role(action) if {
	check_user_has_role_permission(action)
	not check_user_has_custom_disallowance(action)
	not has_unit
}

can_user_perform_action_via_role(action) if {
	check_user_has_role_permission(action)
	not check_user_has_custom_disallowance(action)
	user_has_unit_permission
    unit_has_solution
    user_has_module_unit_access
}

can_user_perform_action_via_custom(action) if {
	check_user_has_custom_permission(action)
	not check_user_has_custom_disallowance(action)
	not has_unit
}

can_user_perform_action_via_custom(action) if {
	check_user_has_custom_permission(action)
	not check_user_has_custom_disallowance(action)
	user_has_unit_permission
    unit_has_solution
    user_has_module_unit_access
}

can_user_perform_action(action) if {
	can_user_perform_action_via_role(action)
}

can_user_perform_action(action) if {
	can_user_perform_action_via_custom(action)
}

# Regra para verificar se o usuário é sysadmin
user_is_sysadmin if {
	user := user_data(input.user)
	user.sysadmin == true
}

has_unit := input.unit != null

################################################
#        Permissões/Proibições custom          #
################################################
# Verifica se o usuário tem uma permissão customizada em uma action específica
check_user_has_custom_permission(action) if {
	user := user_data(input.user)
	permission := user.directPermissions[action]
	permission.effect == "allow"
}

# Verifica se o usuário tem uma proibição customizada em uma action específica
check_user_has_custom_disallowance(action) if {
	user := user_data(input.user)
	permission := user.directPermissions[action]
	permission.effect == "deny"
}

######################################################################################################
#                                         Permissões Default                                         #
######################################################################################################

default user_allow := false

user_allow if user_is_sysadmin

user_allow if can_user_perform_action(input.action)

user_has_role_permission if check_user_has_role_permission(input.action)
user_has_custom_permission if check_user_has_custom_permission(input.action)
user_has_custom_disallowance if check_user_has_custom_disallowance(input.action)

######################################################################################################
#                                  Permissão para unidade específica                                 #
######################################################################################################
user_has_unit_permission := false if {
	has_unit
	not check_unit_permission(input.user, input.unit)
}

user_has_unit_permission if {
	has_unit
	check_unit_permission(input.user, input.unit)
}

check_unit_permission(userUuid, unitUuid) if {
	user_units := user_data(userUuid).units
	user_units[unitUuid]
}

######################################################################################################
#                                      Verifica Unidade/Solução                                      #
######################################################################################################
unit_has_solution := false if {
	has_unit
    not check_unit_has_solution(input.unit, input.action)
}

unit_has_solution if {
	has_unit
	check_unit_has_solution(input.unit, input.action)
}

check_unit_has_solution(unitUuid, actionUuid) := result if {
	unit := data.units[unitUuid]
	action_solution_uuid := data.actions[actionUuid].solution
	unit_solutions_ids := [uuid | uuid := key; _ := unit.solutions[key]]
	result := action_solution_uuid in unit_solutions_ids
}

######################################################################################################
#                                   Verifica Usuario/Modulo/Unidade                                  #
######################################################################################################
user_has_module_unit_access := false if {
	has_unit
    not check_user_has_module_and_unit_access(input.unit, input.action)
}

user_has_module_unit_access if {
	has_unit
	check_user_has_module_and_unit_access(input.unit, input.action)
}

check_user_has_module_and_unit_access(unitUuid, actionUuid) if {
	user_has_unit_permission
    unit_has_solution
    check_unit_has_module(unitUuid, actionUuid)
}

check_unit_has_module(unitUuid, actionUuid) := result if {
	unit := data.units[unitUuid]	
    action_solution_uuid := data.actions[actionUuid].solution
	solution_modules := unit.solutions[action_solution_uuid].modules
    solution_modules_ids := [uuid | uuid := key; _ := solution_modules[key]]
    action_module_uuid := data.actions[actionUuid].module
    result := action_module_uuid in solution_modules_ids
}

# ######################################################################################################
# #                                        Permissões do Usuário                                       #
# ######################################################################################################
user_allowed_actions := [action |
	action := [uuid | uuid := key; _ := data.actions[key]][_]
	can_user_perform_action(action)
]

# ######################################################################################################
# #                                       Display Map                                                  #
# ######################################################################################################
display_map := {action: allowed |
	action := [uuid | uuid := key; _ := data.actions[key]][_]
	allowed := action in user_allowed_actions
}

######################################################################################################
#                          Regras Relacionadas a Compartilhamento de Objetos                         #
######################################################################################################
sharing := result if {
	input.object
	result := {
# 		"user_allow":  user_can_perform_action_in_shared_object(input.user, input.object),
		"user_direct_accessible_objects": user_direct_accessible_objects(input.user),
		"user_group_accessible_objects": user_group_accessible_objects(input.user),
        "user_role_group_accessible_objects": user_role_group_accessible_objects(input.user),
# 		"all_user_accessible_objects": all_user_accessible_objects(input.user),
#         "user_accessible_objects_ids": {x | x := all_user_accessible_objects(input.user)[_].objectUuid}
	}
}


# Usuario pode executar ação em objeto compartilhado se
# user_can_perform_action_in_shared_object(userUuid, objectUuid) if {
# 	user_allow
#     objectUuid in {x | x := all_user_accessible_objects(userUuid)[_].objectUuid} 
# }

# Quais objetos um usuário tem acesso direto
user_direct_accessible_objects(userUuid) := {key: obj |
	user_sharings := user_data(userUuid).sharings[_]
    key := user_sharings
	obj := customer_data(input.customer).sharing[user_sharings]
}

# Quais objetos o usuário tem acesso através de grupos
user_group_accessible_objects(userUuid) := {key: obj |
    user_group := user_data(userUuid).groups[_]
	customer := customer_data(input.customer)
    some key
    sharing := customer.sharing[key]
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

# direct_and_group_accessible_objects(userUuid) := object.union(
# 	user_direct_accessible_objects(userUuid),
# 	user_group_accessible_objects(userUuid),
# )
# 
# # Todos objetos aos quais o usuário tem acesso
# all_user_accessible_objects(userUuid) := object.union(
# 	direct_and_group_accessible_objects(userUuid),
# 	user_role_group_accessible_objects(userUuid),
# )
