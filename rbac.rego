package goapice.check_user

import rego.v1

######################################################################################################
#                               Permissões Default (Com unidade especificada)                        #
######################################################################################################

default user_allow := false

user_allow if {
	user_is_sysadmin
	not user_has_custom_disallowance
}

user_allow if {
	user_has_role_permission
	not user_has_custom_disallowance
}

user_allow if {
	user_has_custom_permission
	not user_has_custom_disallowance
}

# Regra para verificar se o usuário é sysadmin
user_is_sysadmin if {
	data.tenants[input.tenant].users[input.user].sysadmin == true
}

# Verifica se o usuário tem uma permissão específica baseada no seu papel na unidade (role permission)
user_has_role_permission if {
	role := data.tenants[input.tenant].users[input.user].units[input.unit].roles[_]
	input.action == data.tenants[input.tenant].rolePermissions[role].permissions[_]
}

######################################################################################################
#                                   Permissões/Proibições custom                                     #
######################################################################################################
# Verifica se o usuário tem uma permissão customizada em uma action específica
user_has_custom_permission if {
	input.action in data.tenants[input.tenant].users[input.user].units[input.unit].custom_permissions
}

# Verifica se o usuário tem uma proibição customizada em uma action específica
user_has_custom_disallowance if {
	input.action in data.tenants[input.tenant].users[input.user].units[input.unit].custom_disallowances
}

######################################################################################################
#                               Permissões Default (Sem unidade especificada)                        #
######################################################################################################
user_has_role_permission_in_any_unit if {
	some unit in data.tenants[input.tenant].users[input.user].units
	some role in unit.roles
	input.action in data.tenants[input.tenant].rolePermissions[role].permissions
}

user_has_custom_permission_in_any_unit if {
	some unit in data.tenants[input.tenant].users[input.user].units
	input.action in unit.custom_permissions
}

user_has_custom_disallowance_in_any_unit if {
	some unit in data.tenants[input.tenant].users[input.user].units
	input.action in unit.custom_disallowances
}

######################################################################################################
#                                      Permissões por Resource ID                                    #
######################################################################################################
default resource_allow := false

resource_allow if {
	user_allow
	user_access_resource
}

resource_allow if {
	user_allow
	user_groups_access_resource
}

# Pega o tipo do resource parsenado input.action
resource_type := split(input.action, ".")[1]

# Pega a action desejada parseando input.action
action_intent = result if {
	arr := split(input.action, ".")
	result := arr[count(arr) - 1]
}

# Verifica se o usuário tem permissão para executar a ação desejada neste resource.id
user_access_resource if {
	reachable_actions := graph.reachable(data.sharing[resource_type].shared_graphs, [data.tenants[input.tenant].resources[resource_type][input.resource_id].userPermissions[input.user]])
	action_intent in reachable_actions
}

# Verifica se o usuário pertence a um grupo que tenha permissão para executar a ação desejada neste resource.id
user_groups_access_resource if {
	group := data.tenants[input.tenant].users[input.user].groups[_]
	reachable_actions := graph.reachable(data.sharing[resource_type].shared_graphs, [data.tenants[input.tenant].resources[resource_type][input.resource_id].groupPermissions[group]])
	action_intent in reachable_actions
}

######################################################################################################
#                                Lista Resources IDs para input.action                               #
######################################################################################################
user_accessible_resources := user_personal_accessible_resources | user_groups_accessible_resources

user_personal_accessible_resources := {resource_key |
	some resource_key, resource_id in data.tenants[input.tenant].resources[resource_type]
	user_permission := resource_id.userPermissions[input.user]
	reachable_actions := graph.reachable(data.sharing[resource_type].shared_graphs, [user_permission])
	action_intent in reachable_actions
}

user_groups_accessible_resources := {resource_key |
	some resource_key, resource_id in data.tenants[input.tenant].resources[resource_type]
	some group in data.tenants[input.tenant].users[input.user].groups
	group_permission := resource_id.groupPermissions[group]
	reachable_actions := graph.reachable(data.sharing[resource_type].shared_graphs, [group_permission])
	action_intent in reachable_actions
}

######################################################################################################
#                                       Permissões por unidade                                       #
######################################################################################################
# Regra principal que retorna um mapa das permissões por unidade
user_unit_permissions := {unit_key: permission_map |
	unit_key := unit
	unit_permissions := data.tenants[input.tenant].users[input.user].units[unit]
	permission_map := check_permissions(unit_permissions.roles, unit_permissions.custom_permissions, unit_permissions.custom_disallowances)
}


check_permissions(roles, custom_permissions, custom_disallowances) = result if {
	role_permissions := {perm |
		some role in roles
		perm := data.tenants[input.tenant].rolePermissions[role].permissions[_]
	}

	all_permissions := role_permissions | {x | x := custom_permissions[_]}
	result := all_permissions - {x | x := custom_disallowances[_]}
}

######################################################################################################
#                                       Permissões por unidade                                       #
######################################################################################################
all_actions := union({action |
    # Iterar sobre os tenants
    tenant := data.tenants[_]

    # Verificar permissões baseadas em roles
    role := tenant.rolePermissions[_]
    role_actions := {x | x := role.permissions[_]}

    # Verificar permissões customizadas nas unidades dos usuários
    user := tenant.users[_]
    unit := user.units[_]

    # Permissões personalizadas
    custom_actions := {x | x := unit.custom_permissions[_]}
#
#     # Disallowances personalizadas
    disallowances_actions := {x | x:= unit.custom_disallowances[_]}

    action := role_actions | custom_actions | disallowances_actions
})

######################################################################################################
#                                       Display Map                                                  #
######################################################################################################
display_map := {unit_key: display_map |
	unit_key := unit
    unit_permissions := user_unit_permissions[unit]
    display_map := {perm: allowed |
        perm := all_actions[_]
        allowed := perm in unit_permissions
    }
}
