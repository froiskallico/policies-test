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
	customer := data.customers[_]
	user := customer.users[_]
	user.sysadmin == true
	user.uuid == input.user
}

default user_has_role_permission := false

# Verifica se o usuário tem uma permissão específica baseada no seu papel na unidade (role permission)
user_has_role_permission if {
	customer := data.customers[_]
	user := customer.users[_]
	unit := user.units[_]
	role := unit.roles[_]
	role_permission := customer.rolePermissions[_]
	role_permission.role == role
	input.action == role_permission.permissions[_]
	user.uuid == input.user
	unit.uuid == input.unit
}

######################################################################################################
#                                   Permissões/Proibições custom                                     #
######################################################################################################
# Verifica se o usuário tem uma permissão customizada em uma action específica
user_has_custom_permission if {
	customer := data.customers[_]
	user := customer.users[_]
	unit := user.units[_]
	permission := unit.directPermissions[_]
	permission.action == input.action
	permission.effect == "allow"
	user.uuid == input.user
	unit.uuid == input.unit
}

# Verifica se o usuário tem uma proibição customizada em uma action específica
user_has_custom_disallowance if {
	customer := data.customers[_]
	user := customer.users[_]
	unit := user.units[_]
	permission := unit.directPermissions[_]
	permission.action == input.action
	permission.effect == "deny"
	user.uuid == input.user
	unit.uuid == input.unit
}

######################################################################################################
#                               Permissões Default (Iterando por Customers)                         #
######################################################################################################

# Permissão baseada em role em qualquer unidade
user_has_role_permission_in_any_unit if {
	some customer in data.customers
	some user in customer.users
	user.uuid == input.user
	some unit in user.units
	some role in unit.roles
	some rolePermission in customer.rolePermissions
	rolePermission.role == role
	input.action in rolePermission.permissions
}

# Permissão customizada em qualquer unidade
user_has_custom_permission_in_any_unit if {
	some customer in data.customers
	some user in customer.users
	user.uuid == input.user
	some unit in user.units
	some permission in unit.directPermissions
	permission.effect == "allow"
	permission.action == input.action
}

# Proibição customizada em qualquer unidade
user_has_custom_disallowance_in_any_unit if {
	some customer in data.customers
	some user in customer.users
	user.uuid == input.user
	some unit in user.units
	some permission in unit.directPermissions
	permission.effect == "deny"
	permission.action == input.action
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
action_intent := result if {
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
	some customer in data.customers
	some user in customer.users
	user.uuid == input.user
	some unit in user.units
	unit_key := unit.uuid
	permission_map := check_permissions(customer, unit.roles, unit.directPermissions)
}

# Função para verificar permissões com base em roles e permissões diretas
check_permissions(customer, roles, direct_permissions) := result if {
	# Permissões baseadas em roles
	role_permissions := {perm |
		some role in roles
		some rolePermission in customer.rolePermissions
		rolePermission.role == role
		perm := rolePermission.permissions[_]
	}

	# Permissões customizadas (allow e deny)
	allow_permissions := {perm.action |
		some perm in direct_permissions
		perm.effect == "allow"
	}

	deny_permissions := {perm.action |
		some perm in direct_permissions
		perm.effect == "deny"
	}

	# União das permissões de roles e permissões allow, menos os denies
	all_permissions := role_permissions | allow_permissions
	result := all_permissions - deny_permissions
}

######################################################################################################
#                                       Permissões por unidade                                       #
######################################################################################################
all_actions := union({action |
	# Iterar sobre os tenants
	customer := data.customers[_]

	# Verificar permissões baseadas em roles
	role := customer.rolePermissions[_]
	role_actions := {x | x := role.permissions[_]}

	# Verificar permissões customizadas nas unidades dos usuários
	user := customer.users[_]
	unit := user.units[_]

	# Permissões personalizadas
	custom_actions := {x.action | x := unit.directPermissions[_]}


	action := (role_actions | custom_actions)
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

######################################################################################################
#                                          Errors                                                    #
######################################################################################################
# Regra que retorna true se o usuário não for encontrado
user_not_found if {
    count({user | some customer in data.customers; some user in customer.users; user.uuid == input.user}) == 0
}

# Regra que retorna true se a unidade não for encontrada
unit_not_found if {
    count({unit | some customer in data.customers; some user in customer.users; user.uuid == input.user; some unit in user.units; unit.uuid == input.unit}) == 0
}


