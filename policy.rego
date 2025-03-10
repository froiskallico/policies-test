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
    customer := data.customers[input.customer]
    user := customer.users[input.user]
    user.sysadmin == true
}

# Verifica se o usuário tem uma permissão específica baseada no seu papel na unidade (role permission)
user_has_role_permission if {
    customer := data.customers[_]
    customer.uuid == input.customer
    user := customer.users[_]
    user.uuid == input.user
    unit := user.units[_]
    unit.uuid == input.unit
    role := unit.roles[_]
    role_permission := customer.rolePermissions[_]
    role_permission.role == role
    input.action == role_permission.permissions[_]
}

######################################################################################################
#                                   Permissões/Proibições custom                                     #
######################################################################################################
# Verifica se o usuário tem uma permissão customizada em uma action específica
user_has_custom_permission if {
    customer := data.customers[_]
    customer.uuid == input.customer
    user := customer.users[_]
    user.uuid == input.user
    unit := user.units[_]
    unit.uuid == input.unit
    permission := unit.directPermissions[_]
    permission.action == input.action
    permission.effect == "allow"
}

# Verifica se o usuário tem uma proibição customizada em uma action específica
user_has_custom_disallowance if {
    customer := data.customers[_]
    customer.uuid == input.customer
    user := customer.users[_]
    user.uuid == input.user
    unit := user.units[_]
    unit.uuid == input.unit
    permission := unit.directPermissions[_]
    permission.action == input.action
    permission.effect == "deny"
}

######################################################################################################
#                               Permissões Default (Sem unidade especificada)                        #
######################################################################################################
user_has_role_permission_in_any_unit if {
    customer := data.customers[_]
    customer.uuid == input.customer
    user := customer.users[_]
    user.uuid == input.user
    unit := user.units[_]
    user_role := unit.roles[_]
    customer_role_permission := customer.rolePermissions[_]
    customer_role_permission.role == user_role
    permission := customer_role_permission.permissions[_]
    permission == input.action
}

user_has_custom_permission_in_any_unit if {
    customer := data.customers[_]
    customer.uuid == input.customer
    user := customer.users[_]
    user.uuid == input.user
    unit := user.units[_]
    permission := unit.directPermissions[_]
    permission.action == input.action
    permission.effect == "allow"
}

user_has_custom_disallowance_in_any_unit if {
    customer := data.customers[_]
    customer.uuid == input.customer
    user := customer.users[_]
    user.uuid == input.user
    unit := user.units[_]
    disallowance := unit.directPermissions[_]
    disallowance.action == input.action
    disallowance.effect == "deny"
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
#                          Regras Relacionadas a Compartilhamento de Objetos                         #
######################################################################################################
# Quais objetos um usuário tem acesso direto
user_direct_accessible_objects := {obj |
	customer := data.customers[_]
	sharing := customer.sharing[_]
	share_obj := sharing.shares[_]
	share_obj.toUser == input.user
	obj := sharing.objectId
}

# Grupos ao qual o usuário pertence na unidade especificada no input
user_groups := {group |
	customer := data.customers[_]
	user := customer.users[_]
	user.uuid == input.user
	unit := user.units[_]
	unit.uuid == input.unit
	group := unit.groups[_]
}

# Quais objetos o usuário tem acesso através do grupo na unidade especificada no input
user_group_accessible_objects := {obj |
	customer := data.customers[_]
	user := customer.users[_]
	user.uuid == input.user
	group := user_groups[_]
	sharing := customer.sharing[_]
	share_obj := sharing.shares[_]
	share_obj.toGroup == group
	obj := sharing.objectId
}

all_user_accessible_objects := user_direct_accessible_objects | user_group_accessible_objects

user_allowed_actions_for_object := {action |
    # Quais ações um usuário está permitido para um objeto específico (via SharingLevels) por grupo
    user_allowed_actions_for_object_thru_sharing_levels_by_group := {action |
        customer := data.customers[_]
        sharing := customer.sharing[_]
        sharing.objectId == input.objectId
        share_obj := sharing.shares[_]
        user_group := user_groups[_]
        share_obj.toGroup == user_group
        level := customer.sharingLevels[_]
        level.module == sharing.module
        level.entity == sharing.entity
        level_level := level.levels[_]
        level_level.level == share_obj.sharingLevel
        action := level_level.actions[_]
    }
    
    # Quais ações um usuário está permitido para um objeto específico (via SharingLevels) por usuario
    user_allowed_actions_for_object_thru_sharing_levels_by_user := {action |
        customer := data.customers[_]
        sharing := customer.sharing[_]
        sharing.objectId == input.objectId
        share_obj := sharing.shares[_]
        share_obj.toUser == input.user
        level := customer.sharingLevels[_]
        level.module == sharing.module
        level.entity == sharing.entity
        level_level := level.levels[_]
        level_level.level == share_obj.sharingLevel
        action := level_level.actions[_]
    }
    
    user_allowed_actions_for_object_thru_custom_level_by_group := {action |
        customer := data.customers[_]
        sharing := customer.sharing[_]
        sharing.objectId == input.objectId
        share_obj := sharing.shares[_]
        user_group := user_groups[_]
        share_obj.toGroup == user_group
        share_obj.sharingLevel == "custom"
        action := share_obj.customSharedActions[_]
    }
    
    user_allowed_actions_for_object_thru_custom_level_by_user := {action |
        customer := data.customers[_]
        sharing := customer.sharing[_]
        sharing.objectId == input.objectId
        share_obj := sharing.shares[_]
        share_obj.toUser == input.user
        share_obj.sharingLevel == "custom"
        action := share_obj.customSharedActions[_]
    }
    
	action := (user_allowed_actions_for_object_thru_sharing_levels_by_group | user_allowed_actions_for_object_thru_sharing_levels_by_user | user_allowed_actions_for_object_thru_custom_level_by_user | user_allowed_actions_for_object_thru_custom_level_by_group)[_]
}


# Verifica se o usuário tem permissão para uma ação em um objeto
user_allowed_action_for_object if {
    action := user_allowed_actions_for_object[_]
    action == input.action
}
