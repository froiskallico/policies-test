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
	unit.uuid = input.unit
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

# Quais ações um usuário está permitido para um tipo de objeto
# Não sei se isso faz sentido, uma vez que ele poderá ter varias permissoes para os objetos em si... 
# user_allowed_actions_for_object_type := {action |
#     customer := data.customers[_]
#     share := customer.sharing[_]
#     share.toUser == input.user
#     share.module == input.module
#     share.entity == input.entity
#     level := customer.sharingLevels[_]
#     level.module == input.module
#     level.entity == input.entity
#     level.level == share.sharingLevel
#     action := level.actions[_]
# }

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
    
    action := user_allowed_actions_for_object_thru_sharing_levels_by_group | user_allowed_actions_for_object_thru_sharing_levels_by_user | user_allowed_actions_for_object_thru_custom_level_by_user | user_allowed_actions_for_object_thru_custom_level_by_group
}


# Verifica se o usuário tem permissão para uma ação em um objeto
user_allowed_action_for_object if {
    action := user_allowed_actions_for_object[_]
    action == input.action
}
