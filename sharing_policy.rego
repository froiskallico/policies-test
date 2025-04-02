package goapice.check_user

import rego.v1


######################################################################################################
#                                       Regras Adicionais                                            #
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