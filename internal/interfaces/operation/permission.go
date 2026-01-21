// Package operation
package operation

type Permission uint64

// 权限节点上限是64, 超过64需要使用切片
const (
	AdminEntry Permission = 1 << iota
	UserShowList
	UserGetProfile
	UserSetPassword
	UserEditBaseInfo
	UserShowPermission
	UserEditPermission
	ControllerShowList
	ControllerTier2Rating
	ControllerEditRating
	ControllerShowRecord
	ControllerCreateRecord
	ControllerDeleteRecord
	ControllerChangeUnderMonitor
	ControllerChangeSolo
	ControllerChangeGuest
	ControllerApplicationShowList
	ControllerApplicationConfirm
	ControllerApplicationPass
	ControllerApplicationReject
	ActivityPublish
	ActivityShowList
	ActivityEdit
	ActivityEditState
	ActivityEditPilotState
	ActivityDelete
	AuditLogShow
	TicketShowList
	TicketReply
	TicketRemove
	FlightPlanShowList
	FlightPlanChangeLock
	FlightPlanDelete
	ClientManagerEntry
	ClientSendMessage
	ClientSendBroadcastMessage
	ClientKill
	AnnouncementShowList
	AnnouncementPublish
	AnnouncementEdit
	AnnouncementDelete
	OAuthClientShowList
	OAuthClientCreate
	OAuthClientEdit
	OAuthClientDelete
)

var PermissionMap = map[string]Permission{
	"AdminEntry":                    AdminEntry,
	"UserShowList":                  UserShowList,
	"UserGetProfile":                UserGetProfile,
	"UserSetPassword":               UserSetPassword,
	"UserEditBaseInfo":              UserEditBaseInfo,
	"UserShowPermission":            UserShowPermission,
	"UserEditPermission":            UserEditPermission,
	"ControllerShowList":            ControllerShowList,
	"ControllerTier2Rating":         ControllerTier2Rating,
	"ControllerEditRating":          ControllerEditRating,
	"ControllerShowRecord":          ControllerShowRecord,
	"ControllerCreateRecord":        ControllerCreateRecord,
	"ControllerDeleteRecord":        ControllerDeleteRecord,
	"ControllerChangeUnderMonitor":  ControllerChangeUnderMonitor,
	"ControllerChangeSolo":          ControllerChangeSolo,
	"ControllerChangeGuest":         ControllerChangeGuest,
	"ControllerApplicationShowList": ControllerApplicationShowList,
	"ControllerApplicationConfirm":  ControllerApplicationConfirm,
	"ControllerApplicationPass":     ControllerApplicationPass,
	"ControllerApplicationReject":   ControllerApplicationReject,
	"ActivityPublish":               ActivityPublish,
	"ActivityShowList":              ActivityShowList,
	"ActivityEdit":                  ActivityEdit,
	"ActivityEditState":             ActivityEditState,
	"ActivityEditPilotState":        ActivityEditPilotState,
	"ActivityDelete":                ActivityDelete,
	"AuditLogShow":                  AuditLogShow,
	"TicketShowList":                TicketShowList,
	"TicketReply":                   TicketReply,
	"TicketRemove":                  TicketRemove,
	"FlightPlanShowList":            FlightPlanShowList,
	"FlightPlanChangeLock":          FlightPlanChangeLock,
	"FlightPlanDelete":              FlightPlanDelete,
	"ClientManagerEntry":            ClientManagerEntry,
	"ClientSendMessage":             ClientSendMessage,
	"ClientKill":                    ClientKill,
	"ClientSendBroadcastMessage":    ClientSendBroadcastMessage,
	"AnnouncementShowList":          AnnouncementShowList,
	"AnnouncementPublish":           AnnouncementPublish,
	"AnnouncementEdit":              AnnouncementEdit,
	"AnnouncementDelete":            AnnouncementDelete,
	"OAuthClientShowList":           OAuthClientShowList,
	"OAuthClientCreate":             OAuthClientCreate,
	"OAuthClientEdit":               OAuthClientEdit,
	"OAuthClientDelete":             OAuthClientDelete,
}

func (p *Permission) HasPermission(perm Permission) bool {
	return *p&perm == perm
}

func (p *Permission) Grant(perm Permission) {
	*p |= perm
}

func (p *Permission) Revoke(perm Permission) {
	*p &^= perm
}
