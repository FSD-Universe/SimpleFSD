// Package operation
package operation

type DatabaseOperations struct {
	userOperation                  UserOperationInterface                  // 用户操作
	flightPlanOperation            FlightPlanOperationInterface            // 飞行计划操作
	historyOperation               HistoryOperationInterface               // 连线记录操作
	activityOperation              ActivityOperationInterface              // 活动操作
	auditLogOperation              AuditLogOperationInterface              // 审计日志操作
	controllerOperation            ControllerOperationInterface            // 管制员操作
	controllerRecordOperation      ControllerRecordOperationInterface      // 管制员履历操作
	controllerApplicationOperation ControllerApplicationOperationInterface // 管制员申请操作
	ticketOperation                TicketOperationInterface                // 工单操作
	announcementOperation          AnnouncementOperationInterface          // 公告操作
	oauth2Operation                OAuth2OperationInterface                // OAuth2操作
}

func NewDatabaseOperations(
	userOperation UserOperationInterface,
	flightPlanOperation FlightPlanOperationInterface,
	historyOperation HistoryOperationInterface,
	activityOperation ActivityOperationInterface,
	auditLogOperation AuditLogOperationInterface,
	controllerOperation ControllerOperationInterface,
	controllerRecordOperation ControllerRecordOperationInterface,
	controllerApplicationOperation ControllerApplicationOperationInterface,
	tickerOperation TicketOperationInterface,
	announcementOperation AnnouncementOperationInterface,
	oauth2Operation OAuth2OperationInterface,
) *DatabaseOperations {
	return &DatabaseOperations{
		userOperation:                  userOperation,
		flightPlanOperation:            flightPlanOperation,
		historyOperation:               historyOperation,
		activityOperation:              activityOperation,
		auditLogOperation:              auditLogOperation,
		controllerOperation:            controllerOperation,
		controllerRecordOperation:      controllerRecordOperation,
		controllerApplicationOperation: controllerApplicationOperation,
		ticketOperation:                tickerOperation,
		announcementOperation:          announcementOperation,
		oauth2Operation:                oauth2Operation,
	}
}

func (db *DatabaseOperations) UserOperation() UserOperationInterface {
	return db.userOperation
}

func (db *DatabaseOperations) FlightPlanOperation() FlightPlanOperationInterface {
	return db.flightPlanOperation
}

func (db *DatabaseOperations) HistoryOperation() HistoryOperationInterface {
	return db.historyOperation
}

func (db *DatabaseOperations) ActivityOperation() ActivityOperationInterface {
	return db.activityOperation
}

func (db *DatabaseOperations) AuditLogOperation() AuditLogOperationInterface {
	return db.auditLogOperation
}

func (db *DatabaseOperations) ControllerOperation() ControllerOperationInterface {
	return db.controllerOperation
}

func (db *DatabaseOperations) ControllerRecordOperation() ControllerRecordOperationInterface {
	return db.controllerRecordOperation
}

func (db *DatabaseOperations) ControllerApplicationOperation() ControllerApplicationOperationInterface {
	return db.controllerApplicationOperation
}

func (db *DatabaseOperations) TicketOperation() TicketOperationInterface { return db.ticketOperation }

func (db *DatabaseOperations) AnnouncementOperation() AnnouncementOperationInterface {
	return db.announcementOperation
}

func (db *DatabaseOperations) OAuth2Operation() OAuth2OperationInterface {
	return db.oauth2Operation
}
