// Package service
package service

import "github.com/half-nothing/simple-fsd/internal/interfaces/operation"

var (
	ErrFlightPlanNotFound       = NewApiStatus("FLIGHT_PLAN_NOT_FOUND", "飞行计划不存在", NotFound)
	ErrFlightPlanLocked         = NewApiStatus("FLIGHT_PLAN_LOCKED", "飞行计划已锁定", Conflict)
	ErrFlightPlanUnlocked       = NewApiStatus("FLIGHT_PLAN_UNLOCKED", "飞行计划未锁定", Conflict)
	SuccessSubmitFlightPlan     = NewApiStatus("SUBMIT_FLIGHT_PLAN", "成功提交计划", Ok)
	SuccessGetFlightPlan        = NewApiStatus("GET_FLIGHT_PLAN", "成功获取计划", Ok)
	SuccessGetFlightPlans       = NewApiStatus("GET_FLIGHT_PLANS", "成功获取计划", Ok)
	SuccessDeleteSelfFlightPlan = NewApiStatus("DELETE_SELF_FLIGHT_PLAN", "成功删除自己的飞行计划", Ok)
	SuccessDeleteFlightPlan     = NewApiStatus("DELETE_FLIGHT_PLAN", "成功删除飞行计划", Ok)
	SuccessLockFlightPlan       = NewApiStatus("LOCK_FLIGHT_PLAN", "成功修改计划锁定状态", Ok)
)

type FlightPlanServiceInterface interface {
	SubmitFlightPlan(req *RequestSubmitFlightPlan) *ApiResponse[bool]
	GetFlightPlan(req *RequestGetFlightPlan) *ApiResponse[ResponseGetFlightPlan]
	GetFlightPlans(req *RequestGetFlightPlans) *ApiResponse[ResponseGetFlightPlans]
	DeleteSelfFlightPlan(req *RequestDeleteSelfFlightPlan) *ApiResponse[bool]
	DeleteFlightPlan(req *RequestDeleteFlightPlan) *ApiResponse[bool]
	LockFlightPlan(req *RequestLockFlightPlan) *ApiResponse[bool]
}

type RequestSubmitFlightPlan struct {
	JwtHeader
	*operation.FlightPlan
}

type RequestGetFlightPlan struct {
	JwtHeader
}

type ResponseGetFlightPlan = *operation.FlightPlan

type RequestGetFlightPlans struct {
	JwtHeader
	PageArguments
}

type ResponseGetFlightPlans = *PageResponse[*operation.FlightPlan]

type RequestDeleteSelfFlightPlan struct {
	JwtHeader
	EchoContentHeader
}

type RequestDeleteFlightPlan struct {
	JwtHeader
	EchoContentHeader
	TargetCid int `param:"cid"`
}

type RequestLockFlightPlan struct {
	JwtHeader
	EchoContentHeader
	TargetCid int `param:"cid"`
	Lock      bool
}
