// Package service
package service

type EmailCode struct {
	Code int
	Cid  int
}

var (
	ErrRenderTemplate = NewApiStatus("RENDER_TEMPLATE_ERROR", "邮件发送失败", ServerInternalError)
	ErrSendEmail      = NewApiStatus("EMAIL_SEND_ERROR", "发送失败", ServerInternalError)
	SendEmailSuccess  = NewApiStatus("SEND_EMAIL_SUCCESS", "邮件发送成功", Ok)
)

type EmailServiceInterface interface {
	VerifyEmailCode(email string, code string, cid int) error
	SendEmailVerifyCode(req *RequestEmailVerifyCode) *ApiResponse[*ResponseEmailVerifyCode]
}

type RequestEmailVerifyCode struct {
	Email string `json:"email"`
	Cid   int    `json:"cid"`
}

type ResponseEmailVerifyCode struct {
	Email string `json:"email"`
}
