package applicationhandoff

import "time"

// CreateInput 定义由已认证用户为固定 Application 创建 Handoff 的输入。
// 用户身份只来自调用方注入的 Access Token，协议不接受 Subject 字段。
type CreateInput struct {
	ApplicationOpenID string
	DecisionID        string
	CorrelationID     string
}

// CreateOutput 定义短时一次性登录交接结果。
type CreateOutput struct {
	HandoffID string
	LaunchURL string
	ExpiresIn time.Duration
}

type createRequest struct {
	ApplicationOpenID string `json:"applicationOpenId"`
	DecisionID        string `json:"decisionId"`
	CorrelationID     string `json:"correlationId"`
}

type createResponse struct {
	HandoffID string `json:"handoffId"`
	LaunchURL string `json:"launchUrl"`
	ExpiresIn int64  `json:"expiresIn"`
}
