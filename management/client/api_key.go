package client

import "context"

// APIKeySource 提供受控 API 请求使用的直接服务账号凭据。
type APIKeySource interface {
	APIKey(context.Context) (string, error)
}

// APIKeySourceFunc 将调用方读取 Secret 的函数适配为 API Key 来源。
type APIKeySourceFunc func(context.Context) (string, error)

// APIKey 读取程序凭据，不换取或刷新 Access Token。
func (f APIKeySourceFunc) APIKey(ctx context.Context) (string, error) { return f(ctx) }
