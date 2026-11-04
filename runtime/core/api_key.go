package core

import "context"

// APIKeySource 为一次请求提供 API Key，不提供或获取 OAuth Access Token。
type APIKeySource interface {
	APIKey(context.Context) (string, error)
}

// APIKeySourceFunc 将调用方密钥读取函数适配为直接程序凭据来源。
type APIKeySourceFunc func(context.Context) (string, error)

// APIKey 读取调用方提供的密钥，SDK 不持久化或刷新。
func (f APIKeySourceFunc) APIKey(ctx context.Context) (string, error) { return f(ctx) }
