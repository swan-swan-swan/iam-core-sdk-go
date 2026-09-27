// Package httpcatalog 提供业务服务启动时的 HTTP Resource Catalog 注册能力。
//
// 调用方负责实现 core.TokenSource，包括 Client Credentials 的获取、缓存、刷新与重试。
// Registry 每次同步只消费当前 Access Token，不接收 Client Secret，也不维护令牌生命周期。
package httpcatalog
