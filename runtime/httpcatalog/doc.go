// Package httpcatalog 提供业务服务的 HTTP Catalog 注册与续约能力。
//
// 新接入通过 RegistrarCredentialSource 注入 *-catalog-registrar Client ID/Secret，
// 同步和续约统一使用 HTTPS Basic；不获取、缓存或刷新机器 Token，不依赖 Service Account。
// 旧 Config.Tokens 仅用于旧服务端显式兼容并将在下一主版本移除，不提供认证失败回退。
package httpcatalog
