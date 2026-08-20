// Package applicationhandoff 提供业务请求链路中的一次性 Application 登录交接 Client。
//
// Client 不获取、刷新、持久化或记录 Access Token。调用方必须为每次 Create 调用注入当前用户的
// core.TokenSource；用户身份由 IAM Core 从该 Token 的已验证 Subject 中取得。
package applicationhandoff
