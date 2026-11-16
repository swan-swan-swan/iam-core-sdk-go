package httpauthz

import "github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/authzcontract"

// ClassifiedRouteSpec 在同一声明中包含PDP路由事实和显式目录分类。
type ClassifiedRouteSpec struct {
	// Spec 是框架路由注册和PDP保护共用的原始事实。
	Spec RouteSpec
	// PolicyClass 是Manifest v4传输的精确类别。
	PolicyClass authzcontract.PolicyClass
}

// NewClassifiedRouteSpec 校验完整路由及分类，保持既有PDP坐标不变。
func NewClassifiedRouteSpec(method, routeTemplate, routeName, action string, class authzcontract.PolicyClass) (ClassifiedRouteSpec, error) {
	spec, err := NewRouteSpec(method, routeTemplate, routeName, action)
	if err != nil {
		return ClassifiedRouteSpec{}, err
	}
	if err = authzcontract.ValidatePolicyClass(method, action, class); err != nil {
		return ClassifiedRouteSpec{}, err
	}
	return ClassifiedRouteSpec{Spec: spec, PolicyClass: class}, nil
}
