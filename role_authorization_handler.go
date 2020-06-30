package security

import "github.com/gin-gonic/gin"

type RoleAuthorizationHandler interface {
	Authorize(roles []string) gin.HandlerFunc
}
