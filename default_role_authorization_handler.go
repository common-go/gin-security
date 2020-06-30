package security

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"sort"
)

type DefaultRoleAuthorizationHandler struct {
	sortedRoles bool
}

func NewRoleAuthorizationHandler(sortedRoles bool) *DefaultRoleAuthorizationHandler {
	return &DefaultRoleAuthorizationHandler{sortedRoles}
}

func (h *DefaultRoleAuthorizationHandler) Authorize(roles []string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		userRoles := h.getRolesFromContext(ctx)
		if userRoles == nil || len(*userRoles) == 0 {
			ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission: Require roles for this user")
			return
		}
		if h.sortedRoles {
			if h.hasSortedRole(roles, *userRoles) {
				ctx.Next()
				return
			}
		}
		if h.hasRole(roles, *userRoles) {
			ctx.Next()
			return
		}
		ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission.")
	}
}

func (h *DefaultRoleAuthorizationHandler) hasRole(roles []string, userRoles []string) bool {
	for _, role := range roles {
		for _, userRole := range userRoles {
			if role == userRole {
				return true
			}
		}
	}
	return false
}

func (h *DefaultRoleAuthorizationHandler) hasSortedRole(roles []string, userRoles []string) bool {
	for _, role := range roles {
		i := sort.SearchStrings(userRoles, role)
		if i >= 0 && userRoles[i] == role {
			return true
		}
	}
	return false
}

func (h *DefaultRoleAuthorizationHandler) getRolesFromContext(ctx *gin.Context) *[]string {
	if token, exist := ctx.Get(Authorization); exist {
		if authorizationToken, exist := token.(map[string]interface{}); exist {
			pRoles, ok2 := authorizationToken["roles"]
			if !ok2 || pRoles == nil {
				return nil
			}
			if roles, exist := pRoles.(*[]string); exist {
				return roles
			}
		}
	}
	return nil
}
