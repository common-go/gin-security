package security

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type PrivilegesAuthorizationHandler struct {
	sortedPrivilege   bool
	exact             bool
	privilegesService PrivilegesService
}

func NewPrivilegesAuthorizationHandler(sortedPrivilege bool, exact bool, privilegesService PrivilegesService) *PrivilegesAuthorizationHandler {
	return &PrivilegesAuthorizationHandler{sortedPrivilege, exact, privilegesService}
}

func (h *PrivilegesAuthorizationHandler) Authorize(privilegeId string, action int32) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		userId := GetUserIdFromGinContext(ctx)
		if len(userId) == 0 {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, "Invalid User Id")
			return
		}
		privileges := h.privilegesService.GetPrivileges(ctx.Request.Context(), userId)
		if privileges == nil || len(privileges) == 0 {
			ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission: Require privileges for this user")
			return
		}

		privilegeAction := GetAction(privileges, privilegeId, h.sortedPrivilege)
		if privilegeAction == ActionNone {
			ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission for this user.")
			return
		}
		if action == ActionNone || action == ActionAll {
			ctx.Next()
			return
		}
		sum := action & privilegeAction
		if h.exact {
			if sum == action {
				ctx.Next()
				return
			}
		} else {
			if sum >= action {
				ctx.Next()
				return
			}
		}
		ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission.")
	}
}
